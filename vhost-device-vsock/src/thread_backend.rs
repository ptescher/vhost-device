// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{Read, Result as StdIOResult, Write},
    ops::Deref,
    os::unix::{
        net::UnixStream,
        prelude::{AsRawFd, RawFd},
    },
    result::Result as StdResult,
    sync::{Arc, RwLock},
    net::Shutdown,
};

use log::{info, warn};
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::{
    bitmap::BitmapSlice, ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile,
};
#[cfg(feature = "backend_vsock")]
use vsock::VsockStream;

use crate::{
    rxops::*,
    vhu_vsock::{
        BackendType, CidMap, ConnMapKey, Error, Result, VSOCK_HOST_CID,
        VSOCK_OP_CREDIT_UPDATE, VSOCK_OP_REQUEST, VSOCK_OP_RESPONSE, VSOCK_OP_RST, VSOCK_OP_RW,
        VSOCK_TYPE_STREAM,
    },
    vhu_vsock_thread::VhostUserVsockThread,
    vsock_conn::*,
};

pub(crate) type RawPktsQ = VecDeque<RawVsockPacket>;

pub(crate) struct RawVsockPacket {
    pub header: [u8; PKT_HEADER_SIZE],
    pub data: Vec<u8>,
}

impl RawVsockPacket {
    fn from_vsock_packet<B: BitmapSlice>(pkt: &VsockPacket<B>) -> Result<Self> {
        let mut raw_pkt = Self {
            header: [0; PKT_HEADER_SIZE],
            data: vec![0; pkt.len() as usize],
        };

        pkt.header_slice().copy_to(&mut raw_pkt.header);
        if !pkt.is_empty() {
            pkt.data_slice()
                .ok_or(Error::PktBufMissing)?
                .copy_to(raw_pkt.data.as_mut());
        }

        Ok(raw_pkt)
    }
}

pub(crate) enum StreamType {
    Unix(UnixStream),
    #[cfg(feature = "backend_vsock")]
    Vsock(VsockStream),
}

impl StreamType {
    fn try_clone(&self) -> StdIOResult<StreamType> {
        match self {
            StreamType::Unix(stream) => {
                let cloned_stream = stream.try_clone()?;
                Ok(StreamType::Unix(cloned_stream))
            }
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => {
                let cloned_stream = stream.try_clone()?;
                Ok(StreamType::Vsock(cloned_stream))
            }
        }
    }
}

impl Read for StreamType {
    fn read(&mut self, buf: &mut [u8]) -> StdIOResult<usize> {
        match self {
            StreamType::Unix(stream) => stream.read(buf),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.read(buf),
        }
    }
}

impl Write for StreamType {
    fn write(&mut self, buf: &[u8]) -> StdIOResult<usize> {
        match self {
            StreamType::Unix(stream) => stream.write(buf),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> StdIOResult<()> {
        match self {
            StreamType::Unix(stream) => stream.flush(),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.flush(),
        }
    }
}

impl AsRawFd for StreamType {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            StreamType::Unix(stream) => stream.as_raw_fd(),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.as_raw_fd(),
        }
    }
}

impl ReadVolatile for StreamType {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<'_, B>,
    ) -> StdResult<usize, VolatileMemoryError> {
        match self {
            StreamType::Unix(stream) => stream.read_volatile(buf),
            // Copied from vm_memory crate's ReadVolatile implementation for UnixStream
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => {
                let fd = stream.as_raw_fd();
                let guard = buf.ptr_guard_mut();

                let dst = guard.as_ptr().cast::<libc::c_void>();

                // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to
                // by `dst` is valid for writes of length `buf.len() by the
                // invariants upheld by the constructor of `VolatileSlice`.
                let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

                if bytes_read < 0 {
                    // We don't know if a partial read might have happened, so mark everything as
                    // dirty
                    buf.bitmap().mark_dirty(0, buf.len());

                    Err(VolatileMemoryError::IOError(std::io::Error::last_os_error()))
                } else {
                    let bytes_read = bytes_read.try_into().unwrap();
                    buf.bitmap().mark_dirty(0, bytes_read);
                    Ok(bytes_read)
                }
            }
        }
    }
}

impl WriteVolatile for StreamType {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<'_, B>,
    ) -> StdResult<usize, VolatileMemoryError> {
        match self {
            StreamType::Unix(stream) => stream.write_volatile(buf),
            // Copied from vm_memory crate's WriteVolatile implementation for UnixStream
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => {
                let fd = stream.as_raw_fd();
                let guard = buf.ptr_guard();

                let src = guard.as_ptr().cast::<libc::c_void>();

                // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to
                // by `src` is valid for reads of length `buf.len() by the
                // invariants upheld by the constructor of `VolatileSlice`.
                let bytes_written = unsafe { libc::write(fd, src, buf.len()) };

                if bytes_written < 0 {
                    Err(VolatileMemoryError::IOError(std::io::Error::last_os_error()))
                } else {
                    Ok(bytes_written.try_into().unwrap())
                }
            }
        }
    }
}

pub(crate) trait IsHybridVsock {
    fn is_hybrid_vsock(&self) -> bool;
    fn shutdown_write(&self) -> std::io::Result<()>;
}

impl IsHybridVsock for StreamType {
    fn is_hybrid_vsock(&self) -> bool {
        matches!(self, StreamType::Unix(_))
    }

    fn shutdown_write(&self) -> std::io::Result<()> {
        match self {
            StreamType::Unix(stream) => stream.shutdown(Shutdown::Write),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.shutdown(Shutdown::Write),
        }
    }
}

pub(crate) struct VsockThreadBackend {
    /// Map of ConnMapKey objects indexed by raw file descriptors.
    pub listener_map: HashMap<RawFd, ConnMapKey>,
    /// Map of vsock connection objects indexed by ConnMapKey objects.
    pub conn_map: HashMap<ConnMapKey, VsockConnection<StreamType>>,
    /// Queue of ConnMapKey objects indicating pending rx operations.
    pub backend_rxq: VecDeque<ConnMapKey>,
    /// Map of host-side unix or vsock streams indexed by raw file descriptors.
    pub stream_map: HashMap<i32, StreamType>,
    /// Host side socket info for listening to new connections from the host.
    backend_info: BackendType,
    /// epoll for registering new host-side connections.
    epoll_fd: i32,
    /// CID of the guest.
    pub guest_cid: u64,
    /// Set of allocated local ports.
    pub local_port_set: HashSet<u32>,
    tx_buffer_size: u32,
    /// Maps the guest CID to the corresponding backend. Used for sibling VM
    /// communication.
    pub cid_map: Arc<RwLock<CidMap>>,
    /// Queue of raw vsock packets received from sibling VMs to be sent to the
    /// guest.
    pub raw_pkts_queue: Arc<RwLock<RawPktsQ>>,
    /// Set of groups assigned to the device which it is allowed to communicate
    /// with.
    groups_set: Arc<RwLock<HashSet<String>>>,
}

impl VsockThreadBackend {
    /// New instance of VsockThreadBackend.
    pub fn new(
        backend_info: BackendType,
        epoll_fd: i32,
        guest_cid: u64,
        tx_buffer_size: u32,
        groups_set: Arc<RwLock<HashSet<String>>>,
        cid_map: Arc<RwLock<CidMap>>,
    ) -> Self {
        Self {
            listener_map: HashMap::new(),
            conn_map: HashMap::new(),
            backend_rxq: VecDeque::new(),
            // Need this map to prevent connected stream from closing
            // TODO: think of a better solution
            stream_map: HashMap::new(),
            backend_info,
            epoll_fd,
            guest_cid,
            local_port_set: HashSet::new(),
            tx_buffer_size,
            cid_map,
            raw_pkts_queue: Arc::new(RwLock::new(VecDeque::new())),
            groups_set,
        }
    }

    /// Checks if there are pending rx requests in the backend rxq.
    pub fn pending_rx(&self) -> bool {
        !self.backend_rxq.is_empty()
    }

    /// Checks if there are pending raw vsock packets to be sent to the guest.
    pub fn pending_raw_pkts(&self) -> bool {
        !self.raw_pkts_queue.read().unwrap().is_empty()
    }

    /// Deliver a vsock packet to the guest vsock driver.
    ///
    /// Returns:
    /// - `Ok(())` if the packet was successfully filled in
    /// - `Err(Error::EmptyBackendRxQ) if there was no available data
    pub fn recv_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacket<B>) -> Result<()> {
        // Pop an event from the backend_rxq
        let key = self.backend_rxq.pop_front().ok_or(Error::EmptyBackendRxQ)?;
        info!("vsock: recv_pkt processing key: {:?}", key);

        let conn = match self.conn_map.get_mut(&key) {
            Some(conn) => conn,
            None => {
                // assume that the connection does not exist
                warn!("vsock: recv_pkt - connection not found for key");
                return Ok(());
            }
        };

        if conn.rx_queue.is_empty() {
            // It's possible to have a connection with no pending RX ops,
            // for example when the guest has no data to send. This is not
            // an error, but we have to consume the virtio descriptor, so we
            // craft a harmless CREDIT_UPDATE packet that the guest can
            // safely ignore.
            pkt.set_op(VSOCK_OP_CREDIT_UPDATE);
            return Ok(());
        }

        if conn.rx_queue.peek() == Some(RxOps::Reset) {
            // Handle RST events here
            let conn = self.conn_map.remove(&key).unwrap();
            self.listener_map.remove(&conn.stream.as_raw_fd());
            self.stream_map.remove(&conn.stream.as_raw_fd());
            self.local_port_set.remove(&conn.local_port);
            VhostUserVsockThread::epoll_unregister(conn.epoll_fd, conn.stream.as_raw_fd())
                .unwrap_or_else(|err| {
                    warn!(
                        "Could not remove epoll listener for fd {:?}: {:?}",
                        conn.stream.as_raw_fd(),
                        err
                    )
                });

            // Initialize the packet header to contain a VSOCK_OP_RST operation
            pkt.set_op(VSOCK_OP_RST)
                .set_src_cid(VSOCK_HOST_CID)
                .set_dst_cid(conn.guest_cid)
                .set_src_port(conn.local_port)
                .set_dst_port(conn.peer_port)
                .set_len(0)
                .set_type(VSOCK_TYPE_STREAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);

            info!(
                "vsock: recv_pkt sending RST - src_cid:{}, src_port:{}, dst_cid:{}, dst_port:{}",
                VSOCK_HOST_CID, conn.local_port, conn.guest_cid, conn.peer_port
            );

            return Ok(());
        }

        // Handle other packet types per connection
        conn.recv_pkt(pkt)?;

        info!(
            "vsock: recv_pkt delivered packet - src_cid:{}, src_port:{}, dst_cid:{}, dst_port:{}, op:{}, len:{}",
            pkt.src_cid(), pkt.src_port(), pkt.dst_cid(), pkt.dst_port(), pkt.op(), pkt.len()
        );

        Ok(())
    }

    /// Deliver a guest generated packet to its destination in the backend.
    ///
    /// Absorbs unexpected packets, handles rest to respective connection
    /// object.
    ///
    /// Returns:
    /// - always `Ok(())` if packet has been consumed correctly
    pub fn send_pkt<B: BitmapSlice>(&mut self, pkt: &VsockPacket<B>) -> Result<()> {
        info!(
            "vsock: [CID {}] send_pkt - src_cid:{}, src_port:{}, dst_cid:{}, dst_port:{}, op:{}, type:{}, len:{}",
            self.guest_cid, pkt.src_cid(), pkt.src_port(), pkt.dst_cid(), pkt.dst_port(), pkt.op(), pkt.type_(), pkt.len()
        );

        // Log packet operation type for debugging
        info!(
            "vsock: [CID {}] GUEST TX PACKET: op={} - {}",
            self.guest_cid, 
            pkt.op(),
            match pkt.op() {
                1 => "VSOCK_OP_REQUEST",
                2 => "VSOCK_OP_RESPONSE", 
                3 => "VSOCK_OP_RST",
                4 => "VSOCK_OP_SHUTDOWN",
                5 => "VSOCK_OP_CREDIT_REQUEST",
                6 => "VSOCK_OP_CREDIT_UPDATE",
                7 => "VSOCK_OP_RW",
                _ => "UNKNOWN_OP",
            }
        );

        // Log any data payload from guest
        if pkt.len() > 0 {
            if let Some(data) = pkt.data_slice() {
                // Create a regular slice from VolatileSlice for logging
                let mut bytes = vec![0u8; data.len()];
                data.copy_to(&mut bytes[..]);
                
                let hex_dump = bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                let ascii_dump = bytes
                    .iter()
                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                    .collect::<String>();
                
                info!(
                    "vsock: [CID {}] GUEST TX DATA: {} bytes - HEX=[{}] ASCII=[{}]",
                    self.guest_cid, bytes.len(), hex_dump, ascii_dump
                );
            }
        }

        if pkt.src_cid() != self.guest_cid {
            warn!(
                "vsock: [CID {}] dropping packet with inconsistent src_cid: {:?} from guest configured with CID: {:?}",
                self.guest_cid, pkt.src_cid(), self.guest_cid
            );
            return Ok(());
        }

        #[allow(irrefutable_let_patterns)]
        if let BackendType::UnixDomainSocket(_) = &self.backend_info {
            let dst_cid = pkt.dst_cid();
            if dst_cid != VSOCK_HOST_CID {
                let cid_map = self.cid_map.read().unwrap();
                if cid_map.contains_key(&dst_cid) {
                    info!("vsock: found CID {} in map, forwarding packet", dst_cid);
                    let (sibling_raw_pkts_queue, sibling_groups_set, sibling_event_fd) =
                        cid_map.get(&dst_cid).unwrap();

                    let our_groups = self.groups_set.read().unwrap();
                    let sibling_groups = sibling_groups_set.read().unwrap();
                    info!(
                        "vsock: our groups: {:?}, sibling groups: {:?}",
                        *our_groups, *sibling_groups
                    );

                    if our_groups.is_disjoint(sibling_groups.deref()) {
                        info!("vsock: dropping packet for cid: {dst_cid:?} due to group mismatch");
                        return Ok(());
                    }

                    info!("vsock: groups match, pushing packet to sibling queue");
                    sibling_raw_pkts_queue
                        .write()
                        .unwrap()
                        .push_back(RawVsockPacket::from_vsock_packet(pkt)?);
                    let written = sibling_event_fd.write(1);
                    info!("vsock: wrote to sibling event_fd, result: {:?}", written);
                } else {
                    warn!("vsock: dropping packet for unknown cid: {dst_cid:?}");
                    info!(
                        "vsock: available CIDs in map: {:?}",
                        cid_map.keys().collect::<Vec<_>>()
                    );
                }

                return Ok(());
            }
        }

        // TODO: Rst if packet has unsupported type
        if pkt.type_() != VSOCK_TYPE_STREAM {
            info!("vsock: dropping packet of unknown type");
            return Ok(());
        }

        let key = ConnMapKey::new(pkt.dst_port(), pkt.src_port());
        
        // Add specific logging for UnixToVsock connections
        #[cfg(feature = "backend_vsock")]
        if let BackendType::UnixToVsock(_, vsock_info) = &self.backend_info {
            info!(
                "vsock: [CID {}] UnixToVsock mode - processing guest TX packet for key {:?}, target_cid:{}, target_port:{}",
                self.guest_cid, key, vsock_info.target_cid, vsock_info.target_port
            );
        }

        // TODO: Handle cases where connection does not exist and packet op
        // is not VSOCK_OP_REQUEST
        if !self.conn_map.contains_key(&key) {
            // The packet contains a new connection request
            if pkt.op() == VSOCK_OP_REQUEST {
                info!("vsock: received connection request, handling new connection");
                self.handle_new_guest_conn(pkt);
            } else {
                warn!(
                    "vsock: received packet op {} for non-existent connection, should send RST",
                    pkt.op()
                );
                // TODO: send back RST
            }
            return Ok(());
        }

        if pkt.op() == VSOCK_OP_RST {
            // Handle an RST packet from the guest here
            let conn = self.conn_map.get(&key).unwrap();
            if conn.rx_queue.contains(RxOps::Reset.bitmask()) {
                return Ok(());
            }
            let conn = self.conn_map.remove(&key).unwrap();
            self.listener_map.remove(&conn.stream.as_raw_fd());
            self.stream_map.remove(&conn.stream.as_raw_fd());
            self.local_port_set.remove(&conn.local_port);
            VhostUserVsockThread::epoll_unregister(conn.epoll_fd, conn.stream.as_raw_fd())
                .unwrap_or_else(|err| {
                    warn!(
                        "Could not remove epoll listener for fd {:?}: {:?}",
                        conn.stream.as_raw_fd(),
                        err
                    )
                });
            return Ok(());
        }

        // Forward this packet to its listening connection
        info!(
            "vsock: [CID {}] forwarding packet op:{} to connection {:?}",
            self.guest_cid, pkt.op(), key
        );
        
        let conn = self.conn_map.get_mut(&key).unwrap();
        conn.send_pkt(pkt)?;

        if conn.rx_queue.pending_rx() {
            // Required if the connection object adds new rx operations
            self.backend_rxq.push_back(key);
        }

        Ok(())
    }

    /// Deliver a raw vsock packet sent from a sibling VM to the guest vsock
    /// driver.
    ///
    /// Returns:
    /// - `Ok(())` if packet was successfully filled in
    /// - `Err(Error::EmptyRawPktsQueue)` if there was no available data
    pub fn recv_raw_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacket<B>) -> Result<()> {
        let queue_size_before = self.raw_pkts_queue.read().unwrap().len();
        info!(
            "vsock: [CID {}] recv_raw_pkt called, queue size before pop: {}",
            self.guest_cid, queue_size_before
        );

        let raw_vsock_pkt = self
            .raw_pkts_queue
            .write()
            .unwrap()
            .pop_front()
            .ok_or(Error::EmptyRawPktsQueue)?;

        let queue_size_after = self.raw_pkts_queue.read().unwrap().len();
        info!(
            "vsock: [CID {}] popped packet from queue, queue size after: {}",
            self.guest_cid, queue_size_after
        );

        pkt.set_header_from_raw(&raw_vsock_pkt.header).unwrap();
        if !raw_vsock_pkt.data.is_empty() {
            let buf = pkt.data_slice().ok_or(Error::PktBufMissing)?;
            buf.copy_from(&raw_vsock_pkt.data);
        }

        info!(
            "vsock: recv_raw_pkt delivered packet from sibling - src_cid:{}, src_port:{}, dst_cid:{}, dst_port:{}, op:{}, type:{}, len:{}",
            pkt.src_cid(), pkt.src_port(), pkt.dst_cid(), pkt.dst_port(), pkt.op(), pkt.type_(), pkt.len()
        );

        // Check if this is a connection request from a sibling VM
        if pkt.op() == VSOCK_OP_REQUEST && pkt.type_() == VSOCK_TYPE_STREAM {
            #[allow(irrefutable_let_patterns)]
            if let BackendType::UnixDomainSocket(uds_path) = &self.backend_info {
                let port_path = format!("{}_{}", uds_path.display(), pkt.dst_port());

                // Check if there's a Unix socket listener - if so, we'll handle this as a proxy connection
                if std::path::Path::new(&port_path).exists() {
                    info!(
                        "vsock: Sibling VM (CID {}) connecting to CID {} port {} - checking for Unix socket proxy at {}",
                        pkt.src_cid(), self.guest_cid, pkt.dst_port(), port_path
                    );

                    // Since there's no guest VM for this CID, we'll need to handle the connection
                    // directly by proxying to the Unix socket
                    // For now, just log that this would be the place to implement it
                    warn!(
                        "vsock: Unix socket proxy for inter-VM connections not yet implemented. \
                        Would proxy connection from CID {} to Unix socket {}",
                        pkt.src_cid(),
                        port_path
                    );
                } else {
                    warn!(
                        "vsock: ERROR - Sibling VM (CID {}) is trying to connect to port {} on CID {}, \
                        but no listener found. Expected either a VM with vsock listener or Unix socket at: {}",
                        pkt.src_cid(), pkt.dst_port(), self.guest_cid, port_path
                    );
                }
            }
        }

        // Note: This packet will be delivered to the guest's vsock driver
        // For incoming connections (op:1), the guest should have a listener on the dst_port
        info!(
            "vsock: raw packet delivered to guest driver for CID {} - guest should {} on port {}",
            self.guest_cid,
            if pkt.op() == VSOCK_OP_REQUEST {
                "have a listener"
            } else {
                "process"
            },
            pkt.dst_port()
        );

        Ok(())
    }

    /// Handle a new guest initiated connection, i.e from the peer, the guest
    /// driver.
    ///
    /// In case of proxying using unix domain socket, attempts to connect to a
    /// host side unix socket listening on a path corresponding to the
    /// destination port as follows:
    /// - "{self.host_sock_path}_{local_port}""
    ///
    /// In case of proxying using vosck, attempts to connect to the
    /// {forward_cid, local_port}
    fn handle_new_guest_conn<B: BitmapSlice>(&mut self, pkt: &VsockPacket<B>) {
        info!(
            "vsock: handle_new_guest_conn - src_cid:{}, src_port:{}, dst_cid:{}, dst_port:{}",
            pkt.src_cid(),
            pkt.src_port(),
            pkt.dst_cid(),
            pkt.dst_port()
        );

        match &self.backend_info {
            BackendType::UnixDomainSocket(uds_path) => {
                let port_path = format!("{}_{}", uds_path.display(), pkt.dst_port());
                info!("vsock: attempting to connect to Unix socket: {}", port_path);

                UnixStream::connect(&port_path)
                    .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
                    .map_err(Error::UnixConnect)
                    .and_then(|stream| {
                        info!(
                            "vsock: successfully connected to Unix socket: {}",
                            port_path
                        );
                        self.add_new_guest_conn(StreamType::Unix(stream), pkt)
                    })
                    .unwrap_or_else(|err| {
                        warn!(
                            "vsock: failed to connect to Unix socket {}: {:?}",
                            port_path, err
                        );
                        self.enq_rst()
                    });
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::UnixToVsock(_, _vsock_info) => {
                // For UnixToVsock mode, guest connections are not supported
                // This mode is only for host->guest forwarding via Unix socket
                warn!(
                    "vsock: guest-initiated connection not supported in UnixToVsock mode, sending RST"
                );
                self.enq_rst();
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::Vsock(vsock_info) => {
                let forward_cid = vsock_info.forward_cid;
                let dst_port = pkt.dst_port();
                info!(
                    "vsock: attempting to connect to vsock CID:{}, port:{}",
                    forward_cid, dst_port
                );

                match VsockStream::connect_with_cid_port(forward_cid, dst_port)
                    .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
                {
                    Ok(stream) => {
                        info!(
                            "vsock: successfully connected to vsock CID:{}, port:{}",
                            forward_cid, dst_port
                        );
                        self.add_new_guest_conn(StreamType::Vsock(stream), pkt)
                            .unwrap_or_else(|err| {
                                warn!("vsock: failed to add connection: {:?}", err);
                                self.enq_rst()
                            });
                    }
                    Err(err) => {
                        warn!(
                            "vsock: failed to connect to vsock CID:{}, port:{}: {:?}",
                            forward_cid, dst_port, err
                        );
                        self.enq_rst();
                    }
                }
            }
        }
    }

    /// Wrapper to add new connection to relevant HashMaps.
    fn add_new_guest_conn<B: BitmapSlice>(
        &mut self,
        stream: StreamType,
        pkt: &VsockPacket<B>,
    ) -> Result<()> {
        info!(
            "vsock: add_new_guest_conn - local_port:{}, peer_port:{}, src_cid:{}, dst_cid:{}",
            pkt.dst_port(),
            pkt.src_port(),
            pkt.src_cid(),
            pkt.dst_cid()
        );

        let conn = VsockConnection::new_peer_init(
            stream.try_clone().map_err(match stream {
                StreamType::Unix(_) => Error::UnixConnect,
                #[cfg(feature = "backend_vsock")]
                StreamType::Vsock(_) => Error::VsockConnect,
            })?,
            pkt.dst_cid(),
            pkt.dst_port(),
            pkt.src_cid(),
            pkt.src_port(),
            self.epoll_fd,
            pkt.buf_alloc(),
            self.tx_buffer_size,
        );
        let stream_fd = conn.stream.as_raw_fd();
        info!("vsock: new connection established with fd: {}", stream_fd);

        self.listener_map
            .insert(stream_fd, ConnMapKey::new(pkt.dst_port(), pkt.src_port()));

        self.conn_map
            .insert(ConnMapKey::new(pkt.dst_port(), pkt.src_port()), conn);
        self.backend_rxq
            .push_back(ConnMapKey::new(pkt.dst_port(), pkt.src_port()));

        self.stream_map.insert(stream_fd, stream);
        self.local_port_set.insert(pkt.dst_port());

        VhostUserVsockThread::epoll_register(
            self.epoll_fd,
            stream_fd,
            epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
        )?;

        info!("vsock: connection added successfully to all maps");
        Ok(())
    }

    /// Enqueue RST packets to be sent to guest.
    fn enq_rst(&mut self) {
        // TODO
        dbg!("New guest conn error: Enqueue RST");
    }

    /// Process raw packets in proxy mode - for virtual CIDs without guest VMs
    pub fn recv_raw_pkt_proxy(&mut self) -> Result<()> {
        let raw_vsock_pkt = self
            .raw_pkts_queue
            .write()
            .unwrap()
            .pop_front()
            .ok_or(Error::EmptyRawPktsQueue)?;

        // Parse the packet header
        let header = &raw_vsock_pkt.header;
        let src_cid = u64::from_le_bytes(header[0..8].try_into().unwrap());
        let dst_cid = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let src_port = u32::from_le_bytes(header[16..20].try_into().unwrap());
        let dst_port = u32::from_le_bytes(header[20..24].try_into().unwrap());
        let _len = u32::from_le_bytes(header[24..28].try_into().unwrap());
        let type_ = u16::from_le_bytes(header[28..30].try_into().unwrap());
        let op = u16::from_le_bytes(header[30..32].try_into().unwrap());
        let buf_alloc = u32::from_le_bytes(header[36..40].try_into().unwrap());

        info!(
            "vsock: [CID {}] proxy mode - received packet from CID {} port {} to port {}, op: {}",
            self.guest_cid, src_cid, src_port, dst_port, op
        );

        // Only handle connection requests for now
        if op == VSOCK_OP_REQUEST && type_ == VSOCK_TYPE_STREAM {
            #[allow(irrefutable_let_patterns)]
            if let BackendType::UnixDomainSocket(uds_path) = &self.backend_info {
                let port_path = format!("{}_{}", uds_path.display(), dst_port);
                info!(
                    "vsock: [CID {}] attempting to connect to Unix socket: {}",
                    self.guest_cid, port_path
                );

                match UnixStream::connect(&port_path) {
                    Ok(stream) => {
                        info!(
                            "vsock: [CID {}] successfully connected to Unix socket for port {}",
                            self.guest_cid, dst_port
                        );

                        // Set non-blocking mode
                        if let Err(e) = stream.set_nonblocking(true) {
                            warn!("vsock: failed to set non-blocking mode: {:?}", e);
                            return Ok(());
                        }

                        // Create a connection entry
                        let key = ConnMapKey::new(dst_port, src_port);

                        if !self.conn_map.contains_key(&key) {
                            let conn = VsockConnection::new_peer_init(
                                StreamType::Unix(stream.try_clone().unwrap()),
                                dst_cid,  // local CID
                                dst_port, // local port
                                src_cid,  // peer CID
                                src_port, // peer port
                                self.epoll_fd,
                                buf_alloc,
                                self.tx_buffer_size,
                            );

                            let stream_fd = conn.stream.as_raw_fd();
                            self.listener_map.insert(stream_fd, key.clone());
                            self.conn_map.insert(key.clone(), conn);
                            self.backend_rxq.push_back(key);
                            self.stream_map.insert(stream_fd, StreamType::Unix(stream));
                            self.local_port_set.insert(dst_port);

                            VhostUserVsockThread::epoll_register(
                                self.epoll_fd,
                                stream_fd,
                                epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                            )
                            .ok();

                            info!("vsock: [CID {}] proxy connection established from CID {} to Unix socket", 
                                self.guest_cid, src_cid);

                            // We need to send the response back to the sibling VM
                            // This requires accessing the sibling's queue
                            if let Some((sibling_queue, _, sibling_event_fd)) =
                                self.cid_map.read().unwrap().get(&src_cid)
                            {
                                // Create a response packet
                                let mut response = RawVsockPacket {
                                    header: [0; PKT_HEADER_SIZE],
                                    data: vec![],
                                };

                                // Build VSOCK_OP_RESPONSE packet
                                response.header[0..8].copy_from_slice(&dst_cid.to_le_bytes()); // src_cid
                                response.header[8..16].copy_from_slice(&src_cid.to_le_bytes()); // dst_cid
                                response.header[16..20].copy_from_slice(&dst_port.to_le_bytes()); // src_port
                                response.header[20..24].copy_from_slice(&src_port.to_le_bytes()); // dst_port
                                response.header[24..28].copy_from_slice(&0u32.to_le_bytes()); // len
                                response.header[28..30]
                                    .copy_from_slice(&VSOCK_TYPE_STREAM.to_le_bytes()); // type
                                response.header[30..32]
                                    .copy_from_slice(&VSOCK_OP_RESPONSE.to_le_bytes()); // op
                                response.header[32..36].copy_from_slice(&0u32.to_le_bytes()); // flags
                                response.header[36..40]
                                    .copy_from_slice(&self.tx_buffer_size.to_le_bytes()); // buf_alloc
                                response.header[40..44].copy_from_slice(&0u32.to_le_bytes()); // fwd_cnt

                                sibling_queue.write().unwrap().push_back(response);
                                let _ = sibling_event_fd.write(1);

                                info!(
                                    "vsock: [CID {}] sent VSOCK_OP_RESPONSE back to CID {}",
                                    self.guest_cid, src_cid
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "vsock: [CID {}] failed to connect to Unix socket {}: {:?}",
                            self.guest_cid, port_path, e
                        );
                        // TODO: Send RST packet back
                    }
                }
            }
        } else if op == VSOCK_OP_RW && type_ == VSOCK_TYPE_STREAM {
            // Handle data packets
            let key = ConnMapKey::new(dst_port, src_port);
            if let Some(conn) = self.conn_map.get_mut(&key) {
                info!("vsock: [CID {}] proxy mode - forwarding {} bytes of data from CID {} to Unix socket", 
                    self.guest_cid, raw_vsock_pkt.data.len(), src_cid);

                // Write the data to the Unix socket
                if !raw_vsock_pkt.data.is_empty() {
                    match conn.stream.write_all(&raw_vsock_pkt.data) {
                        Ok(()) => {
                            let hex_dump = raw_vsock_pkt.data
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            let ascii_dump = raw_vsock_pkt.data
                                .iter()
                                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                                .collect::<String>();
                            
                            info!(
                                "vsock: [CID {}] successfully wrote {} bytes to Unix socket: HEX=[{}] ASCII=[{}]",
                                self.guest_cid,
                                raw_vsock_pkt.data.len(),
                                hex_dump,
                                ascii_dump
                            );
                        }
                        Err(e) => {
                            warn!(
                                "vsock: [CID {}] failed to write to Unix socket: {:?}",
                                self.guest_cid, e
                            );
                        }
                    }
                }

                // TODO: Handle flow control - send credit update if needed
            } else {
                warn!("vsock: [CID {}] proxy mode - no connection found for data packet from CID {} port {} to port {}", 
                    self.guest_cid, src_cid, src_port, dst_port);
            }
        } else {
            info!(
                "vsock: [CID {}] proxy mode - packet with op: {} not yet handled",
                self.guest_cid, op
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use tempfile::tempdir;
    use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
    #[cfg(feature = "backend_vsock")]
    use vsock::{VsockListener, VMADDR_CID_ANY, VMADDR_CID_LOCAL};

    use super::*;
    #[cfg(feature = "backend_vsock")]
    use crate::vhu_vsock::VsockProxyInfo;
    use crate::vhu_vsock::{BackendType, VhostUserVsockBackend, VsockConfig, VSOCK_OP_RW};

    const DATA_LEN: usize = 16;
    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
    const QUEUE_SIZE: usize = 1024;
    const GROUP_NAME: &str = "default";
    const VSOCK_PEER_PORT: u32 = 1234;

    fn test_vsock_thread_backend(backend_info: BackendType) {
        const CID: u64 = 3;

        let epoll_fd = epoll::create(false).unwrap();

        let groups_set: HashSet<String> = vec![GROUP_NAME.to_string()].into_iter().collect();

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let mut vtp = VsockThreadBackend::new(
            backend_info,
            epoll_fd,
            CID,
            CONN_TX_BUF_SIZE,
            Arc::new(RwLock::new(groups_set)),
            cid_map,
        );

        assert!(!vtp.pending_rx());

        let mut pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (hdr_raw, data_raw) = pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        // SAFETY: Safe as hdr_raw and data_raw are guaranteed to be valid.
        let mut packet = unsafe { VsockPacket::new(hdr_raw, Some(data_raw)).unwrap() };

        assert_eq!(
            vtp.recv_pkt(&mut packet).unwrap_err().to_string(),
            Error::EmptyBackendRxQ.to_string()
        );

        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_type(VSOCK_TYPE_STREAM);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_src_cid(CID);
        packet.set_dst_cid(VSOCK_HOST_CID);
        packet.set_dst_port(VSOCK_PEER_PORT);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_REQUEST);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_RW);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_RST);
        assert!(vtp.send_pkt(&packet).is_ok());

        assert!(vtp.recv_pkt(&mut packet).is_ok());

        // TODO: it is a nop for now
        vtp.enq_rst();
    }

    #[test]
    fn test_vsock_thread_backend_unix() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vsock_socket_path = test_dir.path().join("test_vsock_thread_backend.vsock");
        let vsock_peer_path = test_dir.path().join("test_vsock_thread_backend.vsock_1234");

        let _listener = UnixListener::bind(&vsock_peer_path).unwrap();
        let backend_info = BackendType::UnixDomainSocket(vsock_socket_path.clone());

        test_vsock_thread_backend(backend_info);

        // cleanup
        let _ = std::fs::remove_file(&vsock_peer_path);
        let _ = std::fs::remove_file(&vsock_socket_path);

        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_thread_backend_vsock() {
        VsockListener::bind_with_cid_port(VMADDR_CID_LOCAL, libc::VMADDR_PORT_ANY).expect(
            "This test uses VMADDR_CID_LOCAL, so the vsock_loopback kernel module must be loaded",
        );

        let _listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, VSOCK_PEER_PORT).unwrap();
        let backend_info = BackendType::Vsock(VsockProxyInfo {
            forward_cid: VMADDR_CID_LOCAL,
            listen_ports: vec![],
        });

        test_vsock_thread_backend(backend_info);
    }

    #[test]
    fn test_vsock_thread_backend_sibling_vms() {
        const CID: u64 = 3;
        const SIBLING_CID: u64 = 4;
        const SIBLING2_CID: u64 = 5;
        const SIBLING_LISTENING_PORT: u32 = 1234;

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vsock_socket_path = test_dir.path().join("test_vsock_thread_backend.vsock");
        let sibling_vhost_socket_path = test_dir
            .path()
            .join("test_vsock_thread_backend_sibling.socket");
        let sibling_vsock_socket_path = test_dir
            .path()
            .join("test_vsock_thread_backend_sibling.vsock");
        let sibling2_vhost_socket_path = test_dir
            .path()
            .join("test_vsock_thread_backend_sibling2.socket");
        let sibling2_vsock_socket_path = test_dir
            .path()
            .join("test_vsock_thread_backend_sibling2.vsock");

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let sibling_config = VsockConfig::new(
            SIBLING_CID,
            sibling_vhost_socket_path,
            BackendType::UnixDomainSocket(sibling_vsock_socket_path),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            vec!["group1", "group2", "group3"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        let sibling2_config = VsockConfig::new(
            SIBLING2_CID,
            sibling2_vhost_socket_path,
            BackendType::UnixDomainSocket(sibling2_vsock_socket_path),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            vec!["group1"].into_iter().map(String::from).collect(),
        );

        let sibling_backend =
            Arc::new(VhostUserVsockBackend::new(sibling_config, cid_map.clone()).unwrap());
        let sibling2_backend =
            Arc::new(VhostUserVsockBackend::new(sibling2_config, cid_map.clone()).unwrap());

        let epoll_fd = epoll::create(false).unwrap();

        let groups_set: HashSet<String> = vec!["groupA", "groupB", "group3"]
            .into_iter()
            .map(String::from)
            .collect();

        let mut vtp = VsockThreadBackend::new(
            BackendType::UnixDomainSocket(vsock_socket_path),
            epoll_fd,
            CID,
            CONN_TX_BUF_SIZE,
            Arc::new(RwLock::new(groups_set)),
            cid_map,
        );

        assert!(!vtp.pending_raw_pkts());

        let mut pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (hdr_raw, data_raw) = pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        // SAFETY: Safe as hdr_raw and data_raw are guaranteed to be valid.
        let mut packet = unsafe { VsockPacket::new(hdr_raw, Some(data_raw)).unwrap() };

        assert_eq!(
            vtp.recv_raw_pkt(&mut packet).unwrap_err().to_string(),
            Error::EmptyRawPktsQueue.to_string()
        );

        packet.set_type(VSOCK_TYPE_STREAM);
        packet.set_src_cid(CID);
        packet.set_dst_cid(SIBLING_CID);
        packet.set_dst_port(SIBLING_LISTENING_PORT);
        packet.set_op(VSOCK_OP_RW);
        packet.set_len(DATA_LEN as u32);
        packet
            .data_slice()
            .unwrap()
            .copy_from(&[0xCAu8, 0xFEu8, 0xBAu8, 0xBEu8]);

        assert!(vtp.send_pkt(&packet).is_ok());
        assert!(sibling_backend.threads[0]
            .lock()
            .unwrap()
            .thread_backend
            .pending_raw_pkts());

        packet.set_dst_cid(SIBLING2_CID);
        assert!(vtp.send_pkt(&packet).is_ok());
        // packet should be discarded since sibling2 is not in the same group
        assert!(!sibling2_backend.threads[0]
            .lock()
            .unwrap()
            .thread_backend
            .pending_raw_pkts());

        let mut recvd_pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (recvd_hdr_raw, recvd_data_raw) = recvd_pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        let mut recvd_packet =
            // SAFETY: Safe as recvd_hdr_raw and recvd_data_raw are guaranteed to be valid.
            unsafe { VsockPacket::new(recvd_hdr_raw, Some(recvd_data_raw)).unwrap() };

        assert!(sibling_backend.threads[0]
            .lock()
            .unwrap()
            .thread_backend
            .recv_raw_pkt(&mut recvd_packet)
            .is_ok());

        assert_eq!(recvd_packet.type_(), VSOCK_TYPE_STREAM);
        assert_eq!(recvd_packet.src_cid(), CID);
        assert_eq!(recvd_packet.dst_cid(), SIBLING_CID);
        assert_eq!(recvd_packet.dst_port(), SIBLING_LISTENING_PORT);
        assert_eq!(recvd_packet.op(), VSOCK_OP_RW);
        assert_eq!(recvd_packet.len(), DATA_LEN as u32);

        assert_eq!(recvd_data_raw[0], 0xCAu8);
        assert_eq!(recvd_data_raw[1], 0xFEu8);
        assert_eq!(recvd_data_raw[2], 0xBAu8);
        assert_eq!(recvd_data_raw[3], 0xBEu8);

        test_dir.close().unwrap();
    }
}
