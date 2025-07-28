// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufRead, BufReader, Read},
    iter::FromIterator,
    num::Wrapping,
    ops::Deref,
    os::unix::{
        net::{UnixListener, UnixStream},
        prelude::{AsRawFd, FromRawFd, RawFd},
    },
    sync::{
        mpsc::{self, Sender},
        Arc, RwLock,
    },
    thread,
};

use log::{error, info, warn};
use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
use virtio_queue::QueueOwnedT;
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};
#[cfg(feature = "backend_vsock")]
use vsock::{VsockListener, VMADDR_CID_ANY};

use crate::{
    rxops::*,
    thread_backend::*,
    vhu_vsock::{
        BackendType, CidMap, ConnMapKey, Error, Result, VhostUserVsockBackend, BACKEND_EVENT,
        SIBLING_VM_EVENT, VSOCK_HOST_CID, VSOCK_OP_RW, VSOCK_TYPE_STREAM,
    },
    vsock_conn::*,
};

type ArcVhostBknd = Arc<VhostUserVsockBackend>;

#[derive(PartialEq, Debug)]
enum RxQueueType {
    Standard,
    RawPkts,
}

// Data which is required by a worker handling event idx.
struct EventData {
    vring: VringRwLock,
    event_idx: bool,
    head_idx: u16,
    used_len: usize,
}

enum ListenerType {
    Unix(UnixListener),
    #[cfg(feature = "backend_vsock")]
    Vsock(VsockListener),
}

pub(crate) struct VhostUserVsockThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    backend_info: BackendType,
    /// Host socket raw file descriptor and listener.
    host_listeners_map: HashMap<i32, ListenerType>,
    /// epoll fd to which new host connections are added.
    epoll_file: File,
    /// VsockThreadBackend instance.
    pub thread_backend: VsockThreadBackend,
    /// CID of the guest.
    guest_cid: u64,
    /// Channel to a worker which handles event idx.
    sender: Sender<EventData>,
    /// host side port on which application listens.
    local_port: Wrapping<u32>,
    /// The tx buffer size
    tx_buffer_size: u32,
    /// EventFd to notify this thread for custom events. Currently used to
    /// notify this thread to process raw vsock packets sent from a sibling
    /// VM.
    pub sibling_event_fd: EventFd,
    /// Keeps track of which RX queue was processed first in the last iteration.
    /// Used to alternate between the RX queues to prevent the starvation of one
    /// by the other.
    last_processed: RxQueueType,
}

impl VhostUserVsockThread {
    /// Detect and strip vhost headers from Unix socket data
    /// Returns (payload_data, payload_size) where payload_data is the data without headers
    fn strip_vhost_headers_if_present<'a>(buffer: &'a [u8]) -> (&'a [u8], usize) {
        // Check if the buffer might contain a vhost header
        if buffer.len() < PKT_HEADER_SIZE {
            // Too small to contain a vhost header, return as-is
            return (buffer, buffer.len());
        }

        // Try to parse as a vhost packet header to detect if it's actually a vhost packet
        // Vhost headers have a specific structure - check if this looks like one
        let potential_header = &buffer[..PKT_HEADER_SIZE];

        // Extract fields from potential header
        let src_cid = u64::from_le_bytes(potential_header[0..8].try_into().unwrap_or([0; 8]));
        let dst_cid = u64::from_le_bytes(potential_header[8..16].try_into().unwrap_or([0; 8]));
        let _src_port = u32::from_le_bytes(potential_header[16..20].try_into().unwrap_or([0; 4]));
        let _dst_port = u32::from_le_bytes(potential_header[20..24].try_into().unwrap_or([0; 4]));
        let len = u32::from_le_bytes(potential_header[24..28].try_into().unwrap_or([0; 4]));
        let pkt_type = u16::from_le_bytes(potential_header[28..30].try_into().unwrap_or([0; 2]));
        let op = u16::from_le_bytes(potential_header[30..32].try_into().unwrap_or([0; 2]));

        // Heuristics to detect if this is actually a vhost header:
        // 1. CIDs should be reasonable values (not random garbage)
        // 2. Length should match remaining buffer size
        // 3. Packet type should be valid (VSOCK_TYPE_STREAM = 1)
        // 4. Operation should be valid (1-7 are valid ops)
        let looks_like_vhost_header = src_cid > 0 && src_cid < 0xFFFFFFFF &&  // Reasonable CID range
            dst_cid > 0 && dst_cid < 0xFFFFFFFF &&  // Reasonable CID range  
            len as usize == buffer.len() - PKT_HEADER_SIZE && // Length matches remaining data
            pkt_type == crate::vhu_vsock::VSOCK_TYPE_STREAM && // Valid packet type
            op >= 1 && op <= 7; // Valid operation code

        if looks_like_vhost_header {
            info!(
                "vsock: detected vhost header in Unix socket data, stripping {} bytes header",
                PKT_HEADER_SIZE
            );

            // Return payload without the header
            (&buffer[PKT_HEADER_SIZE..], len as usize)
        } else {
            // Not a vhost header, return data as-is
            info!(
                "vsock: no vhost header detected in Unix socket data, forwarding {} bytes as-is",
                buffer.len()
            );
            (buffer, buffer.len())
        }
    }

    /// Create a new instance of VhostUserVsockThread.
    pub fn new(
        backend_info: BackendType,
        guest_cid: u64,
        tx_buffer_size: u32,
        groups: Vec<String>,
        cid_map: Arc<RwLock<CidMap>>,
    ) -> Result<Self> {
        let mut host_listeners_map = HashMap::new();
        match &backend_info {
            BackendType::UnixDomainSocket(uds_path) => {
                // TODO: better error handling, maybe add a param to force the unlink
                let _ = std::fs::remove_file(uds_path.clone());
                let host_listener = UnixListener::bind(uds_path)
                    .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                    .map_err(Error::UnixBind)?;
                let host_sock = host_listener.as_raw_fd();
                host_listeners_map.insert(host_sock, ListenerType::Unix(host_listener));
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::UnixToVsock(uds_path, _vsock_info) => {
                info!(
                    "vsock: [CID {}] creating Unix socket listener for forwarding to vsock at {}",
                    guest_cid,
                    uds_path.display()
                );
                // TODO: better error handling, maybe add a param to force the unlink
                let _ = std::fs::remove_file(uds_path.clone());
                let host_listener = UnixListener::bind(uds_path)
                    .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                    .map_err(Error::UnixBind)?;
                let host_sock = host_listener.as_raw_fd();
                info!(
                    "vsock: [CID {}] successfully created Unix socket listener with fd {}",
                    guest_cid, host_sock
                );
                host_listeners_map.insert(host_sock, ListenerType::Unix(host_listener));
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::Vsock(vsock_info) => {
                for p in &vsock_info.listen_ports {
                    info!(
                        "vsock: [CID {}] creating vsock listener on port {}",
                        guest_cid, p
                    );
                    let host_listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, *p)
                        .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                        .map_err(Error::VsockBind)?;
                    let host_sock = host_listener.as_raw_fd();
                    info!(
                        "vsock: [CID {}] successfully created vsock listener on port {} with fd {}",
                        guest_cid, p, host_sock
                    );
                    host_listeners_map.insert(host_sock, ListenerType::Vsock(host_listener));
                }
                if vsock_info.listen_ports.is_empty() {
                    info!(
                        "vsock: [CID {}] no forward-listen ports configured",
                        guest_cid
                    );
                } else {
                    info!(
                        "vsock: [CID {}] configured to accept host connections on ports: {:?}",
                        guest_cid, vsock_info.listen_ports
                    );
                }
            }
        }

        let epoll_fd = epoll::create(true).map_err(Error::EpollFdCreate)?;
        // SAFETY: Safe as the fd is guaranteed to be valid here.
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        let mut groups = groups;
        let groups_set: Arc<RwLock<HashSet<String>>> =
            Arc::new(RwLock::new(HashSet::from_iter(groups.drain(..))));

        let sibling_event_fd = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

        let thread_backend = VsockThreadBackend::new(
            backend_info.clone(),
            epoll_fd,
            guest_cid,
            tx_buffer_size,
            groups_set.clone(),
            cid_map.clone(),
        );

        {
            let mut cid_map = cid_map.write().unwrap();
            if cid_map.contains_key(&guest_cid) {
                return Err(Error::CidAlreadyInUse);
            }

            cid_map.insert(
                guest_cid,
                (
                    thread_backend.raw_pkts_queue.clone(),
                    groups_set,
                    sibling_event_fd.try_clone().unwrap(),
                ),
            );
        }
        let (sender, receiver) = mpsc::channel::<EventData>();
        thread::spawn(move || loop {
            // TODO: Understand why doing the following in the background thread works.
            // maybe we'd better have thread pool for the entire application if necessary.
            let Ok(event_data) = receiver.recv() else {
                break;
            };
            Self::vring_handle_event(event_data);
        });

        let thread = VhostUserVsockThread {
            mem: None,
            event_idx: false,
            backend_info: backend_info.clone(),
            host_listeners_map,
            epoll_file,
            thread_backend,
            guest_cid,
            sender,
            local_port: Wrapping(0),
            tx_buffer_size,
            sibling_event_fd,
            last_processed: RxQueueType::Standard,
        };

        for host_raw_fd in thread.host_listeners_map.keys() {
            info!(
                "vsock: [CID {}] registering host listener fd {} with epoll fd {}",
                guest_cid, host_raw_fd, epoll_fd
            );
            match VhostUserVsockThread::epoll_register(
                epoll_fd,
                *host_raw_fd,
                epoll::Events::EPOLLIN,
            ) {
                Ok(()) => {
                    info!(
                        "vsock: [CID {}] successfully registered host listener fd {} with epoll",
                        guest_cid, host_raw_fd
                    );
                }
                Err(e) => {
                    error!(
                        "vsock: [CID {}] failed to register host listener fd {} with epoll: {:?}",
                        guest_cid, host_raw_fd, e
                    );
                    return Err(e);
                }
            }
        }

        Ok(thread)
    }

    fn vring_handle_event(event_data: EventData) {
        if event_data.event_idx {
            if event_data
                .vring
                .add_used(event_data.head_idx, event_data.used_len as u32)
                .is_err()
            {
                warn!("Could not return used descriptors to ring");
            }
            match event_data.vring.needs_notification() {
                Err(_) => {
                    warn!("Could not check if queue needs to be notified");
                    event_data.vring.signal_used_queue().unwrap();
                }
                Ok(needs_notification) => {
                    if needs_notification {
                        event_data.vring.signal_used_queue().unwrap();
                    }
                }
            }
        } else {
            if event_data
                .vring
                .add_used(event_data.head_idx, event_data.used_len as u32)
                .is_err()
            {
                warn!("Could not return used descriptors to ring");
            }
            event_data.vring.signal_used_queue().unwrap();
        }
    }
    /// Register a file with an epoll to listen for events in evset.
    pub fn epoll_register(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(Error::EpollAdd)?;

        Ok(())
    }

    /// Remove a file from the epoll.
    pub fn epoll_unregister(epoll_fd: RawFd, fd: RawFd) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_DEL,
            fd,
            epoll::Event::new(epoll::Events::empty(), 0),
        )
        .map_err(Error::EpollRemove)?;

        Ok(())
    }

    /// Modify the events we listen to for the fd in the epoll.
    pub fn epoll_modify(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_MOD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(Error::EpollModify)?;

        Ok(())
    }

    /// Return raw file descriptor of the epoll file.
    fn get_epoll_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }

    /// Register our listeners in the VringEpollHandler
    pub fn register_listeners(&mut self, epoll_handler: Arc<VringEpollHandler<ArcVhostBknd>>) {
        info!("vsock: [CID {}] registering internal epoll fd {} as BACKEND_EVENT with main epoll handler", 
            self.guest_cid, self.get_epoll_fd());

        match epoll_handler.register_listener(
            self.get_epoll_fd(),
            EventSet::IN,
            u64::from(BACKEND_EVENT),
        ) {
            Ok(()) => {
                info!(
                    "vsock: [CID {}] successfully registered BACKEND_EVENT",
                    self.guest_cid
                );
            }
            Err(e) => {
                error!(
                    "vsock: [CID {}] failed to register BACKEND_EVENT: {:?}",
                    self.guest_cid, e
                );
            }
        }

        info!("vsock: [CID {}] registering sibling event fd {} as SIBLING_VM_EVENT with main epoll handler", 
            self.guest_cid, self.sibling_event_fd.as_raw_fd());

        match epoll_handler.register_listener(
            self.sibling_event_fd.as_raw_fd(),
            EventSet::IN,
            u64::from(SIBLING_VM_EVENT),
        ) {
            Ok(()) => {
                info!(
                    "vsock: [CID {}] successfully registered SIBLING_VM_EVENT",
                    self.guest_cid
                );
            }
            Err(e) => {
                error!(
                    "vsock: [CID {}] failed to register SIBLING_VM_EVENT: {:?}",
                    self.guest_cid, e
                );
            }
        }
    }

    /// Process backend events in proxy mode (no guest VM)
    fn process_backend_evt_proxy(&mut self) {
        info!(
            "vsock: [CID {}] processing backend events in proxy mode",
            self.thread_backend.guest_cid
        );

        let mut epoll_events = vec![epoll::Event::new(epoll::Events::empty(), 0); 32];

        match epoll::wait(self.epoll_file.as_raw_fd(), 0, epoll_events.as_mut_slice()) {
            Ok(ev_cnt) => {
                for i in 0..ev_cnt {
                    let fd = epoll_events[i].data as RawFd;
                    let evset = epoll::Events::from_bits_truncate(epoll_events[i].events);

                    if let Some(key) = self.thread_backend.listener_map.get(&fd) {
                        info!(
                            "vsock: [CID {}] proxy backend event for connection {:?}",
                            self.thread_backend.guest_cid, key
                        );

                        // Handle Unix socket data
                        if evset.contains(epoll::Events::EPOLLIN) {
                            // Data available to read from Unix socket
                            // We need to package it as vsock packets and send to the peer
                            info!(
                                "vsock: [CID {}] data available on Unix socket",
                                self.thread_backend.guest_cid
                            );

                            if let Some(conn) = self.thread_backend.conn_map.get_mut(&key) {
                                let mut buffer = vec![0u8; 4096];
                                match conn.stream.read(&mut buffer) {
                                    Ok(0) => {
                                        // Connection closed
                                        info!(
                                            "vsock: [CID {}] Unix socket closed by peer",
                                            self.thread_backend.guest_cid
                                        );
                                        // TODO: Send VSOCK_OP_SHUTDOWN
                                    }
                                    Ok(n) => {
                                        // Check for and strip vhost headers if present
                                        let raw_data = &buffer[..n];
                                        let (payload_data, payload_len) =
                                            Self::strip_vhost_headers_if_present(raw_data);

                                        info!(
                                            "vsock: [CID {}] read {} bytes from Unix socket (payload: {} bytes after header processing)",
                                            self.thread_backend.guest_cid, n, payload_len
                                        );

                                        // Send data back to vsock peer
                                        // For proxy connections, guest_cid is the peer from host perspective
                                        if let Some((peer_queue, _, peer_event_fd)) = self
                                            .thread_backend
                                            .cid_map
                                            .read()
                                            .unwrap()
                                            .get(&conn.guest_cid)
                                        {
                                            let mut response = RawVsockPacket {
                                                header: [0; PKT_HEADER_SIZE],
                                                data: payload_data.to_vec(),
                                            };

                                            // Build VSOCK_OP_RW packet
                                            // In proxy mode: local_cid is host (CID 3), guest_cid is peer (CID 16)
                                            response.header[0..8].copy_from_slice(
                                                &self.thread_backend.guest_cid.to_le_bytes(),
                                            ); // src_cid (CID 3)
                                            response.header[8..16]
                                                .copy_from_slice(&conn.guest_cid.to_le_bytes()); // dst_cid (peer)
                                            response.header[16..20]
                                                .copy_from_slice(&conn.local_port.to_le_bytes()); // src_port
                                            response.header[20..24]
                                                .copy_from_slice(&conn.peer_port.to_le_bytes()); // dst_port
                                            response.header[24..28].copy_from_slice(
                                                &(payload_len as u32).to_le_bytes(),
                                            ); // len
                                            response.header[28..30]
                                                .copy_from_slice(&VSOCK_TYPE_STREAM.to_le_bytes()); // type
                                            response.header[30..32]
                                                .copy_from_slice(&VSOCK_OP_RW.to_le_bytes()); // op
                                            response.header[32..36]
                                                .copy_from_slice(&0u32.to_le_bytes()); // flags
                                            response.header[36..40].copy_from_slice(
                                                &conn.tx_buf.get_buf_size().to_le_bytes(),
                                            ); // buf_alloc
                                            response.header[40..44]
                                                .copy_from_slice(&conn.fwd_cnt.0.to_le_bytes()); // fwd_cnt

                                            peer_queue.write().unwrap().push_back(response);
                                            let _ = peer_event_fd.write(1);

                                            info!(
                                                "vsock: [CID {}] sent {} bytes to CID {} (after header stripping)",
                                                self.thread_backend.guest_cid, payload_len, conn.guest_cid
                                            );
                                        }
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        // No data available yet
                                    }
                                    Err(e) => {
                                        warn!(
                                            "vsock: [CID {}] error reading from Unix socket: {:?}",
                                            self.thread_backend.guest_cid, e
                                        );
                                    }
                                }
                            }
                        }

                        if evset.contains(epoll::Events::EPOLLHUP) {
                            // Connection closed
                            info!(
                                "vsock: [CID {}] Unix socket connection closed",
                                self.thread_backend.guest_cid
                            );
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::Interrupted {
                    error!(
                        "vsock: [CID {}] epoll_wait error in proxy mode: {:?}",
                        self.thread_backend.guest_cid, e
                    );
                }
            }
        }
    }

    /// Process a BACKEND_EVENT received by VhostUserVsockBackend.
    pub fn process_backend_evt(&mut self, _evset: EventSet) {
        info!(
            "vsock: [CID {}] *** process_backend_evt called *** evset={:?}",
            self.thread_backend.guest_cid, _evset
        );

        // If no memory is configured, we're in proxy mode
        if self.mem.is_none() {
            info!(
                "vsock: [CID {}] no guest memory configured, processing in proxy mode",
                self.thread_backend.guest_cid
            );
            self.process_backend_evt_proxy();
            return;
        }

        info!(
            "vsock: [CID {}] guest memory configured, processing epoll events",
            self.thread_backend.guest_cid
        );
        info!(
            "vsock: [CID {}] about to call epoll_wait on fd {} with {} host listeners registered",
            self.thread_backend.guest_cid,
            self.epoll_file.as_raw_fd(),
            self.host_listeners_map.len()
        );

        let mut epoll_events = vec![epoll::Event::new(epoll::Events::empty(), 0); 32];
        'epoll: loop {
            info!(
                "vsock: [CID {}] calling epoll_wait(fd={}, timeout=0) with {} registered fds",
                self.thread_backend.guest_cid,
                self.epoll_file.as_raw_fd(),
                self.host_listeners_map.len()
            );

            match epoll::wait(self.epoll_file.as_raw_fd(), 0, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    info!(
                        "vsock: [CID {}] epoll_wait returned {} events",
                        self.thread_backend.guest_cid, ev_cnt
                    );

                    if ev_cnt == 0 {
                        info!(
                            "vsock: [CID {}] no epoll events detected - breaking from loop",
                            self.thread_backend.guest_cid
                        );
                        break 'epoll;
                    }

                    for evt in epoll_events.iter().take(ev_cnt) {
                        let fd = evt.data as RawFd;
                        let events = evt.events;

                        info!(
                            "vsock: [CID {}] processing epoll event: fd={}, events={:?} (raw={})",
                            self.thread_backend.guest_cid,
                            fd,
                            epoll::Events::from_bits(events),
                            events
                        );

                        // Check if this fd is one of our host listeners
                        if self.host_listeners_map.contains_key(&fd) {
                            info!(
                                "vsock: [CID {}] *** HOST LISTENER EVENT DETECTED *** fd={}",
                                self.thread_backend.guest_cid, fd
                            );
                        } else {
                            info!(
                                "vsock: [CID {}] event for non-host-listener fd={}",
                                self.thread_backend.guest_cid, fd
                            );
                        }

                        self.handle_event(fd, epoll::Events::from_bits(events).unwrap());
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        info!(
                            "vsock: [CID {}] epoll_wait interrupted, continuing",
                            self.thread_backend.guest_cid
                        );
                        continue;
                    }
                    warn!(
                        "vsock: [CID {}] epoll_wait error: {:?}",
                        self.thread_backend.guest_cid, e
                    );
                }
            }
            break 'epoll;
        }
        info!(
            "vsock: [CID {}] finished processing backend events",
            self.thread_backend.guest_cid
        );
    }

    /// Handle a BACKEND_EVENT by either accepting a new connection or
    /// forwarding a request to the appropriate connection object.
    fn handle_event(&mut self, fd: RawFd, evset: epoll::Events) {
        if let Some(listener) = self.host_listeners_map.get(&fd) {
            // This is a new connection initiated by an application running on the host
            match listener {
                ListenerType::Unix(unix_listener) => {
                    let conn = unix_listener.accept().map_err(Error::UnixAccept);
                    if self.mem.is_some() {
                        match &self.backend_info {
                            BackendType::UnixDomainSocket(_) => {
                                // Traditional mode - add stream listener and wait for CONNECT command
                                conn.and_then(|(stream, _)| {
                                    stream
                                        .set_nonblocking(true)
                                        .map(|_| stream)
                                        .map_err(Error::UnixAccept)
                                })
                                .and_then(|stream| self.add_stream_listener(stream))
                                .unwrap_or_else(|err| {
                                    warn!("Unable to accept new local connection: {err:?}");
                                });
                            }
                            #[cfg(feature = "backend_vsock")]
                            BackendType::UnixToVsock(_, vsock_info) => {
                                // Forward mode - create virtual connection through vhost-user protocol
                                info!(
                                    "vsock: [CID {}] Unix socket connection received, creating virtual connection to guest CID {} port {}",
                                    self.thread_backend.guest_cid, vsock_info.target_cid, vsock_info.target_port
                                );

                                match conn {
                                    Ok((unix_stream, _)) => {
                                        if let Err(err) = unix_stream.set_nonblocking(true) {
                                            warn!("Failed to set Unix stream to non-blocking: {err:?}");
                                            return;
                                        }

                                        // Create a virtual vhost-user connection
                                        // We'll act as if this is a host-initiated connection TO the guest
                                        if let Err(err) = self.setup_unix_to_guest_proxy(
                                            unix_stream,
                                            vsock_info.target_cid,
                                            vsock_info.target_port,
                                        ) {
                                            warn!("Failed to setup Unix to guest proxy: {err:?}");
                                        }
                                    }
                                    Err(err) => {
                                        warn!("Failed to accept Unix socket connection: {err:?}");
                                    }
                                }
                            }
                            _ => {
                                warn!("Unexpected backend type for Unix listener");
                            }
                        }
                    } else {
                        // If we aren't ready to process requests, accept and immediately close
                        // the connection.
                        conn.map(drop).unwrap_or_else(|err| {
                            warn!("Error closing an incoming connection: {err:?}");
                        });
                    }
                }
                #[cfg(feature = "backend_vsock")]
                ListenerType::Vsock(vsock_listener) => {
                    info!(
                        "vsock: [CID {}] received connection on vsock listener fd {}",
                        self.thread_backend.guest_cid, fd
                    );
                    let conn = vsock_listener.accept().map_err(Error::VsockAccept);
                    if self.mem.is_some() {
                        match conn {
                            Ok((stream, addr)) => {
                                info!(
                                    "vsock: [CID {}] accepted connection from CID {} port {}",
                                    self.thread_backend.guest_cid,
                                    addr.cid(),
                                    addr.port()
                                );

                                if let Err(err) = stream.set_nonblocking(true) {
                                    warn!("Failed to set stream to non-blocking: {err:?}");
                                    return;
                                }

                                let peer_port = match vsock_listener.local_addr() {
                                    Ok(listener_addr) => {
                                        info!(
                                            "vsock: [CID {}] listener bound to port {}",
                                            self.thread_backend.guest_cid,
                                            listener_addr.port()
                                        );
                                        listener_addr.port()
                                    }
                                    Err(err) => {
                                        warn!("Failed to get peer address: {err:?}");
                                        return;
                                    }
                                };

                                let local_port = addr.port();
                                let stream_raw_fd = stream.as_raw_fd();
                                info!("vsock: [CID {}] adding new host connection: local_port={}, peer_port={}, stream_fd={}", 
                                    self.thread_backend.guest_cid, local_port, peer_port, stream_raw_fd);

                                self.add_new_connection_from_host(
                                    stream_raw_fd,
                                    StreamType::Vsock(stream),
                                    local_port,
                                    peer_port,
                                );
                                if let Err(err) = Self::epoll_register(
                                    self.get_epoll_fd(),
                                    stream_raw_fd,
                                    epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                                ) {
                                    warn!("Failed to register with epoll: {err:?}");
                                } else {
                                    info!("vsock: [CID {}] successfully registered stream_fd {} with epoll", 
                                        self.thread_backend.guest_cid, stream_raw_fd);
                                }
                            }
                            Err(err) => {
                                warn!(
                                    "vsock: [CID {}] failed to accept connection on fd {}: {:?}",
                                    self.thread_backend.guest_cid, fd, err
                                );
                            }
                        }
                    } else {
                        info!("vsock: [CID {}] no guest VM memory configured - closing incoming connection", 
                            self.thread_backend.guest_cid);
                        // If we aren't ready to process requests, accept and immediately close
                        // the connection.
                        conn.map(drop).unwrap_or_else(|err| {
                            warn!("Error closing an incoming connection: {err:?}");
                        });
                    }
                }
            }
        } else if let Some(key) = self.thread_backend.listener_map.get(&fd).cloned() {
            // This might be a forwarding connection OR a Unix socket proxy connection
            info!(
                "vsock: [CID {}] received event on fd {} with key {:?}",
                self.thread_backend.guest_cid, fd, key
            );

            info!(
                "vsock: [CID {}] DEBUG: evset={:?}, EPOLLOUT={:?}, contains_EPOLLOUT={}",
                self.thread_backend.guest_cid,
                evset,
                epoll::Events::EPOLLOUT,
                evset.contains(epoll::Events::EPOLLOUT)
            );

            // Handle EPOLLHUP first - if the connection is closed, clean up immediately
            if evset.contains(epoll::Events::EPOLLHUP) {
                // But first, check if there's data to read with the HUP
                if evset.contains(epoll::Events::EPOLLIN) {
                    info!(
                        "vsock: [CID {}] Unix socket proxy fd {} has both EPOLLIN and EPOLLHUP - reading final data first",
                        self.thread_backend.guest_cid, fd
                    );

                    // Try to read any final data before closing
                    if let Some(conn) = self.thread_backend.conn_map.get_mut(&key) {
                        let mut buffer = [0u8; 4096];
                        match conn.stream.read(&mut buffer) {
                            Ok(0) => {
                                info!(
                                    "vsock: [CID {}] No final data to read from fd {} before close",
                                    self.thread_backend.guest_cid, fd
                                );
                            }
                            Ok(n) => {
                                info!(
                                    "vsock: [CID {}] Read {} final bytes from fd {} before close: {:?}",
                                    self.thread_backend.guest_cid, fd, n, &buffer[..n]
                                );
                                // Process this final data if needed
                            }
                            Err(e) => {
                                info!(
                                    "vsock: [CID {}] Error reading final data from fd {}: {:?}",
                                    self.thread_backend.guest_cid, fd, e
                                );
                            }
                        }

                        // Send EOF to complete the conversation
                        if conn.stream.is_hybrid_vsock() {
                            if let Err(e) = conn.stream.shutdown_write() {
                                warn!(
                                    "vsock: [CID {}] Failed to shutdown write when client closed connection: {:?}",
                                    self.thread_backend.guest_cid, e
                                );
                            } else {
                                info!(
                                    "vsock: [CID {}] Successfully shutdown write after client closed connection - EOF sent",
                                    self.thread_backend.guest_cid
                                );
                            }
                        }
                    }
                }

                info!(
                    "vsock: [CID {}] Unix socket proxy fd {} closed by client",
                    self.thread_backend.guest_cid, fd
                );
                self.cleanup_unix_proxy_connection(fd, &key);
                return; // Return immediately after cleanup to avoid processing other events
            }

            // Check if this is a Unix socket proxy connection
            info!(
                "vsock: [CID {}] DEBUG: checking conn_map for key {:?}, found={}",
                self.thread_backend.guest_cid,
                key,
                self.thread_backend.conn_map.contains_key(&key)
            );

            if let Some(conn) = self.thread_backend.conn_map.get_mut(&key) {
                info!(
                    "vsock: [CID {}] DEBUG: found connection for key {:?}, processing events",
                    self.thread_backend.guest_cid, key
                );
                // This is a Unix socket proxy connection - handle data normally
                if evset.contains(epoll::Events::EPOLLIN) {
                    info!(
                        "vsock: [CID {}] data available on Unix socket proxy fd {}, queuing forward to guest",
                        self.thread_backend.guest_cid, fd
                    );

                    // Log connection state before enqueuing
                    info!(
                        "vsock: [CID {}] connection state before enqueue - connect:{}, rx_queue_len:{}, pending_rx:{}",
                        self.thread_backend.guest_cid, conn.connect, conn.rx_queue.len(), conn.rx_queue.pending_rx()
                    );

                    // Enqueue a read operation for this connection
                    conn.rx_queue.enqueue(crate::rxops::RxOps::Rw);
                    self.thread_backend.backend_rxq.push_back(key.clone());

                    info!(
                        "vsock: [CID {}] enqueued Rw op for fd {}, backend_rxq size now: {}",
                        self.thread_backend.guest_cid,
                        fd,
                        self.thread_backend.backend_rxq.len()
                    );

                    // Disable EPOLLIN temporarily to prevent busy-looping while we process
                    if let Err(e) = Self::epoll_modify(
                        self.get_epoll_fd(),
                        fd,
                        epoll::Events::EPOLLOUT, // Only EPOLLOUT until we process the read
                    ) {
                        warn!(
                            "vsock: [CID {}] failed to modify epoll for fd {}: {:?}",
                            self.thread_backend.guest_cid, fd, e
                        );
                    } else {
                        info!(
                            "vsock: [CID {}] disabled EPOLLIN for fd {} to prevent busy-loop",
                            self.thread_backend.guest_cid, fd
                        );
                    }
                }

                // Handle EPOLLOUT events for Unix proxy connections
                if evset.contains(epoll::Events::EPOLLOUT) {
                    info!(
                        "vsock: [CID {}] EPOLLOUT event on Unix socket proxy fd {} - removing EPOLLOUT from registration",
                        self.thread_backend.guest_cid, fd
                    );

                    // Modify epoll registration to only listen for EPOLLIN events
                    if let Err(err) = Self::epoll_modify(
                        self.get_epoll_fd(),
                        fd,
                        epoll::Events::EPOLLIN, // Only listen for input events
                    ) {
                        warn!(
                            "vsock: [CID {}] failed to modify epoll registration for fd {}: {:?}",
                            self.thread_backend.guest_cid, fd, err
                        );

                        // If epoll_modify fails, try to unregister completely to prevent infinite loops
                        warn!(
                            "vsock: [CID {}] attempting to unregister fd {} completely due to epoll_modify failure",
                            self.thread_backend.guest_cid, fd
                        );

                        if let Err(unreg_err) = Self::epoll_unregister(self.get_epoll_fd(), fd) {
                            error!(
                                "vsock: [CID {}] failed to unregister fd {} from epoll: {:?} - this may cause infinite loops",
                                self.thread_backend.guest_cid, fd, unreg_err
                            );
                        } else {
                            info!(
                                "vsock: [CID {}] successfully unregistered fd {} from epoll as fallback",
                                self.thread_backend.guest_cid, fd
                            );
                            // Clean up the connection since we unregistered it
                            self.cleanup_unix_proxy_connection(fd, &key);
                            return;
                        }
                    } else {
                        info!(
                            "vsock: [CID {}] successfully modified epoll registration for fd {} to EPOLLIN only",
                            self.thread_backend.guest_cid, fd
                        );
                    }
                }

                // Catch-all for unexpected events
                if !evset.contains(epoll::Events::EPOLLIN)
                    && !evset.contains(epoll::Events::EPOLLOUT)
                    && !evset.contains(epoll::Events::EPOLLHUP)
                {
                    warn!(
                        "vsock: [CID {}] unexpected event on Unix socket proxy fd {}: {:?}",
                        self.thread_backend.guest_cid, fd, evset
                    );
                }
            } else {
                // Connection not found in conn_map - this shouldn't happen after proper cleanup
                warn!(
                    "vsock: [CID {}] received event for fd {} but connection not found in conn_map - cleaning up stale listener",
                    self.thread_backend.guest_cid, fd
                );
                warn!(
                    "vsock: [CID {}] DEBUG: evset was {:?}, this might be causing the infinite loop",
                    self.thread_backend.guest_cid, evset
                );

                // Remove stale listener entry and unregister from epoll
                self.thread_backend.listener_map.remove(&fd);
                if let Err(err) = Self::epoll_unregister(self.get_epoll_fd(), fd) {
                    warn!(
                        "vsock: [CID {}] failed to unregister stale fd {} from epoll: {:?}",
                        self.thread_backend.guest_cid, fd, err
                    );
                }
            }
        } else {
            // Check if the stream represented by fd has already established a
            // connection with the application running in the guest
            if let std::collections::hash_map::Entry::Vacant(_) =
                self.thread_backend.listener_map.entry(fd)
            {
                // Check if this is a stale fd that's still registered in epoll
                // but not in our tracking maps - this can cause infinite loops
                if evset.contains(epoll::Events::EPOLLOUT)
                    || evset.contains(epoll::Events::EPOLLHUP)
                {
                    warn!(
                        "vsock: [CID {}] received event {:?} for untracked fd {} - unregistering from epoll to prevent infinite loop",
                        self.thread_backend.guest_cid, evset, fd
                    );

                    // Unregister the stale fd from epoll
                    if let Err(err) = Self::epoll_unregister(self.get_epoll_fd(), fd) {
                        warn!(
                            "vsock: [CID {}] failed to unregister stale fd {} from epoll: {:?}",
                            self.thread_backend.guest_cid, fd, err
                        );
                    } else {
                        info!(
                            "vsock: [CID {}] successfully unregistered stale fd {} from epoll",
                            self.thread_backend.guest_cid, fd
                        );
                    }
                    return;
                }

                // New connection from the host
                if evset.bits() != epoll::Events::EPOLLIN.bits() {
                    // Has to be EPOLLIN as it was not connected previously
                    warn!(
                        "vsock: [CID {}] unexpected event {:?} for new connection fd {} - ignoring",
                        self.thread_backend.guest_cid, evset, fd
                    );
                    return;
                }
                let mut stream = match self.thread_backend.stream_map.remove(&fd) {
                    Some(s) => s,
                    None => {
                        warn!("Error while searching fd in the stream map");
                        return;
                    }
                };

                match stream {
                    #[cfg(feature = "backend_vsock")]
                    StreamType::Vsock(_) => {
                        error!("Stream type should not be of type vsock");
                    }
                    StreamType::Unix(ref mut unix_stream) => {
                        // Local peer is sending a "connect PORT\n" command
                        let peer_port = match Self::read_local_stream_port(unix_stream) {
                            Ok(port) => port,
                            Err(err) => {
                                warn!("Error while parsing \"connect PORT\n\" command: {err:?}");
                                return;
                            }
                        };

                        // Allocate a local port number
                        let local_port = match self.allocate_local_port() {
                            Ok(lp) => lp,
                            Err(err) => {
                                warn!("Error while allocating local port: {err:?}");
                                return;
                            }
                        };

                        self.add_new_connection_from_host(fd, stream, local_port, peer_port);

                        // Re-register the fd to listen for EPOLLIN and EPOLLOUT events
                        Self::epoll_modify(
                            self.get_epoll_fd(),
                            fd,
                            epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                        )
                        .unwrap();
                    }
                }
            } else {
                // Previously connected connection

                // Get epoll fd before getting conn as that takes self mut ref
                let epoll_fd = self.get_epoll_fd();
                let key = self.thread_backend.listener_map.get(&fd).unwrap();
                let conn = self.thread_backend.conn_map.get_mut(key).unwrap();

                if evset.bits() == epoll::Events::EPOLLOUT.bits() {
                    // Flush any remaining data from the tx buffer
                    match conn.tx_buf.flush_to(&mut conn.stream) {
                        Ok(cnt) => {
                            if cnt > 0 {
                                conn.fwd_cnt += Wrapping(cnt as u32);
                                conn.rx_queue.enqueue(RxOps::CreditUpdate);
                            } else {
                                // If no remaining data to flush, try to disable EPOLLOUT
                                if let Err(err) =
                                    Self::epoll_modify(epoll_fd, fd, epoll::Events::EPOLLIN)
                                {
                                    error!(
                                        "vsock: [CID {}] failed to disable EPOLLOUT for fd {}: {:?}",
                                        self.thread_backend.guest_cid, fd, err
                                    );

                                    // As a fallback, try to unregister completely to prevent infinite loops
                                    warn!(
                                        "vsock: [CID {}] attempting to unregister fd {} completely due to epoll_modify failure",
                                        self.thread_backend.guest_cid, fd
                                    );

                                    if let Err(unreg_err) = Self::epoll_unregister(epoll_fd, fd) {
                                        error!(
                                            "vsock: [CID {}] failed to unregister fd {} from epoll: {:?} - this may cause infinite loops",
                                            self.thread_backend.guest_cid, fd, unreg_err
                                        );
                                    } else {
                                        info!(
                                            "vsock: [CID {}] successfully unregistered fd {} from epoll as fallback",
                                            self.thread_backend.guest_cid, fd
                                        );

                                        // Clean up the connection since we unregistered it
                                        let key = key.clone();
                                        let conn =
                                            self.thread_backend.conn_map.remove(&key).unwrap();
                                        self.thread_backend.listener_map.remove(&fd);
                                        self.thread_backend.stream_map.remove(&fd);
                                        self.thread_backend.local_port_set.remove(&conn.local_port);
                                        return;
                                    }
                                } else {
                                    info!(
                                        "vsock: [CID {}] successfully disabled EPOLLOUT for fd {}",
                                        self.thread_backend.guest_cid, fd
                                    );
                                }
                            }
                            self.thread_backend
                                .backend_rxq
                                .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
                        }
                        Err(e) => {
                            error!(
                                "vsock: [CID {}] error flushing tx buffer for fd {}: {:?}",
                                self.thread_backend.guest_cid, fd, e
                            );
                        }
                    }
                    return;
                }

                // Unregister stream from the epoll, register when connection is
                // established with the guest
                Self::epoll_unregister(self.epoll_file.as_raw_fd(), fd).unwrap();

                // Enqueue a read request
                conn.rx_queue.enqueue(RxOps::Rw);
                self.thread_backend
                    .backend_rxq
                    .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
            }
        }

        info!(
            "vsock: [CID {}] DEBUG: handle_event for fd {} completed",
            self.thread_backend.guest_cid, fd
        );
    }

    fn add_new_connection_from_host(
        &mut self,
        fd: RawFd,
        stream: StreamType,
        local_port: u32,
        peer_port: u32,
    ) {
        info!(
            "vsock: [CID {}] add_new_connection_from_host: fd={}, local_port={}, peer_port={}",
            self.thread_backend.guest_cid, fd, local_port, peer_port
        );

        // Insert the fd into the backend's maps
        self.thread_backend
            .listener_map
            .insert(fd, ConnMapKey::new(local_port, peer_port));

        // Create a new connection object an enqueue a connection request
        // packet to be sent to the guest
        let conn_map_key = ConnMapKey::new(local_port, peer_port);
        let mut new_conn = VsockConnection::new_local_init(
            stream,
            VSOCK_HOST_CID,
            local_port,
            self.guest_cid,
            peer_port,
            self.get_epoll_fd(),
            self.tx_buffer_size,
        );
        new_conn.rx_queue.enqueue(RxOps::Request);
        new_conn.set_peer_port(peer_port);

        info!(
            "vsock: [CID {}] connection created with key {:?}, enqueuing connection request",
            self.thread_backend.guest_cid, conn_map_key
        );

        // Add connection object into the backend's maps
        self.thread_backend.conn_map.insert(conn_map_key, new_conn);

        self.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(local_port, peer_port));

        info!(
            "vsock: [CID {}] connection added to maps and queued for processing",
            self.thread_backend.guest_cid
        );
    }

    /// Allocate a new local port number.
    fn allocate_local_port(&mut self) -> Result<u32> {
        // TODO: Improve space efficiency of this operation
        // TODO: Reuse the conn_map HashMap
        // TODO: Test this.
        let mut alloc_local_port = self.local_port.0;
        loop {
            if !self
                .thread_backend
                .local_port_set
                .contains(&alloc_local_port)
            {
                // The port set doesn't contain the newly allocated port number.
                self.local_port = Wrapping(alloc_local_port + 1);
                self.thread_backend.local_port_set.insert(alloc_local_port);
                return Ok(alloc_local_port);
            } else {
                if alloc_local_port == self.local_port.0 {
                    // We have exhausted our search and wrapped back to the current port number
                    return Err(Error::NoFreeLocalPort);
                }
                alloc_local_port += 1;
            }
        }
    }

    /// Read `CONNECT PORT_NUM\n` from the connected stream.
    fn read_local_stream_port(stream: &mut UnixStream) -> Result<u32> {
        let mut buf = Vec::new();
        let mut reader = BufReader::new(stream);

        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(Error::UnixRead)?;

        let mut word_iter = std::str::from_utf8(&buf[..n])
            .map_err(Error::ConvertFromUtf8)?
            .split_whitespace();

        word_iter
            .next()
            .ok_or(Error::InvalidPortRequest)
            .and_then(|word| {
                if word.to_lowercase() == "connect" {
                    Ok(())
                } else {
                    Err(Error::InvalidPortRequest)
                }
            })
            .and_then(|_| word_iter.next().ok_or(Error::InvalidPortRequest))
            .and_then(|word| word.parse::<u32>().map_err(Error::ParseInteger))
            .map_err(|e| Error::ReadStreamPort(Box::new(e)))
    }

    /// Add a stream to epoll to listen for EPOLLIN events.
    fn add_stream_listener(&mut self, stream: UnixStream) -> Result<()> {
        let stream_fd = stream.as_raw_fd();
        self.thread_backend
            .stream_map
            .insert(stream_fd, StreamType::Unix(stream));
        VhostUserVsockThread::epoll_register(
            self.get_epoll_fd(),
            stream_fd,
            epoll::Events::EPOLLIN,
        )?;

        Ok(())
    }

    /// Iterate over the rx queue and process rx requests.
    fn process_rx_queue(&mut self, vring: &VringRwLock, rx_queue_type: RxQueueType) -> Result<()> {
        info!(
            "vsock: [CID {}] process_rx_queue called for {:?}",
            self.thread_backend.guest_cid, rx_queue_type
        );

        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => {
                info!(
                    "vsock: [CID {}] ERROR: No memory configured for {:?}",
                    self.thread_backend.guest_cid, rx_queue_type
                );
                return Err(Error::NoMemoryConfigured);
            }
        };

        info!(
            "vsock: [CID {}] getting vring mutex for {:?}",
            self.thread_backend.guest_cid, rx_queue_type
        );

        let mut vring_mut = vring.get_mut();

        info!(
            "vsock: [CID {}] getting queue for {:?}",
            self.thread_backend.guest_cid, rx_queue_type
        );

        let queue = vring_mut.get_queue_mut();

        info!(
            "vsock: [CID {}] checking for available descriptors in {:?} queue",
            self.thread_backend.guest_cid, rx_queue_type
        );

        let mut desc_count = 0;
        let mut queue_iter = match queue.iter(atomic_mem.memory()) {
            Ok(iter) => iter,
            Err(e) => {
                info!(
                    "vsock: [CID {}] ERROR: Failed to create queue iterator for {:?}: {:?}",
                    self.thread_backend.guest_cid, rx_queue_type, e
                );
                return Err(Error::IterateQueue);
            }
        };

        info!(
            "vsock: [CID {}] created queue iterator, checking for descriptors",
            self.thread_backend.guest_cid
        );

        while let Some(mut avail_desc) = queue_iter.next() {
            desc_count += 1;
            if desc_count == 1 {
                info!(
                    "vsock: [CID {}] found available descriptor in rx queue for {:?}",
                    self.thread_backend.guest_cid, rx_queue_type
                );
            }

            // Log descriptor details
            info!(
                "vsock: [CID {}] processing descriptor #{} - head_idx={}",
                self.thread_backend.guest_cid,
                desc_count,
                avail_desc.head_index()
            );

            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let used_len = match VsockPacket::from_rx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(mut pkt) => {
                    // Log the packet buffer size
                    let pkt_buf_size = if let Some(buf) = pkt.data_slice() {
                        buf.len()
                    } else {
                        0
                    };

                    info!(
                        "vsock: [CID {}] created packet from descriptor - buffer_size={}, tx_buffer_size={}",
                        self.thread_backend.guest_cid, pkt_buf_size, self.tx_buffer_size
                    );

                    let recv_result = match rx_queue_type {
                        RxQueueType::Standard => {
                            info!(
                                "vsock: [CID {}] calling recv_pkt for standard queue, backend_rxq size: {}",
                                self.thread_backend.guest_cid, self.thread_backend.backend_rxq.len()
                            );
                            self.thread_backend.recv_pkt(&mut pkt)
                        }
                        RxQueueType::RawPkts => {
                            info!(
                                "vsock: [CID {}] processing raw packet from sibling VM",
                                self.thread_backend.guest_cid
                            );
                            let result = self.thread_backend.recv_raw_pkt(&mut pkt);
                            if let Err(ref e) = result {
                                info!(
                                    "vsock: [CID {}] recv_raw_pkt returned error: {:?}",
                                    self.thread_backend.guest_cid, e
                                );
                            }
                            result
                        }
                    };

                    if recv_result.is_ok() {
                        let packet_len = pkt.len();
                        let packet_op = pkt.op();
                        let total_len = PKT_HEADER_SIZE + packet_len as usize;

                        info!(
                            "vsock: [CID {}] successfully processed packet - op:{}, data_len:{}, total_len:{}, will notify guest",
                            self.thread_backend.guest_cid, packet_op, packet_len, total_len
                        );

                        if rx_queue_type == RxQueueType::RawPkts {
                            info!(
                                "vsock: delivered raw pkt to guest - src_cid:{}, dst_cid:{}, op:{}, used_len:{}",
                                pkt.src_cid(), pkt.dst_cid(), pkt.op(), total_len
                            );
                        }
                        total_len
                    } else {
                        info!(
                            "vsock: [CID {}] recv_pkt returned error or no more packets - breaking from loop",
                            self.thread_backend.guest_cid
                        );
                        if rx_queue_type == RxQueueType::RawPkts {
                            info!("vsock: no more raw packets to process");
                        }
                        queue.iter(mem).unwrap().go_to_previous_position();
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "vsock: [CID {}] RX queue error creating packet from descriptor: {e:?}",
                        self.thread_backend.guest_cid
                    );
                    0
                }
            };

            // Send completion notification
            info!(
                "vsock: [CID {}] sending completion notification for descriptor head_idx={}, used_len={}",
                self.thread_backend.guest_cid, head_idx, used_len
            );

            let vring = vring.clone();
            let event_idx = self.event_idx;
            let send_result = self
                .sender
                .send(EventData {
                    vring,
                    event_idx,
                    head_idx,
                    used_len,
                })
                .map_err(|e| {
                    error!(
                        "vsock: [CID {}] CRITICAL: Failed to send completion notification: {:?}",
                        self.thread_backend.guest_cid, e
                    );
                    Error::NoMemoryConfigured
                });

            match send_result {
                Ok(()) => {
                    info!(
                        "vsock: [CID {}] completion notification sent successfully - guest should now see the packet",
                        self.thread_backend.guest_cid
                    );
                }
                Err(e) => {
                    error!(
                        "vsock: [CID {}] ERROR: completion notification failed: {:?}",
                        self.thread_backend.guest_cid, e
                    );
                    return Err(e);
                }
            }

            match rx_queue_type {
                RxQueueType::Standard => {
                    let still_pending = self.thread_backend.pending_rx();
                    info!(
                        "vsock: [CID {}] checking if more standard packets pending: {}",
                        self.thread_backend.guest_cid, still_pending
                    );
                    if !still_pending {
                        break;
                    }
                }
                RxQueueType::RawPkts => {
                    if !self.thread_backend.pending_raw_pkts() {
                        break;
                    }
                }
            }
        }

        if desc_count == 0 {
            info!("vsock: [CID {}] WARNING: No available descriptors in rx queue for {:?} - guest may not be ready to receive packets", 
                self.thread_backend.guest_cid, rx_queue_type);
            if rx_queue_type == RxQueueType::RawPkts {
                info!("vsock: [CID {}] The guest VM needs to have the vsock driver loaded and running to receive inter-VM packets", 
                    self.thread_backend.guest_cid);
            }
        } else {
            info!(
                "vsock: [CID {}] processed {} descriptors for {:?}",
                self.thread_backend.guest_cid, desc_count, rx_queue_type
            );
        }

        Ok(())
    }

    /// Wrapper to process rx queue based on whether event idx is enabled or
    /// not.
    fn process_unix_sockets(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                if !self.thread_backend.pending_rx() {
                    break;
                }
                vring.disable_notification().unwrap();

                self.process_rx_queue(vring, RxQueueType::Standard)?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring, RxQueueType::Standard)?;
        }
        Ok(())
    }

    /// Wrapper to process raw vsock packets queue based on whether event idx is
    /// enabled or not.
    /// Process raw packets in proxy mode (when there's no guest VM)
    pub fn process_raw_pkts_as_proxy(&mut self) -> Result<()> {
        info!(
            "vsock: [CID {}] processing raw packets in Unix socket proxy mode",
            self.thread_backend.guest_cid
        );

        while self.thread_backend.pending_raw_pkts() {
            // We don't need to create a packet, just pass a dummy one
            // The actual packet data will be read from the queue
            match self.thread_backend.recv_raw_pkt_proxy() {
                Ok(()) => {
                    info!(
                        "vsock: [CID {}] processed raw packet in proxy mode",
                        self.thread_backend.guest_cid
                    );
                }
                Err(e) => {
                    if !matches!(e, Error::EmptyRawPktsQueue) {
                        warn!(
                            "vsock: [CID {}] error processing raw packet in proxy mode: {:?}",
                            self.thread_backend.guest_cid, e
                        );
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn process_raw_pkts(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        let pending_count = self.thread_backend.raw_pkts_queue.read().unwrap().len();
        info!(
            "vsock: [CID {}] process_raw_pkts called, pending: {}, queue size: {}",
            self.thread_backend.guest_cid,
            self.thread_backend.pending_raw_pkts(),
            pending_count
        );

        if event_idx {
            loop {
                if !self.thread_backend.pending_raw_pkts() {
                    break;
                }
                vring.disable_notification().unwrap();

                self.process_rx_queue(vring, RxQueueType::RawPkts)?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring, RxQueueType::RawPkts)?;
        }
        Ok(())
    }

    pub fn process_rx(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        match self.last_processed {
            RxQueueType::Standard => {
                if self.thread_backend.pending_raw_pkts() {
                    self.process_raw_pkts(vring, event_idx)?;
                    self.last_processed = RxQueueType::RawPkts;
                }
                if self.thread_backend.pending_rx() {
                    self.process_unix_sockets(vring, event_idx)?;
                }
            }
            RxQueueType::RawPkts => {
                if self.thread_backend.pending_rx() {
                    self.process_unix_sockets(vring, event_idx)?;
                    self.last_processed = RxQueueType::Standard;
                }
                if self.thread_backend.pending_raw_pkts() {
                    self.process_raw_pkts(vring, event_idx)?;
                }
            }
        }
        Ok(())
    }

    /// Process tx queue and send requests to the backend for processing.
    fn process_tx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        info!(
            "vsock: [CID {}] process_tx_queue called - checking for TX packets from guest",
            self.thread_backend.guest_cid
        );

        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        let mut processed_count = 0;
        while let Some(mut avail_desc) = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            processed_count += 1;
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            info!(
                "vsock: [CID {}] processing TX descriptor #{} with head_idx={}",
                self.thread_backend.guest_cid, processed_count, head_idx
            );

            let pkt = match VsockPacket::from_tx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(pkt) => {
                    info!(
                        "vsock: [CID {}] successfully parsed TX packet #{} - src_cid:{}, src_port:{}, dst_cid:{}, dst_port:{}, op:{}, len:{}",
                        self.thread_backend.guest_cid, processed_count, pkt.src_cid(), pkt.src_port(), pkt.dst_cid(), pkt.dst_port(), pkt.op(), pkt.len()
                    );
                    pkt
                }
                Err(e) => {
                    warn!(
                        "vsock: [CID {}] error reading TX packet #{}: {:?}",
                        self.thread_backend.guest_cid, processed_count, e
                    );
                    continue;
                }
            };

            match self.thread_backend.send_pkt(&pkt) {
                Ok(()) => {
                    info!(
                        "vsock: [CID {}] successfully processed TX packet #{} via thread_backend.send_pkt",
                        self.thread_backend.guest_cid, processed_count
                    );
                }
                Err(e) => {
                    warn!(
                        "vsock: [CID {}] thread_backend.send_pkt failed for TX packet #{}: {:?}",
                        self.thread_backend.guest_cid, processed_count, e
                    );
                    vring
                        .get_mut()
                        .get_queue_mut()
                        .iter(mem)
                        .unwrap()
                        .go_to_previous_position();
                    break;
                }
            }

            // TODO: Check if the protocol requires read length to be correct
            let used_len = 0;

            let vring = vring.clone();
            let event_idx = self.event_idx;
            self.sender
                .send(EventData {
                    vring,
                    event_idx,
                    head_idx,
                    used_len,
                })
                .unwrap();
        }

        if processed_count == 0 {
            // Only log at debug level since this is normal - process_tx_queue gets called
            // multiple times and finding no descriptors after initial processing is expected
            info!(
                "vsock: [CID {}] process_tx_queue found no TX descriptors (normal after processing)",
                self.thread_backend.guest_cid
            );
        } else {
            info!(
                "vsock: [CID {}] process_tx_queue processed {} TX descriptors from guest",
                self.thread_backend.guest_cid, processed_count
            );
        }

        Ok(())
    }

    /// Wrapper to process tx queue based on whether event idx is enabled or
    /// not.
    pub fn process_tx(&mut self, vring_lock: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                vring_lock.disable_notification().unwrap();
                self.process_tx_queue(vring_lock)?;
                if !vring_lock.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_tx_queue(vring_lock)?;
        }
        Ok(())
    }

    /// Set up Unix socket to guest proxy using vhost-user protocol
    #[cfg(feature = "backend_vsock")]
    fn setup_unix_to_guest_proxy(
        &mut self,
        unix_stream: UnixStream,
        target_cid: u32,
        target_port: u32,
    ) -> Result<()> {
        info!(
            "vsock: [CID {}] setting up Unix socket to guest CID {} port {} proxy via vhost-user",
            self.guest_cid, target_cid, target_port
        );

        // Allocate a local port for this connection
        let local_port = match self.allocate_local_port() {
            Ok(port) => port,
            Err(err) => {
                warn!(
                    "vsock: [CID {}] failed to allocate local port: {:?}",
                    self.guest_cid, err
                );
                return Err(err);
            }
        };

        info!(
            "vsock: [CID {}] allocated local port {} for Unix socket proxy to CID {} port {}",
            self.guest_cid, local_port, target_cid, target_port
        );

        // Create a connection entry for this proxy connection
        let unix_fd = unix_stream.as_raw_fd();
        let key = ConnMapKey::new(local_port, target_port);

        // Create the connection object - this will be used to handle data forwarding
        // IMPORTANT: Use VSOCK_HOST_CID (2) as local_cid so the guest sees this as a host-initiated connection
        let conn = VsockConnection::new_local_init(
            StreamType::Unix(unix_stream.try_clone().map_err(Error::UnixConnect)?),
            crate::vhu_vsock::VSOCK_HOST_CID, // local CID (make it appear to come from host)
            local_port,                       // local port
            target_cid as u64,                // peer CID (guest)
            target_port,                      // peer port
            self.get_epoll_fd(),
            self.tx_buffer_size,
        );

        // Register the Unix socket with epoll
        Self::epoll_register(
            self.get_epoll_fd(),
            unix_fd,
            epoll::Events::EPOLLIN, // Only register for input events initially
        )?;

        // Store the connection in our maps
        self.thread_backend
            .stream_map
            .insert(unix_fd, StreamType::Unix(unix_stream));
        self.thread_backend
            .listener_map
            .insert(unix_fd, key.clone());
        self.thread_backend.conn_map.insert(key.clone(), conn);
        self.thread_backend.local_port_set.insert(local_port);

        // CRITICAL FIX: Set connect=true for UnixToVsock connections since they're already established
        // This prevents recv_pkt from sending VSOCK_OP_RST when processing RxOps::Rw
        if let Some(conn) = self.thread_backend.conn_map.get_mut(&key) {
            conn.connect = true;
        }

        info!(
            "vsock: [CID {}] Unix socket proxy setup complete - Unix fd {} mapped to guest CID {} port {} via local port {}",
            self.guest_cid, unix_fd, target_cid, target_port, local_port
        );

        // Send connection request to guest via vhost-user protocol
        self.send_connection_request_to_guest(target_cid, target_port, local_port)?;

        Ok(())
    }

    /// Send a connection request packet to the guest via vhost-user protocol
    #[cfg(feature = "backend_vsock")]
    fn send_connection_request_to_guest(
        &mut self,
        dst_cid: u32,
        dst_port: u32,
        src_port: u32,
    ) -> Result<()> {
        info!(
            "vsock: [CID {}] sending connection request to guest CID {} port {} from local port {}",
            self.guest_cid, dst_cid, dst_port, src_port
        );

        // For Unix socket forwarding, we need to queue a connection request
        // The connection will be established when the guest responds with an ACK
        let key = ConnMapKey::new(src_port, dst_port);
        if let Some(conn) = self.thread_backend.conn_map.get_mut(&key) {
            // Enqueue a request operation for this connection
            conn.rx_queue.enqueue(crate::rxops::RxOps::Request);

            // Add to backend RX queue so it gets processed
            self.thread_backend.backend_rxq.push_back(key);

            info!(
                "vsock: [CID {}] connection request queued for guest CID {} port {}",
                self.guest_cid, dst_cid, dst_port
            );
        } else {
            warn!(
                "vsock: [CID {}] connection not found for sending request",
                self.guest_cid
            );
            return Err(Error::PktBufMissing);
        }

        Ok(())
    }

    /// Clean up a Unix socket proxy connection.
    fn cleanup_unix_proxy_connection(&mut self, fd: RawFd, key: &ConnMapKey) {
        info!(
            "vsock: [CID {}] Cleaning up Unix socket proxy connection for key {:?}",
            self.thread_backend.guest_cid, key
        );

        // Unregister the Unix socket from epoll
        if let Err(err) = Self::epoll_unregister(self.get_epoll_fd(), fd) {
            warn!(
                "vsock: [CID {}] Failed to unregister fd {} from epoll: {:?}",
                self.thread_backend.guest_cid, fd, err
            );
        }

        // Remove the connection from our maps
        self.thread_backend.stream_map.remove(&fd);
        self.thread_backend.listener_map.remove(&fd);
        self.thread_backend.conn_map.remove(key);
        self.thread_backend.local_port_set.remove(&key.local_port());

        info!(
            "vsock: [CID {}] Unix socket proxy connection for key {:?} cleaned up",
            self.thread_backend.guest_cid, key
        );
    }
}

impl Drop for VhostUserVsockThread {
    fn drop(&mut self) {
        match &self.backend_info {
            BackendType::UnixDomainSocket(uds_path) => {
                let _ = std::fs::remove_file(uds_path);
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::UnixToVsock(_uds_path, _vsock_info) => {
                // Nothing to do
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::Vsock(_) => {
                // Nothing to do
            }
        }
        self.thread_backend
            .cid_map
            .write()
            .unwrap()
            .remove(&self.guest_cid);
    }
}
#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::{Read, Write},
        path::PathBuf,
    };

    use tempfile::tempdir;
    use vm_memory::GuestAddress;
    use vmm_sys_util::eventfd::EventFd;
    #[cfg(feature = "backend_vsock")]
    use vsock::{VsockStream, VMADDR_CID_LOCAL};

    use super::*;
    #[cfg(feature = "backend_vsock")]
    use crate::vhu_vsock::VsockProxyInfo;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

    impl VhostUserVsockThread {
        fn get_epoll_file(&self) -> &File {
            &self.epoll_file
        }
    }

    fn test_vsock_thread(backend_info: BackendType) {
        let groups: Vec<String> = vec![String::from("default")];

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let t = VhostUserVsockThread::new(backend_info, 3, CONN_TX_BUF_SIZE, groups, cid_map);
        assert!(t.is_ok());

        let mut t = t.unwrap();
        let epoll_fd = t.get_epoll_file().as_raw_fd();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let dummy_fd = EventFd::new(0).unwrap();

        assert!(VhostUserVsockThread::epoll_register(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLOUT
        )
        .is_ok());
        assert!(VhostUserVsockThread::epoll_modify(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLIN
        )
        .is_ok());
        assert!(VhostUserVsockThread::epoll_unregister(epoll_fd, dummy_fd.as_raw_fd()).is_ok());
        assert!(VhostUserVsockThread::epoll_register(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLIN
        )
        .is_ok());

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        assert!(t.process_tx(&vring, false).is_ok());
        assert!(t.process_tx(&vring, true).is_ok());
        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        assert!(t.process_rx(&vring, false).is_ok());
        assert!(t.process_rx(&vring, true).is_ok());
        assert!(t.process_raw_pkts(&vring, false).is_ok());
        assert!(t.process_raw_pkts(&vring, true).is_ok());

        VhostUserVsockThread::vring_handle_event(EventData {
            vring: vring.clone(),
            event_idx: false,
            head_idx: 0,
            used_len: 0,
        });
        VhostUserVsockThread::vring_handle_event(EventData {
            vring,
            event_idx: true,
            head_idx: 0,
            used_len: 0,
        });

        dummy_fd.write(1).unwrap();

        t.process_backend_evt(EventSet::empty());
    }

    #[test]
    fn test_vsock_thread_unix() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let backend_info =
            BackendType::UnixDomainSocket(test_dir.path().join("test_vsock_thread.vsock"));
        test_vsock_thread(backend_info);
        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_thread_vsock() {
        let backend_info = BackendType::Vsock(VsockProxyInfo {
            forward_cid: 1,
            listen_ports: vec![],
        });
        test_vsock_thread(backend_info);
    }

    #[test]
    fn test_vsock_thread_failures() {
        let groups: Vec<String> = vec![String::from("default")];

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(PathBuf::from("/sys/not_allowed.vsock")),
            3,
            CONN_TX_BUF_SIZE,
            groups.clone(),
            cid_map.clone(),
        );
        assert!(t.is_err());

        let vsock_socket_path = test_dir.path().join("test_vsock_thread_failures.vsock");
        let mut t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_socket_path),
            3,
            CONN_TX_BUF_SIZE,
            groups.clone(),
            cid_map.clone(),
        )
        .unwrap();
        assert!(VhostUserVsockThread::epoll_register(-1, -1, epoll::Events::EPOLLIN).is_err());
        assert!(VhostUserVsockThread::epoll_modify(-1, -1, epoll::Events::EPOLLIN).is_err());
        assert!(VhostUserVsockThread::epoll_unregister(-1, -1).is_err());

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // memory is not configured, so processing TX should fail
        assert!(t.process_tx(&vring, false).is_err());
        assert!(t.process_tx(&vring, true).is_err());

        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        assert!(t.process_rx(&vring, false).is_err());
        assert!(t.process_rx(&vring, true).is_err());

        // trying to use a CID that is already in use should fail
        let vsock_socket_path2 = test_dir.path().join("test_vsock_thread_failures2.vsock");
        let t2 = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_socket_path2),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );
        assert!(t2.is_err());

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_thread_unix_backend() {
        let groups: Vec<String> = vec![String::from("default")];
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let vsock_path = test_dir.path().join("test_vsock_thread.vsock");

        let t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_path.clone()),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );

        let mut t = t.unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let mut uds = UnixStream::connect(vsock_path).unwrap();
        t.process_backend_evt(EventSet::empty());

        uds.write_all(b"CONNECT 1234\n").unwrap();
        t.process_backend_evt(EventSet::empty());

        // Write and read something from the Unix socket
        uds.write_all(b"some data").unwrap();

        let mut buf = vec![0u8; 16];
        uds.set_nonblocking(true).unwrap();
        // There isn't any peer responding, so we don't expect data
        uds.read(&mut buf).unwrap_err();

        t.process_backend_evt(EventSet::empty());

        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_thread_vsock_backend() {
        VsockListener::bind_with_cid_port(VMADDR_CID_LOCAL, libc::VMADDR_PORT_ANY).expect(
            "This test uses VMADDR_CID_LOCAL, so the vsock_loopback kernel module must be loaded",
        );

        let groups: Vec<String> = vec![String::from("default")];
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let t = VhostUserVsockThread::new(
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: VMADDR_CID_LOCAL,
                listen_ports: vec![9003, 9004],
            }),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );

        let mut t = t.unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let mut vs1 = VsockStream::connect_with_cid_port(VMADDR_CID_LOCAL, 9003).unwrap();
        let mut vs2 = VsockStream::connect_with_cid_port(VMADDR_CID_LOCAL, 9004).unwrap();
        t.process_backend_evt(EventSet::empty());

        vs1.write_all(b"some data").unwrap();
        vs2.write_all(b"some data").unwrap();
        t.process_backend_evt(EventSet::empty());

        let mut buf = vec![0u8; 16];
        vs1.set_nonblocking(true).unwrap();
        vs2.set_nonblocking(true).unwrap();
        // There isn't any peer responding, so we don't expect data
        vs1.read(&mut buf).unwrap_err();
        vs2.read(&mut buf).unwrap_err();

        t.process_backend_evt(EventSet::empty());
    }

    #[test]
    fn test_unix_socket_eof_after_ok_response() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::thread;
        use std::time::Duration;

        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let uds_path = test_dir.path().join("test_eof.socket");

        // Create VhostUserVsockThread with Unix socket backend
        let backend_info = BackendType::UnixDomainSocket(uds_path.clone());
        let groups: Vec<String> = vec![String::from("default")];
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let mut thread =
            VhostUserVsockThread::new(backend_info, 4, CONN_TX_BUF_SIZE, groups, cid_map)
                .expect("Failed to create VhostUserVsockThread");

        // Set up guest memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        thread.mem = Some(mem.clone());

        // Start the thread in background
        let thread_handle = thread::spawn(move || {
            // In a real scenario, this would be run by the vhost-user framework
            // For testing, we'll just set up the listener part
            thread.backend_info = BackendType::UnixDomainSocket(uds_path);
        });

        // Give the server a moment to start
        thread::sleep(Duration::from_millis(100));

        // Test client that mimics the Rust client behavior
        let client_result = thread::spawn(
            move || -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
                // Connect to Unix socket
                let mut stream = UnixStream::connect(&uds_path)?;

                // Send request (mimicking the 9 bytes we see in logs)
                let request = b"\x01\x00\x00\x00\x00\x00\x00\x00\x01";
                stream.write_all(request)?;

                // Read response until EOF (this is what the Rust client does)
                let mut response = Vec::new();
                stream.read_to_end(&mut response)?;

                Ok(String::from_utf8_lossy(&response).to_string())
            },
        )
        .join();

        // Verify the result
        match client_result {
            Ok(Ok(response)) => {
                assert_eq!(response, "OK 3\n", "Expected 'OK 3\\n' response");
                println!("✅ SUCCESS: Got expected 'OK 3\\n' response with proper EOF");
            }
            Ok(Err(e)) => {
                panic!("❌ Client error: {}", e);
            }
            Err(_) => {
                panic!("❌ Thread join error");
            }
        }

        // Clean up
        if let Ok(handle) = thread_handle.join() {
            // Thread completed
        }

        test_dir.close().unwrap();
    }
}
