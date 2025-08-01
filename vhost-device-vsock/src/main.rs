// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod rxops;
mod rxqueue;
mod thread_backend;
mod txbuf;
mod vhu_vsock;
mod vhu_vsock_thread;
mod vsock_conn;

use std::{
    any::Any,
    collections::HashMap,
    convert::TryFrom,
    path::PathBuf,
    process::exit,
    sync::{Arc, RwLock},
    thread,
};

use clap::{Args, Parser};
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use log::error;
use serde::Deserialize;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

#[cfg(feature = "backend_vsock")]
use crate::vhu_vsock::{BackendType, VhostUserVsockBackend};
#[cfg(feature = "backend_vsock")]
use crate::vhu_vsock::{UnixToVsockInfo, VsockProxyInfo};
use crate::vhu_vsock::{CidMap, VsockConfig};

const DEFAULT_GUEST_CID: u64 = 3;
const DEFAULT_TX_BUFFER_SIZE: u32 = 64 * 1024;
const DEFAULT_QUEUE_SIZE: usize = 1024;
const DEFAULT_GROUP_NAME: &str = "default";

#[derive(Debug, ThisError)]
enum CliError {
    #[error("No arguments provided")]
    NoArgsProvided,
    #[error("Failed to parse configuration file")]
    ConfigParse,
}

#[derive(Debug, ThisError)]
enum VmArgsParseError {
    #[error("Bad argument")]
    BadArgument,
    #[error("Invalid key `{0}`")]
    InvalidKey(String),
    #[error("Unable to convert string to integer: {0}")]
    ParseInteger(std::num::ParseIntError),
    #[error("Required key `{0}` not found")]
    RequiredKeyNotFound(String),
}

#[derive(Debug, ThisError)]
enum BackendError {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_vsock::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
    #[error("Thread `{0}` panicked")]
    ThreadPanic(String, Box<dyn Any + Send>),
}

#[derive(Args, Clone, Debug)]
struct VsockParam {
    /// Context identifier of the guest which uniquely identifies the device for
    /// its lifetime.
    #[arg(
        long,
        default_value_t = DEFAULT_GUEST_CID,
        conflicts_with = "config",
        conflicts_with = "vm"
    )]
    guest_cid: u64,

    /// Unix socket to which a hypervisor connects to and sets up the control
    /// path with the device.
    #[arg(long, conflicts_with = "config", conflicts_with = "vm")]
    socket: PathBuf,

    /// Unix socket to which a host-side application connects to.
    #[cfg(not(feature = "backend_vsock"))]
    #[arg(long, conflicts_with = "config", conflicts_with = "vm")]
    uds_path: Option<PathBuf>,

    /// Unix socket to which a host-side application connects to.
    #[cfg(feature = "backend_vsock")]
    #[arg(
        long,
        conflicts_with = "forward_cid",
        conflicts_with = "forward_listen",
        conflicts_with = "uds_forward_cid",
        conflicts_with = "uds_forward_port",
        conflicts_with = "config",
        conflicts_with = "vm"
    )]
    uds_path: Option<PathBuf>,

    /// Unix socket path that forwards connections to a specific vsock CID
    #[cfg(feature = "backend_vsock")]
    #[arg(
        long,
        conflicts_with = "forward_cid",
        conflicts_with = "forward_listen", 
        conflicts_with = "uds_path",
        conflicts_with = "config",
        conflicts_with = "vm"
    )]
    uds_forward_path: Option<PathBuf>,
    
    /// The vsock CID to forward Unix socket connections to
    #[cfg(feature = "backend_vsock")]
    #[arg(
        long,
        conflicts_with = "forward_cid",
        conflicts_with = "forward_listen",
        conflicts_with = "uds_path", 
        conflicts_with = "config",
        conflicts_with = "vm",
        requires = "uds_forward_path"
    )]
    uds_forward_cid: Option<u32>,

    /// The vsock port to forward Unix socket connections to
    #[cfg(feature = "backend_vsock")]
    #[arg(
        long,
        conflicts_with = "forward_cid",
        conflicts_with = "forward_listen",
        conflicts_with = "uds_path",
        conflicts_with = "config", 
        conflicts_with = "vm",
        requires = "uds_forward_path"
    )]
    uds_forward_port: Option<u32>,

    /// The vsock CID to forward connections from guest
    #[cfg(feature = "backend_vsock")]
    #[clap(
        long,
        conflicts_with = "uds_path",
        conflicts_with = "uds_forward_path",
        conflicts_with = "config",
        conflicts_with = "vm"
    )]
    forward_cid: Option<u32>,

    /// The vsock ports to forward connections from host
    #[cfg(feature = "backend_vsock")]
    #[clap(
        long,
        conflicts_with = "uds_path",
        conflicts_with = "config",
        conflicts_with = "vm"
    )]
    forward_listen: Option<String>,

    /// The size of the buffer used for the TX virtqueue
    #[clap(long, default_value_t = DEFAULT_TX_BUFFER_SIZE, conflicts_with = "config", conflicts_with = "vm")]
    tx_buffer_size: u32,

    /// The size of the vring queue
    #[clap(long, default_value_t = DEFAULT_QUEUE_SIZE, conflicts_with = "config", conflicts_with = "vm")]
    queue_size: usize,

    /// The list of group names to which the device belongs.
    /// A group is a set of devices that allow sibling communication between
    /// their guests.
    #[arg(
        long,
        default_value_t = String::from(DEFAULT_GROUP_NAME),
        conflicts_with = "config",
        conflicts_with = "vm",
        verbatim_doc_comment
    )]
    groups: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ConfigFileVsockParam {
    guest_cid: Option<u64>,
    socket: PathBuf,
    uds_path: Option<PathBuf>,
    #[cfg(feature = "backend_vsock")]
    forward_cid: Option<u32>,
    #[cfg(feature = "backend_vsock")]
    forward_listen: Option<String>,
    tx_buffer_size: Option<u32>,
    queue_size: Option<usize>,
    groups: Option<String>,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct VsockArgs {
    #[command(flatten)]
    param: Option<VsockParam>,

    /// Device parameters corresponding to a VM in the form of comma separated
    /// key=value pairs.
    ///
    /// The allowed keys are: guest_cid, socket, uds_path, tx_buffer_size,
    /// queue_size and group.
    ///
    /// Example:
    ///   --vm guest-cid=3,socket=/tmp/vhost3.socket,uds-path=/tmp/vm3.vsock,
    /// tx-buffer-size=65536,queue-size=1024,groups=group1+group2
    ///
    /// Multiple instances of this argument can be provided to configure devices
    /// for multiple guests.
    #[cfg(not(feature = "backend_vsock"))]
    #[arg(long, conflicts_with = "config", verbatim_doc_comment, value_parser = parse_vm_params)]
    vm: Option<Vec<VsockConfig>>,

    /// Device parameters corresponding to a VM in the form of comma separated
    /// key=value pairs.
    ///
    /// The allowed keys are: guest_cid, socket, uds_path, forward_cid,
    /// forward_listen, tx_buffer_size, queue_size and group. uds_path and
    /// (forward_cid, forward_listen) are mutually exclusive. Use uds_path when
    /// you want unix domain socket backend, otherwise forward_cid,
    /// forward_listen for vsock backend.
    ///
    /// Example:
    ///   --vm guest-cid=3,socket=/tmp/vhost3.socket,uds-path=/tmp/vm3.vsock,
    /// tx-buffer-size=65536,queue-size=1024,groups=group1+group2
    ///   --vm guest-cid=3,socket=/tmp/vhost3.socket,forward-cid=1,
    /// forward-listen=9001,queue-size=1024
    ///
    /// Multiple instances of this argument can be provided to configure devices
    /// for multiple guests.
    #[cfg(feature = "backend_vsock")]
    #[arg(long, conflicts_with = "config", verbatim_doc_comment, value_parser = parse_vm_params)]
    vm: Option<Vec<VsockConfig>>,

    /// Load from a given configuration file
    #[arg(long)]
    config: Option<String>,
}

fn parse_vm_params(s: &str) -> Result<VsockConfig, VmArgsParseError> {
    let mut guest_cid = None;
    let mut socket = None;
    let mut uds_path = None;
    let mut tx_buffer_size = None;
    let mut queue_size = None;
    let mut groups = None;

    #[cfg(feature = "backend_vsock")]
    let mut forward_cid = None;
    #[cfg(feature = "backend_vsock")]
    let mut forward_listen: Option<Vec<u32>> = None;

    #[cfg(feature = "backend_vsock")]
    let mut uds_forward_path = None;
    #[cfg(feature = "backend_vsock")]
    let mut uds_forward_cid = None;
    #[cfg(feature = "backend_vsock")]
    let mut uds_forward_port: Option<u32> = None;

    for arg in s.trim().split(',') {
        let mut parts = arg.split('=');
        let key = parts.next().ok_or(VmArgsParseError::BadArgument)?;
        let val = parts.next().ok_or(VmArgsParseError::BadArgument)?;

        match key {
            "guest_cid" | "guest-cid" => {
                guest_cid = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            "socket" => socket = Some(PathBuf::from(val)),
            "uds_path" | "uds-path" => uds_path = Some(PathBuf::from(val)),

            #[cfg(feature = "backend_vsock")]
            "uds_forward_path" | "uds-forward-path" => {
                uds_forward_path = Some(PathBuf::from(val));
            }
            #[cfg(feature = "backend_vsock")]
            "uds_forward_cid" | "uds-forward-cid" => {
                uds_forward_cid = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            #[cfg(feature = "backend_vsock")]
            "uds_forward_port" | "uds-forward-port" => {
                uds_forward_port = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }

            #[cfg(feature = "backend_vsock")]
            "forward_cid" | "forward-cid" => {
                forward_cid = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            #[cfg(feature = "backend_vsock")]
            "forward_listen" | "forward-listen" => {
                forward_listen = Some(val.split('+').map(|s| s.parse().unwrap()).collect())
            }

            "tx_buffer_size" | "tx-buffer-size" => {
                tx_buffer_size = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            "queue_size" | "queue-size" => {
                queue_size = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            "groups" => groups = Some(val.split('+').map(String::from).collect()),
            _ => return Err(VmArgsParseError::InvalidKey(key.to_string())),
        }
    }

    #[cfg(feature = "backend_vsock")]
    let backend_info = match (uds_path, uds_forward_path, uds_forward_cid, uds_forward_port, forward_cid) {
        (Some(path), None, None, None, None) => BackendType::UnixDomainSocket(path),
        (None, Some(path), Some(cid), Some(port), None) => {
            BackendType::UnixToVsock(path, UnixToVsockInfo {
                target_cid: cid,
                target_port: port,
            })
        }
        (None, None, None, None, Some(cid)) => {
            let listen_ports: Vec<u32> = forward_listen.unwrap_or_default();
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: cid,
                listen_ports,
            })
        }
        _ => {
            return Err(VmArgsParseError::RequiredKeyNotFound(
                "Must specify one of: uds-path, uds-forward-path+uds-forward-cid+uds-forward-port, or forward-cid".to_string(),
            ))
        }
    };

    #[cfg(not(feature = "backend_vsock"))]
    let backend_info = match uds_path {
        Some(path) => BackendType::UnixDomainSocket(path),
        _ => {
            return Err(VmArgsParseError::RequiredKeyNotFound(
                "uds-path".to_string(),
            ))
        }
    };

    Ok(VsockConfig::new(
        guest_cid.unwrap_or(DEFAULT_GUEST_CID),
        socket.ok_or_else(|| VmArgsParseError::RequiredKeyNotFound("socket".to_string()))?,
        backend_info.clone(),
        tx_buffer_size.unwrap_or(DEFAULT_TX_BUFFER_SIZE),
        queue_size.unwrap_or(DEFAULT_QUEUE_SIZE),
        groups.unwrap_or(vec![DEFAULT_GROUP_NAME.to_string()]),
    ))
}

impl VsockArgs {
    pub fn parse_config(&self) -> Option<Result<Vec<VsockConfig>, CliError>> {
        if let Some(c) = &self.config {
            let figment = Figment::new().merge(Yaml::file(c.as_str()));

            if let Ok(mut config_map) =
                figment.extract::<HashMap<String, Vec<ConfigFileVsockParam>>>()
            {
                let vms_param = config_map.get_mut("vms").unwrap();
                if !vms_param.is_empty() {
                    let mut parsed = Vec::new();
                    for p in vms_param.drain(..) {
                        #[cfg(feature = "backend_vsock")]
                        let backend_info = match (p.uds_path, p.forward_cid) {
                            (Some(path), None) => BackendType::UnixDomainSocket(path),
                            (None, Some(cid)) => {
                                let listen_ports: Vec<u32> = match p.forward_listen {
                                    None => Vec::new(),
                                    Some(ports) => {
                                        ports.split('+').map(|s| s.parse().unwrap()).collect()
                                    }
                                };
                                BackendType::Vsock(VsockProxyInfo {
                                    forward_cid: cid,
                                    listen_ports,
                                })
                            }
                            _ => return Some(Err(CliError::ConfigParse)),
                        };

                        #[cfg(not(feature = "backend_vsock"))]
                        let backend_info = match p.uds_path {
                            Some(path) => BackendType::UnixDomainSocket(path.trim().to_string()),
                            _ => return Some(Err(CliError::ConfigParse)),
                        };

                        let config = VsockConfig::new(
                            p.guest_cid.unwrap_or(DEFAULT_GUEST_CID),
                            p.socket,
                            backend_info,
                            p.tx_buffer_size.unwrap_or(DEFAULT_TX_BUFFER_SIZE),
                            p.queue_size.unwrap_or(DEFAULT_QUEUE_SIZE),
                            p.groups.map_or(vec![DEFAULT_GROUP_NAME.to_string()], |g| {
                                g.trim().split('+').map(String::from).collect()
                            }),
                        );
                        parsed.push(config);
                    }
                    return Some(Ok(parsed));
                } else {
                    return Some(Err(CliError::ConfigParse));
                }
            } else {
                return Some(Err(CliError::ConfigParse));
            }
        }
        None
    }
}

impl TryFrom<VsockArgs> for Vec<VsockConfig> {
    type Error = CliError;

    fn try_from(cmd_args: VsockArgs) -> Result<Self, CliError> {
        // we try to use the configuration first, if failed,  then fall back to the
        // manual settings.
        match cmd_args.parse_config() {
            Some(c) => c,
            _ => match cmd_args.vm {
                Some(v) => Ok(v),
                _ => cmd_args.param.map_or(Err(CliError::NoArgsProvided), |p| {
                    #[cfg(feature = "backend_vsock")]
                    let backend_info = match (p.uds_path, p.forward_cid) {
                        (Some(path), None) => BackendType::UnixDomainSocket(path),
                        (None, Some(cid)) => {
                            let listen_ports: Vec<u32> = match p.forward_listen {
                                None => Vec::new(),
                                Some(ports) => {
                                    ports.split('+').map(|s| s.parse().unwrap()).collect()
                                }
                            };
                            BackendType::Vsock(VsockProxyInfo {
                                forward_cid: cid,
                                listen_ports,
                            })
                        }
                        _ => return Err(CliError::ConfigParse),
                    };

                    #[cfg(not(feature = "backend_vsock"))]
                    let backend_info = match p.uds_path {
                        Some(path) => BackendType::UnixDomainSocket(path.trim().to_string()),
                        _ => return Err(CliError::ConfigParse),
                    };

                    Ok(vec![VsockConfig::new(
                        p.guest_cid,
                        p.socket,
                        backend_info,
                        p.tx_buffer_size,
                        p.queue_size,
                        p.groups.trim().split('+').map(String::from).collect(),
                    )])
                }),
            },
        }
    }
}

/// This is the public API through which an external program starts the
/// vhost-device-vsock backend server.
pub(crate) fn start_backend_server(
    config: VsockConfig,
    cid_map: Arc<RwLock<CidMap>>,
) -> Result<(), BackendError> {
    loop {
        let backend = Arc::new(
            VhostUserVsockBackend::new(config.clone(), cid_map.clone())
                .map_err(BackendError::CouldNotCreateBackend)?,
        );

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(BackendError::CouldNotCreateDaemon)?;

        let mut epoll_handlers = daemon.get_epoll_handlers();

        for thread in backend.threads.iter() {
            thread
                .lock()
                .unwrap()
                .register_listeners(epoll_handlers.remove(0));
        }

        if let Err(e) = daemon
            .serve(config.get_socket_path())
            .map_err(BackendError::ServeFailed)
        {
            error!("{e}");
        }
    }
}

pub(crate) fn start_backend_servers(configs: &[VsockConfig]) -> Result<(), BackendError> {
    let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));
    let mut handles = HashMap::new();
    let (senders, receiver) = std::sync::mpsc::channel();

    for (thread_id, c) in configs.iter().enumerate() {
        let config = c.clone();
        let cid_map = cid_map.clone();
        let sender = senders.clone();
        let name = format!("vhu-vsock-cid-{}", c.get_guest_cid());
        let handle = thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(move || start_backend_server(config, cid_map));

                // Notify the main thread that we are done.
                sender.send(thread_id).unwrap();

                result.map_err(|e| BackendError::ThreadPanic(name, e))?
            })
            .unwrap();
        handles.insert(thread_id, handle);
    }

    while !handles.is_empty() {
        let thread_id = receiver.recv().unwrap();
        handles
            .remove(&thread_id)
            .unwrap()
            .join()
            .map_err(std::panic::resume_unwind)
            .unwrap()?;
    }

    Ok(())
}

fn main() {
    env_logger::init();

    let configs = match Vec::<VsockConfig>::try_from(VsockArgs::parse()) {
        Ok(c) => c,
        Err(e) => {
            println!("Error parsing arguments: {e}");
            return;
        }
    };

    if let Err(e) = start_backend_servers(&configs) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write, path::Path};

    use assert_matches::assert_matches;
    use tempfile::tempdir;

    use super::*;

    impl VsockArgs {
        fn from_args_unix(
            guest_cid: u64,
            socket: &Path,
            uds_path: &Path,
            tx_buffer_size: u32,
            queue_size: usize,
            groups: &str,
        ) -> Self {
            VsockArgs {
                param: Some(VsockParam {
                    guest_cid,
                    socket: socket.to_path_buf(),
                    uds_path: Some(uds_path.to_path_buf()),

                    #[cfg(feature = "backend_vsock")]
                    forward_cid: None,
                    #[cfg(feature = "backend_vsock")]
                    forward_listen: None,

                    #[cfg(feature = "backend_vsock")]
                    uds_forward_path: None,
                    #[cfg(feature = "backend_vsock")]
                    uds_forward_cid: None,
                    #[cfg(feature = "backend_vsock")]
                    uds_forward_port: None,

                    tx_buffer_size,
                    queue_size,
                    groups: groups.to_string(),
                }),
                vm: None,
                config: None,
            }
        }

        #[cfg(feature = "backend_vsock")]
        fn from_args_vsock(
            guest_cid: u64,
            socket: &Path,
            forward_cid: u32,
            forward_listen: &str,
            tx_buffer_size: u32,
            queue_size: usize,
            groups: &str,
        ) -> Self {
            VsockArgs {
                param: Some(VsockParam {
                    guest_cid,
                    socket: socket.to_path_buf(),
                    uds_path: None,
                    #[cfg(feature = "backend_vsock")]
                    uds_forward_path: None,
                    #[cfg(feature = "backend_vsock")]
                    uds_forward_cid: None,
                    #[cfg(feature = "backend_vsock")]
                    uds_forward_port: None,
                    forward_cid: Some(forward_cid),
                    forward_listen: Some(forward_listen.to_string()),
                    tx_buffer_size,
                    queue_size,
                    groups: groups.to_string(),
                }),
                vm: None,
                config: None,
            }
        }

        fn from_file(config: &str) -> Self {
            VsockArgs {
                param: None,
                vm: None,
                config: Some(config.to_string()),
            }
        }
    }

    #[test]
    fn test_vsock_config_setup_unix() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_path = test_dir.path().join("vhost4.socket");
        let uds_path = test_dir.path().join("vm4.vsock");
        let args = VsockArgs::from_args_unix(3, &socket_path, &uds_path, 64 * 1024, 1024, "group1");

        let configs = Vec::<VsockConfig>::try_from(args);
        assert!(configs.is_ok());

        let configs = configs.unwrap();
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(config.get_socket_path(), socket_path);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_path)
        );
        assert_eq!(config.get_tx_buffer_size(), 64 * 1024);
        assert_eq!(config.get_queue_size(), 1024);
        assert_eq!(config.get_groups(), vec!["group1".to_string()]);

        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_config_setup_vsock() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_path = test_dir.path().join("vhost4.socket");
        let args =
            VsockArgs::from_args_vsock(3, &socket_path, 1, "1234+4321", 64 * 1024, 1024, "group1");

        let configs = Vec::<VsockConfig>::try_from(args);
        assert!(configs.is_ok());

        let configs = configs.unwrap();
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(config.get_socket_path(), socket_path);
        assert_eq!(
            config.get_backend_info(),
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: 1,
                listen_ports: vec![1234, 4321]
            })
        );
        assert_eq!(config.get_tx_buffer_size(), 64 * 1024);
        assert_eq!(config.get_queue_size(), 1024);
        assert_eq!(config.get_groups(), vec!["group1".to_string()]);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_config_setup_from_vm_args_unix() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_paths = [
            test_dir.path().join("vhost3.socket"),
            test_dir.path().join("vhost4.socket"),
            test_dir.path().join("vhost5.socket"),
        ];
        let uds_paths = [
            test_dir.path().join("vm3.vsock"),
            test_dir.path().join("vm4.vsock"),
            test_dir.path().join("vm5.vsock"),
        ];
        let params = format!(
            "--vm socket={vhost3_socket},uds_path={vm3_vsock} \
             --vm socket={vhost4_socket},uds-path={vm4_vsock},guest-cid=4,tx_buffer_size=65536,queue_size=1024,groups=group1 \
             --vm groups=group2+group3,guest-cid=5,socket={vhost5_socket},uds_path={vm5_vsock},tx-buffer-size=32768,queue_size=256",
            vhost3_socket = socket_paths[0].display(),
            vhost4_socket = socket_paths[1].display(),
            vhost5_socket = socket_paths[2].display(),
            vm3_vsock = uds_paths[0].display(),
            vm4_vsock = uds_paths[1].display(),
            vm5_vsock = uds_paths[2].display(),
        );

        let mut params = params.split_whitespace().collect::<Vec<&str>>();
        params.insert(0, ""); // to make the test binary name agnostic

        let args = VsockArgs::parse_from(params);

        let configs = Vec::<VsockConfig>::try_from(args);
        assert!(configs.is_ok());

        let configs = configs.unwrap();
        assert_eq!(configs.len(), 3);

        let config = configs.first().unwrap();
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(config.get_socket_path(), socket_paths[0]);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_paths[0].clone())
        );
        assert_eq!(config.get_tx_buffer_size(), 65536);
        assert_eq!(config.get_queue_size(), 1024);
        assert_eq!(config.get_groups(), vec![DEFAULT_GROUP_NAME.to_string()]);

        let config = configs.get(1).unwrap();
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(config.get_socket_path(), socket_paths[1]);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_paths[1].clone())
        );
        assert_eq!(config.get_tx_buffer_size(), 65536);
        assert_eq!(config.get_queue_size(), 1024);
        assert_eq!(config.get_groups(), vec!["group1".to_string()]);

        let config = configs.get(2).unwrap();
        assert_eq!(config.get_guest_cid(), 5);
        assert_eq!(config.get_socket_path(), socket_paths[2]);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_paths[2].clone())
        );
        assert_eq!(config.get_tx_buffer_size(), 32768);
        assert_eq!(config.get_queue_size(), 256);
        assert_eq!(
            config.get_groups(),
            vec!["group2".to_string(), "group3".to_string()]
        );

        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_config_setup_from_vm_args_vsock() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_paths = [
            test_dir.path().join("vhost3.socket"),
            test_dir.path().join("vhost4.socket"),
            test_dir.path().join("vhost5.socket"),
            test_dir.path().join("vhost6.socket"),
        ];
        let uds_paths = [
            test_dir.path().join("vm3.vsock"),
            test_dir.path().join("vm4.vsock"),
            test_dir.path().join("vm5.vsock"),
        ];
        let params = format!(
            "--vm socket={vhost3_socket},uds_path={vm3_vsock} \
             --vm socket={vhost4_socket},uds-path={vm4_vsock},guest-cid=4,tx_buffer_size=65536,queue_size=1024,groups=group1 \
             --vm groups=group2+group3,guest-cid=5,socket={vhost5_socket},uds_path={vm5_vsock},tx-buffer-size=32768,queue_size=256 \
             --vm guest-cid=6,socket={vhost6_socket},forward-cid=1,forward-listen=1234+4321,queue-size=2048",
            vhost3_socket = socket_paths[0].display(),
            vhost4_socket = socket_paths[1].display(),
            vhost5_socket = socket_paths[2].display(),
            vhost6_socket = socket_paths[3].display(),
            vm3_vsock = uds_paths[0].display(),
            vm4_vsock = uds_paths[1].display(),
            vm5_vsock = uds_paths[2].display(),
        );

        let mut params = params.split_whitespace().collect::<Vec<&str>>();
        params.insert(0, ""); // to make the test binary name agnostic

        let args = VsockArgs::parse_from(params);

        let configs = Vec::<VsockConfig>::try_from(args);
        assert!(configs.is_ok());

        let configs = configs.unwrap();
        assert_eq!(configs.len(), 4);

        let config = configs.first().unwrap();
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(config.get_socket_path(), socket_paths[0]);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_paths[0].clone())
        );
        assert_eq!(config.get_tx_buffer_size(), 65536);
        assert_eq!(config.get_queue_size(), 1024);
        assert_eq!(config.get_groups(), vec![DEFAULT_GROUP_NAME.to_string()]);

        let config = configs.get(1).unwrap();
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(config.get_socket_path(), socket_paths[1]);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_paths[1].clone())
        );
        assert_eq!(config.get_tx_buffer_size(), 65536);
        assert_eq!(config.get_queue_size(), 1024);
        assert_eq!(config.get_groups(), vec!["group1".to_string()]);

        let config = configs.get(2).unwrap();
        assert_eq!(config.get_guest_cid(), 5);
        assert_eq!(config.get_socket_path(), socket_paths[2]);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_paths[2].clone())
        );
        assert_eq!(config.get_tx_buffer_size(), 32768);
        assert_eq!(config.get_queue_size(), 256);
        assert_eq!(
            config.get_groups(),
            vec!["group2".to_string(), "group3".to_string()]
        );

        let config = configs.get(3).unwrap();
        assert_eq!(config.get_guest_cid(), 6);
        assert_eq!(config.get_socket_path(), socket_paths[3]);
        assert_eq!(
            config.get_backend_info(),
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: 1,
                listen_ports: vec![1234, 4321]
            })
        );
        assert_eq!(config.get_tx_buffer_size(), 65536);
        assert_eq!(config.get_queue_size(), 2048);
        assert_eq!(config.get_groups(), vec![DEFAULT_GROUP_NAME.to_string()]);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_config_setup_from_file_unix() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let config_path = test_dir.path().join("config.yaml");
        let socket_path = test_dir.path().join("vhost4.socket");
        let uds_path = test_dir.path().join("vm4.vsock");

        let mut yaml = File::create(&config_path).unwrap();
        yaml.write_all(
            format!(
                "vms:
    - guest_cid: 4
      socket: {}
      uds_path: {}
      tx_buffer_size: 32768
      queue_size: 256
      groups: group1+group2",
                socket_path.display(),
                uds_path.display(),
            )
            .as_bytes(),
        )
        .unwrap();
        let args = VsockArgs::from_file(&config_path.display().to_string());

        let configs = Vec::<VsockConfig>::try_from(args).unwrap();
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(config.get_socket_path(), socket_path);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_path.clone())
        );
        assert_eq!(config.get_tx_buffer_size(), 32768);
        assert_eq!(config.get_queue_size(), 256);
        assert_eq!(
            config.get_groups(),
            vec!["group1".to_string(), "group2".to_string()]
        );

        // Now test that optional parameters are correctly set to their default values.
        let mut yaml = File::create(&config_path).unwrap();
        yaml.write_all(
            format!(
                "vms:
    - socket: {}
      uds_path: {}",
                socket_path.display(),
                uds_path.display(),
            )
            .as_bytes(),
        )
        .unwrap();
        let args = VsockArgs::from_file(&config_path.display().to_string());

        let configs = Vec::<VsockConfig>::try_from(args).unwrap();
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), DEFAULT_GUEST_CID);
        assert_eq!(config.get_socket_path(), socket_path);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_path)
        );
        assert_eq!(config.get_tx_buffer_size(), DEFAULT_TX_BUFFER_SIZE);
        assert_eq!(config.get_queue_size(), DEFAULT_QUEUE_SIZE);
        assert_eq!(config.get_groups(), vec![DEFAULT_GROUP_NAME.to_string()]);

        std::fs::remove_file(&config_path).unwrap();
        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_config_setup_from_file_vsock() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let config_path = test_dir.path().join("config.yaml");
        let socket_path_unix = test_dir.path().join("vhost4.socket");
        let socket_path_vsock = test_dir.path().join("vhost5.socket");
        let uds_path = test_dir.path().join("vm4.vsock");

        let mut yaml = File::create(&config_path).unwrap();
        yaml.write_all(
            format!(
                "vms:
    - guest_cid: 4
      socket: {}
      uds_path: {}
      tx_buffer_size: 32768
      queue_size: 256
      groups: group1+group2
    - guest_cid: 5
      socket: {}
      forward_cid: 1
      forward_listen: 1234+4321
      tx_buffer_size: 32768",
                socket_path_unix.display(),
                uds_path.display(),
                socket_path_vsock.display(),
            )
            .as_bytes(),
        )
        .unwrap();
        let args = VsockArgs::from_file(&config_path.display().to_string());

        let configs = Vec::<VsockConfig>::try_from(args).unwrap();
        assert_eq!(configs.len(), 2);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(config.get_socket_path(), socket_path_unix);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_path.clone())
        );
        assert_eq!(config.get_tx_buffer_size(), 32768);
        assert_eq!(config.get_queue_size(), 256);
        assert_eq!(
            config.get_groups(),
            vec!["group1".to_string(), "group2".to_string()]
        );

        let config = &configs[1];
        assert_eq!(config.get_guest_cid(), 5);
        assert_eq!(config.get_socket_path(), socket_path_vsock);
        assert_eq!(
            config.get_backend_info(),
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: 1,
                listen_ports: vec![1234, 4321]
            })
        );
        assert_eq!(config.get_tx_buffer_size(), 32768);
        assert_eq!(config.get_queue_size(), 1024);
        assert_eq!(config.get_groups(), vec![DEFAULT_GROUP_NAME.to_string()]);

        // Now test that optional parameters are correctly set to their default values.
        let mut yaml = File::create(&config_path).unwrap();
        yaml.write_all(
            format!(
                "vms:
    - socket: {}
      uds_path: {}",
                socket_path_unix.display(),
                uds_path.display(),
            )
            .as_bytes(),
        )
        .unwrap();
        let args = VsockArgs::from_file(&config_path.display().to_string());

        let configs = Vec::<VsockConfig>::try_from(args).unwrap();
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), DEFAULT_GUEST_CID);
        assert_eq!(config.get_socket_path(), socket_path_unix);
        assert_eq!(
            config.get_backend_info(),
            BackendType::UnixDomainSocket(uds_path)
        );
        assert_eq!(config.get_tx_buffer_size(), DEFAULT_TX_BUFFER_SIZE);
        assert_eq!(config.get_queue_size(), DEFAULT_QUEUE_SIZE);
        assert_eq!(config.get_groups(), vec![DEFAULT_GROUP_NAME.to_string()]);

        std::fs::remove_file(&config_path).unwrap();
        test_dir.close().unwrap();
    }

    fn test_vsock_server(config: VsockConfig) {
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let backend = Arc::new(VhostUserVsockBackend::new(config, cid_map).unwrap());

        let daemon = VhostUserDaemon::new(
            String::from("vhost-device-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let mut epoll_handlers = daemon.get_epoll_handlers();

        // VhostUserVsockBackend support a single thread that handles the TX and RX
        // queues
        assert_eq!(backend.threads.len(), 1);

        assert_eq!(epoll_handlers.len(), backend.threads.len());

        for thread in backend.threads.iter() {
            thread
                .lock()
                .unwrap()
                .register_listeners(epoll_handlers.remove(0));
        }
    }

    #[test]
    fn test_vsock_server_unix() {
        const CID: u64 = 3;
        const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
        const QUEUE_SIZE: usize = 1024;

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_server.socket");
        let vsock_socket_path = test_dir.path().join("test_vsock_server.vsock");

        let config = VsockConfig::new(
            CID,
            vhost_socket_path,
            BackendType::UnixDomainSocket(vsock_socket_path),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            vec![DEFAULT_GROUP_NAME.to_string()],
        );

        test_vsock_server(config);

        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_server_vsock() {
        const CID: u64 = 3;
        const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
        const QUEUE_SIZE: usize = 1024;

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_server.socket");

        let config = VsockConfig::new(
            CID,
            vhost_socket_path,
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: 1,
                listen_ports: vec![9000],
            }),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            vec![DEFAULT_GROUP_NAME.to_string()],
        );

        test_vsock_server(config);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_start_backend_servers_failure() {
        const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
        const QUEUE_SIZE: usize = 1024;

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let configs = [
            VsockConfig::new(
                3,
                test_dir.path().join("test_vsock_server1.socket"),
                BackendType::UnixDomainSocket(test_dir.path().join("test_vsock_server1.vsock")),
                CONN_TX_BUF_SIZE,
                QUEUE_SIZE,
                vec![DEFAULT_GROUP_NAME.to_string()],
            ),
            VsockConfig::new(
                3,
                test_dir.path().join("test_vsock_server2.socket"),
                BackendType::UnixDomainSocket(test_dir.path().join("test_vsock_server2.vsock")),
                CONN_TX_BUF_SIZE,
                QUEUE_SIZE,
                vec![DEFAULT_GROUP_NAME.to_string()],
            ),
        ];

        let error = start_backend_servers(&configs).unwrap_err();
        assert_matches!(
            error,
            BackendError::CouldNotCreateBackend(vhu_vsock::Error::CidAlreadyInUse)
        );
        assert_eq!(
            format!("{error:?}"),
            "CouldNotCreateBackend(CidAlreadyInUse)"
        );

        // In slow systems it can happen that one thread is exiting due to
        // an error and another thread is creating files (Unix socket),
        // so sometimes this call fails because after deleting all the
        // files it finds more. So let's discard eventual errors.
        let _ = test_dir.close();
    }

    #[cfg(not(feature = "backend_vsock"))]
    #[test]
    fn test_main_structs_unix() {
        let error = parse_vm_params("").unwrap_err();
        assert_matches!(error, VmArgsParseError::BadArgument);
        assert_eq!(format!("{error:?}"), "BadArgument");

        let args = VsockArgs {
            param: None,
            vm: None,
            config: None,
        };
        let error = Vec::<VsockConfig>::try_from(args).unwrap_err();
        assert_matches!(error, CliError::NoArgsProvided);
        assert_eq!(format!("{error:?}"), "NoArgsProvided");

        let args = VsockArgs::from_args_unix(0, "", "", 0, 0, "");
        assert_eq!(format!("{args:?}"), "VsockArgs { param: Some(VsockParam { guest_cid: 0, socket: \"\", uds_path: Some(\"\"), tx_buffer_size: 0, queue_size: 0, groups: \"\" }), vm: None, config: None }");

        let param = args.param.unwrap().clone();
        assert_eq!(format!("{param:?}"), "VsockParam { guest_cid: 0, socket: \"\", uds_path: Some(\"\"), tx_buffer_size: 0, queue_size: 0, groups: \"\" }");

        let config = ConfigFileVsockParam {
            guest_cid: None,
            socket: String::new(),
            uds_path: Some(String::new()),
            tx_buffer_size: None,
            queue_size: None,
            groups: None,
        }
        .clone();
        assert_eq!(format!("{config:?}"), "ConfigFileVsockParam { guest_cid: None, socket: \"\", uds_path: Some(\"\"), tx_buffer_size: None, queue_size: None, groups: None }");
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_main_structs_vsock() {
        let error = parse_vm_params("").unwrap_err();
        assert_matches!(error, VmArgsParseError::BadArgument);
        assert_eq!(format!("{error:?}"), "BadArgument");

        let args = VsockArgs {
            param: None,
            vm: None,
            config: None,
        };
        let error = Vec::<VsockConfig>::try_from(args).unwrap_err();
        assert_matches!(error, CliError::NoArgsProvided);
        assert_eq!(format!("{error:?}"), "NoArgsProvided");

        let args = VsockArgs::from_args_unix(0, &PathBuf::new(), &PathBuf::new(), 0, 0, "");
        assert_eq!(format!("{args:?}"), "VsockArgs { param: Some(VsockParam { guest_cid: 0, socket: \"\", uds_path: Some(\"\"), forward_cid: None, forward_listen: None, tx_buffer_size: 0, queue_size: 0, groups: \"\" }), vm: None, config: None }");

        let param = args.param.unwrap().clone();
        assert_eq!(format!("{param:?}"), "VsockParam { guest_cid: 0, socket: \"\", uds_path: Some(\"\"), forward_cid: None, forward_listen: None, tx_buffer_size: 0, queue_size: 0, groups: \"\" }");

        let args = VsockArgs::from_args_vsock(0, &PathBuf::new(), 1, "", 0, 0, "");
        assert_eq!(format!("{args:?}"), "VsockArgs { param: Some(VsockParam { guest_cid: 0, socket: \"\", uds_path: None, forward_cid: Some(1), forward_listen: Some(\"\"), tx_buffer_size: 0, queue_size: 0, groups: \"\" }), vm: None, config: None }");

        let param = args.param.unwrap().clone();
        assert_eq!(format!("{param:?}"), "VsockParam { guest_cid: 0, socket: \"\", uds_path: None, forward_cid: Some(1), forward_listen: Some(\"\"), tx_buffer_size: 0, queue_size: 0, groups: \"\" }");

        let config = ConfigFileVsockParam {
            guest_cid: None,
            socket: PathBuf::new(),
            uds_path: Some(PathBuf::new()),
            forward_cid: None,
            forward_listen: None,
            tx_buffer_size: None,
            queue_size: None,
            groups: None,
        }
        .clone();
        assert_eq!(format!("{config:?}"), "ConfigFileVsockParam { guest_cid: None, socket: \"\", uds_path: Some(\"\"), forward_cid: None, forward_listen: None, tx_buffer_size: None, queue_size: None, groups: None }");

        let config = ConfigFileVsockParam {
            guest_cid: None,
            socket: PathBuf::new(),
            uds_path: None,
            forward_cid: Some(1),
            forward_listen: Some(String::new()),
            tx_buffer_size: None,
            queue_size: None,
            groups: None,
        }
        .clone();
        assert_eq!(format!("{config:?}"), "ConfigFileVsockParam { guest_cid: None, socket: \"\", uds_path: None, forward_cid: Some(1), forward_listen: Some(\"\"), tx_buffer_size: None, queue_size: None, groups: None }");
    }
}
