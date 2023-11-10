// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::fs::{read_link, File, OpenOptions};
use std::io::{Stdin, Stdout};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use libc::{cfmakeraw, tcgetattr, tcsetattr, termios};
use log::{error, info};
use vmm_sys_util::epoll::EventSet;

use machine_manager::machine::{PathInfo, PTY_PATH};
use machine_manager::{
    config::{ChardevConfig, ChardevType},
    temp_cleaner::TempCleaner,
};
use util::file::clear_file;
use util::loop_context::{
    gen_delete_notifiers, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::set_termi_raw_mode;
use util::socket::{SocketListener, SocketStream};
use util::unix::limit_permission;

/// Provide the trait that helps handle the input data.
pub trait InputReceiver: Send {
    /// Handle the input data and trigger interrupt if necessary.
    fn receive(&mut self, buffer: &[u8]);
    /// Return the remain space size of receiver buffer.
    fn remain_size(&mut self) -> usize;
}

/// Provide the trait that notifies device the socket is opened or closed.
pub trait ChardevNotifyDevice: Send {
    fn chardev_notify(&mut self, status: ChardevStatus);
}

pub enum ChardevStatus {
    Close,
    Open,
}

/// Character device structure.
pub struct Chardev {
    /// Id of chardev.
    id: String,
    /// Type of backend device.
    backend: ChardevType,
    /// Socket listener for chardev of socket type.
    listener: Option<SocketListener>,
    /// Chardev input.
    input: Option<Arc<Mutex<dyn CommunicatInInterface>>>,
    /// Chardev output.
    pub output: Option<Arc<Mutex<dyn CommunicatOutInterface>>>,
    /// Fd of socket stream.
    stream_fd: Option<i32>,
    /// Input receiver.
    receiver: Option<Arc<Mutex<dyn InputReceiver>>>,
    /// Used to notify device the socket is opened or closed.
    dev: Option<Arc<Mutex<dyn ChardevNotifyDevice>>>,
}

impl Chardev {
    pub fn new(chardev_cfg: ChardevConfig) -> Self {
        Chardev {
            id: chardev_cfg.id,
            backend: chardev_cfg.backend,
            listener: None,
            input: None,
            output: None,
            stream_fd: None,
            receiver: None,
            dev: None,
        }
    }

    pub fn realize(&mut self) -> Result<()> {
        match &self.backend {
            ChardevType::Stdio => {
                set_termi_raw_mode().with_context(|| "Failed to set terminal to raw mode")?;
                self.input = Some(Arc::new(Mutex::new(std::io::stdin())));
                self.output = Some(Arc::new(Mutex::new(std::io::stdout())));
            }
            ChardevType::Pty => {
                let (master, path) =
                    set_pty_raw_mode().with_context(|| "Failed to set pty to raw mode")?;
                info!("Pty path is: {:?}", path);
                let path_info = PathInfo {
                    path: format!("pty:{:?}", &path),
                    label: self.id.clone(),
                };
                PTY_PATH.lock().unwrap().push(path_info);
                // SAFETY: master was created in the function of set_pty_raw_mode,
                // the value can be guaranteed to be legal.
                let master_arc = Arc::new(Mutex::new(unsafe { File::from_raw_fd(master) }));
                self.input = Some(master_arc.clone());
                self.output = Some(master_arc);
            }
            ChardevType::UnixSocket {
                path,
                server,
                nowait,
            } => {
                if !*server || !*nowait {
                    bail!(
                        "Argument \'server\' and \'nowait\' are both required for chardev \'{}\'",
                        &self.id
                    );
                }

                clear_file(path.clone())?;
                let listener = SocketListener::bind_by_uds(path).with_context(|| {
                    format!(
                        "Failed to bind socket for chardev \'{}\', path: {}",
                        &self.id, path
                    )
                })?;
                self.listener = Some(listener);

                // add file to temporary pool, so it could be cleaned when vm exit.
                TempCleaner::add_path(path.clone());
                limit_permission(path).with_context(|| {
                    format!(
                        "Failed to change file permission for chardev \'{}\', path: {}",
                        &self.id, path
                    )
                })?;
            }
            ChardevType::TcpSocket {
                host,
                port,
                server,
                nowait,
            } => {
                if !*server || !*nowait {
                    bail!(
                        "Argument \'server\' and \'nowait\' are both required for chardev \'{}\'",
                        &self.id
                    );
                }

                let listener = SocketListener::bind_by_tcp(host, *port).with_context(|| {
                    format!(
                        "Failed to bind socket for chardev \'{}\', address: {}:{}",
                        &self.id, host, port
                    )
                })?;
                self.listener = Some(listener);
            }
            ChardevType::File(path) => {
                let file = Arc::new(Mutex::new(
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(path)?,
                ));
                self.output = Some(file);
            }
        };
        Ok(())
    }

    pub fn set_receiver<T: 'static + InputReceiver>(&mut self, dev: &Arc<Mutex<T>>) {
        self.receiver = Some(dev.clone());
    }

    pub fn set_device(&mut self, dev: Arc<Mutex<dyn ChardevNotifyDevice>>) {
        self.dev = Some(dev.clone());
    }
}

fn set_pty_raw_mode() -> Result<(i32, PathBuf)> {
    let mut master: libc::c_int = 0;
    let master_ptr: *mut libc::c_int = &mut master;
    let mut slave: libc::c_int = 0;
    let slave_ptr: *mut libc::c_int = &mut slave;
    // Safe because this only create a new pseudoterminal and set the master and slave fd.
    let ret = {
        unsafe {
            libc::openpty(
                master_ptr,
                slave_ptr,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
    };
    if ret < 0 {
        bail!(
            "Failed to open pty, error is {}",
            std::io::Error::last_os_error()
        )
    }
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", slave));
    let path = read_link(proc_path).with_context(|| "Failed to read slave pty link")?;
    // Safe because this only set the `old_termios` struct to zero.
    let mut old_termios: termios = unsafe { std::mem::zeroed() };
    // Safe because this only get the current mode of slave pty and save it.
    let ret = unsafe { tcgetattr(slave, &mut old_termios as *mut _) };
    if ret < 0 {
        bail!(
            "Failed to get mode of pty, error is {}",
            std::io::Error::last_os_error()
        );
    }
    let mut new_termios: termios = old_termios;
    // Safe because this function only change the `new_termios` argument.
    unsafe { cfmakeraw(&mut new_termios as *mut _) };
    // Safe because this function only set the slave pty to raw mode.
    let ret = unsafe { tcsetattr(slave, libc::TCSAFLUSH, &new_termios as *const _) };
    if ret < 0 {
        bail!(
            "Failed to set pty to raw mode, error is {}",
            std::io::Error::last_os_error()
        );
    }

    // SAFETY: master is got from openpty.
    let ret = unsafe { libc::fcntl(master, libc::F_SETFL, libc::O_NONBLOCK) };
    if ret < 0 {
        bail!(
            "Failed to set pty master to nonblocking mode, error is {}",
            std::io::Error::last_os_error()
        );
    }

    Ok((master, path))
}

// Notification handling in case of stdio or pty usage.
fn get_terminal_notifier(chardev: Arc<Mutex<Chardev>>) -> Option<EventNotifier> {
    let locked_chardev = chardev.lock().unwrap();
    let input = locked_chardev.input.clone();
    if input.is_none() {
        // Method `realize` expected to be called before we get here because to build event
        // notifier we need already valid file descriptors here.
        error!(
            "Failed to initialize input events for chardev \'{}\', chardev not initialized",
            &locked_chardev.id
        );
        return None;
    }

    let cloned_chardev = chardev.clone();
    let event_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
        let locked_chardev = cloned_chardev.lock().unwrap();
        if locked_chardev.receiver.is_none() {
            error!(
                "Failed to read input data from chardev \'{}\', receiver is none",
                &locked_chardev.id
            );
            return None;
        }
        let receiver = locked_chardev.receiver.clone().unwrap();
        let input = locked_chardev.input.clone().unwrap();
        drop(locked_chardev);

        let mut locked_receiver = receiver.lock().unwrap();
        let buff_size = locked_receiver.remain_size();
        if buff_size == 0 {
            return None;
        }

        let mut buffer = vec![0_u8; buff_size];
        if let Ok(bytes_count) = input.lock().unwrap().chr_read_raw(&mut buffer) {
            locked_receiver.receive(&buffer[..bytes_count]);
        } else {
            let os_error = std::io::Error::last_os_error();
            let locked_chardev = cloned_chardev.lock().unwrap();
            error!(
                "Failed to read input data from chardev \'{}\', {}",
                &locked_chardev.id, &os_error
            );
        }
        None
    });

    let input_fd = input.unwrap().lock().unwrap().as_raw_fd();
    Some(EventNotifier::new(
        NotifierOperation::AddShared,
        input_fd,
        None,
        EventSet::IN,
        vec![event_handler],
    ))
}

// Notification handling in case of listening (server) socket.
fn get_socket_notifier(chardev: Arc<Mutex<Chardev>>) -> Option<EventNotifier> {
    let locked_chardev = chardev.lock().unwrap();
    let listener = &locked_chardev.listener;
    if listener.is_none() {
        // Method `realize` expected to be called before we get here because to build event
        // notifier we need already valid file descriptors here.
        error!(
            "Failed to setup io-event notifications for chardev \'{}\', device not initialized",
            &locked_chardev.id
        );
        return None;
    }

    let cloned_chardev = chardev.clone();
    let event_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
        let mut locked_chardev = cloned_chardev.lock().unwrap();

        let stream = locked_chardev.listener.as_ref().unwrap().accept().unwrap();
        let connection_info = stream.link_description();
        info!(
            "Chardev \'{}\' event, connection opened: {}",
            &locked_chardev.id, connection_info
        );
        let stream_fd = stream.as_raw_fd();
        let stream_arc = Arc::new(Mutex::new(stream));
        let listener_fd = locked_chardev.listener.as_ref().unwrap().as_raw_fd();
        let notify_dev = locked_chardev.dev.clone();

        locked_chardev.stream_fd = Some(stream_fd);
        locked_chardev.input = Some(stream_arc.clone());
        locked_chardev.output = Some(stream_arc.clone());
        drop(locked_chardev);

        if let Some(dev) = notify_dev {
            dev.lock().unwrap().chardev_notify(ChardevStatus::Open);
        }

        let cloned_chardev = cloned_chardev.clone();
        let inner_handler: Rc<NotifierCallback> = Rc::new(move |event, _| {
            if event == EventSet::IN {
                let locked_chardev = cloned_chardev.lock().unwrap();
                if locked_chardev.receiver.is_none() {
                    error!(
                        "Failed to read input data from chardev \'{}\', receiver is none",
                        &locked_chardev.id
                    );
                    return None;
                }
                let receiver = locked_chardev.receiver.clone().unwrap();
                let input = locked_chardev.input.clone().unwrap();
                drop(locked_chardev);

                let mut locked_receiver = receiver.lock().unwrap();
                let buff_size = locked_receiver.remain_size();
                if buff_size == 0 {
                    return None;
                }

                let mut buffer = vec![0_u8; buff_size];
                if let Ok(bytes_count) = input.lock().unwrap().chr_read_raw(&mut buffer) {
                    locked_receiver.receive(&buffer[..bytes_count]);
                } else {
                    let os_error = std::io::Error::last_os_error();
                    if os_error.kind() != std::io::ErrorKind::WouldBlock {
                        let locked_chardev = cloned_chardev.lock().unwrap();
                        error!(
                            "Failed to read input data from chardev \'{}\', {}",
                            &locked_chardev.id, &os_error
                        );
                    }
                }
                None
            } else if event & EventSet::HANG_UP == EventSet::HANG_UP {
                let mut locked_chardev = cloned_chardev.lock().unwrap();
                let notify_dev = locked_chardev.dev.clone();
                locked_chardev.input = None;
                locked_chardev.output = None;
                locked_chardev.stream_fd = None;
                info!(
                    "Chardev \'{}\' event, connection closed: {}",
                    &locked_chardev.id, connection_info
                );
                drop(locked_chardev);

                if let Some(dev) = notify_dev {
                    dev.lock().unwrap().chardev_notify(ChardevStatus::Close);
                }

                // Note: we use stream_arc variable here because we want to capture it and prolongate
                // its lifetime with this notifier callback lifetime. It allows us to ensure
                // that socket fd be valid until we unregister it from epoll_fd subscription.
                let stream_fd = stream_arc.lock().unwrap().as_raw_fd();
                Some(gen_delete_notifiers(&[stream_fd]))
            } else {
                None
            }
        });

        Some(vec![EventNotifier::new(
            NotifierOperation::AddShared,
            stream_fd,
            Some(listener_fd),
            EventSet::IN | EventSet::HANG_UP,
            vec![inner_handler],
        )])
    });

    let listener_fd = listener.as_ref().unwrap().as_raw_fd();
    Some(EventNotifier::new(
        NotifierOperation::AddShared,
        listener_fd,
        None,
        EventSet::IN,
        vec![event_handler],
    ))
}

impl EventNotifierHelper for Chardev {
    fn internal_notifiers(chardev: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let notifier = {
            let backend = chardev.lock().unwrap().backend.clone();
            match backend {
                ChardevType::Stdio => get_terminal_notifier(chardev),
                ChardevType::Pty => get_terminal_notifier(chardev),
                ChardevType::UnixSocket { .. } => get_socket_notifier(chardev),
                ChardevType::TcpSocket { .. } => get_socket_notifier(chardev),
                ChardevType::File(_) => None,
            }
        };
        notifier.map_or(Vec::new(), |value| vec![value])
    }
}

/// Provide backend trait object receiving the input from the guest.
pub trait CommunicatInInterface: std::marker::Send + std::os::unix::io::AsRawFd {
    fn chr_read_raw(&mut self, buf: &mut [u8]) -> Result<usize> {
        use libc::read;
        // Safe because this only read the bytes from terminal within the buffer.
        let ret = unsafe { read(self.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret < 0 {
            bail!("Failed to read buffer");
        }
        Ok(ret as usize)
    }
}

/// Provide backend trait object processing the output from the guest.
pub trait CommunicatOutInterface: std::io::Write + std::marker::Send {}

impl CommunicatInInterface for SocketStream {}
impl CommunicatInInterface for File {}
impl CommunicatInInterface for Stdin {}

impl CommunicatOutInterface for SocketStream {}
impl CommunicatOutInterface for File {}
impl CommunicatOutInterface for Stdout {}
