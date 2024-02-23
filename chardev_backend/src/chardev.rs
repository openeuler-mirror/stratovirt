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
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use log::{error, info, warn};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::pty::openpty;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg, Termios};
use vmm_sys_util::epoll::EventSet;

use machine_manager::event_loop::EventLoop;
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
    /// 0 if receiver is not ready or no space in FIFO
    fn remain_size(&mut self) -> usize;
    /// Tell receiver that RX is paused and receiver
    /// must unpause it when it becomes ready
    fn set_paused(&mut self);
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
    /// Whether event-handling of device is initialized
    /// and we wait for port to become available
    wait_port: bool,
    /// Scheduled DPC to unpause input stream.
    /// Unpause must be done inside event-loop
    unpause_timer: Option<u64>,
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
            wait_port: false,
            unpause_timer: None,
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
        if self.wait_port {
            warn!("Serial port for chardev \'{}\' appeared.", &self.id);
            self.wait_port = false;
            self.unpause_rx();
        }
    }

    fn wait_for_port(&mut self, input_fd: RawFd) -> EventNotifier {
        // set_receiver() will unpause rx
        warn!(
            "Serial port for chardev \'{}\' is not ready yet, waiting for port.",
            &self.id
        );

        self.wait_port = true;

        EventNotifier::new(
            NotifierOperation::Modify,
            input_fd,
            None,
            EventSet::HANG_UP,
            vec![],
        )
    }

    pub fn set_device(&mut self, dev: Arc<Mutex<dyn ChardevNotifyDevice>>) {
        self.dev = Some(dev.clone());
    }

    pub fn unpause_rx(&mut self) {
        // Receiver calls this if it returned 0 from remain_size()
        // and now it's ready to accept rx-data again
        if self.input.is_none() {
            error!("unpause called for non-initialized device \'{}\'", &self.id);
            return;
        }
        if self.unpause_timer.is_some() {
            return; // already set
        }

        let input_fd = self.input.clone().unwrap().lock().unwrap().as_raw_fd();

        let unpause_fn = Box::new(move || {
            let res = EventLoop::update_event(
                vec![EventNotifier::new(
                    NotifierOperation::Modify,
                    input_fd,
                    None,
                    EventSet::IN | EventSet::HANG_UP,
                    vec![],
                )],
                None,
            );
            if let Err(e) = res {
                error!("Failed to unpause on fd {input_fd}: {e:?}");
            }
        });
        let main_loop = EventLoop::get_ctx(None).unwrap();
        let timer_id = main_loop.timer_add(unpause_fn, Duration::ZERO);
        self.unpause_timer = Some(timer_id);
    }

    fn cancel_unpause_timer(&mut self) {
        if let Some(timer_id) = self.unpause_timer {
            let main_loop = EventLoop::get_ctx(None).unwrap();
            main_loop.timer_del(timer_id);
            self.unpause_timer = None;
        }
    }
}

fn set_pty_raw_mode() -> Result<(i32, PathBuf)> {
    let (master, slave) = match openpty(None, None) {
        Ok(res) => (res.master, res.slave),
        Err(e) => bail!("Failed to open pty, error is {:?}", e),
    };

    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", slave));
    let path = read_link(proc_path).with_context(|| "Failed to read slave pty link")?;

    let mut new_termios: Termios = match tcgetattr(slave) {
        Ok(tm) => tm,
        Err(e) => bail!("Failed to get mode of pty, error is {:?}", e),
    };

    cfmakeraw(&mut new_termios);

    if let Err(e) = tcsetattr(slave, SetArg::TCSAFLUSH, &new_termios) {
        bail!("Failed to set pty to raw mode, error is {:?}", e);
    }

    let fcnt_arg = FcntlArg::F_SETFL(OFlag::from_bits(libc::O_NONBLOCK).unwrap());
    if let Err(e) = fcntl(master, fcnt_arg) {
        bail!(
            "Failed to set pty master to nonblocking mode, error is {:?}",
            e
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
    let input_fd = input.unwrap().lock().unwrap().as_raw_fd();

    let event_handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
        let mut locked_chardev = cloned_chardev.lock().unwrap();
        if locked_chardev.receiver.is_none() {
            let wait_port = locked_chardev.wait_for_port(input_fd);
            return Some(vec![wait_port]);
        }

        locked_chardev.cancel_unpause_timer(); // it will be rescheduled if needed

        let receiver = locked_chardev.receiver.clone().unwrap();
        let input = locked_chardev.input.clone().unwrap();
        drop(locked_chardev);

        let mut locked_receiver = receiver.lock().unwrap();
        let buff_size = locked_receiver.remain_size();
        if buff_size == 0 {
            locked_receiver.set_paused();

            return Some(vec![EventNotifier::new(
                NotifierOperation::Modify,
                input_fd,
                None,
                EventSet::HANG_UP,
                vec![],
            )]);
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

        let handling_chardev = cloned_chardev.clone();
        let close_connection = Rc::new(move || {
            let mut locked_chardev = handling_chardev.lock().unwrap();
            let notify_dev = locked_chardev.dev.clone();
            locked_chardev.input = None;
            locked_chardev.output = None;
            locked_chardev.stream_fd = None;
            locked_chardev.cancel_unpause_timer();
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
        });

        let handling_chardev = cloned_chardev.clone();
        let input_handler: Rc<NotifierCallback> = Rc::new(move |event, _| {
            let mut locked_chardev = handling_chardev.lock().unwrap();

            let peer_disconnected = event & EventSet::HANG_UP == EventSet::HANG_UP;
            if peer_disconnected && locked_chardev.receiver.is_none() {
                drop(locked_chardev);
                return close_connection();
            }

            let input_ready = event & EventSet::IN == EventSet::IN;
            if input_ready {
                locked_chardev.cancel_unpause_timer();

                if locked_chardev.receiver.is_none() {
                    let wait_port = locked_chardev.wait_for_port(stream_fd);
                    return Some(vec![wait_port]);
                }

                let receiver = locked_chardev.receiver.clone().unwrap();
                let input = locked_chardev.input.clone().unwrap();
                drop(locked_chardev);

                let mut locked_receiver = receiver.lock().unwrap();
                let buff_size = locked_receiver.remain_size();
                if buff_size == 0 {
                    locked_receiver.set_paused();

                    return Some(vec![EventNotifier::new(
                        NotifierOperation::Modify,
                        stream_fd,
                        None,
                        EventSet::HANG_UP,
                        vec![],
                    )]);
                }

                let mut buffer = vec![0_u8; buff_size];
                let mut locked_input = input.lock().unwrap();
                if let Ok(bytes_count) = locked_input.chr_read_raw(&mut buffer) {
                    if bytes_count > 0 {
                        locked_receiver.receive(&buffer[..bytes_count]);
                    } else {
                        drop(locked_receiver);
                        drop(locked_input);
                        return close_connection();
                    }
                } else {
                    let os_error = std::io::Error::last_os_error();
                    if os_error.kind() != std::io::ErrorKind::WouldBlock {
                        let locked_chardev = handling_chardev.lock().unwrap();
                        error!(
                            "Failed to read input data from chardev \'{}\', {}",
                            &locked_chardev.id, &os_error
                        );
                    }
                }
            }

            None
        });

        Some(vec![EventNotifier::new(
            NotifierOperation::AddShared,
            stream_fd,
            Some(listener_fd),
            EventSet::IN | EventSet::HANG_UP,
            vec![input_handler],
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
        match nix::unistd::read(self.as_raw_fd(), buf) {
            Err(e) => bail!("Failed to read buffer: {:?}", e),
            Ok(bytes) => Ok(bytes),
        }
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
