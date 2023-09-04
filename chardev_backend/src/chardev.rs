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
use std::os::unix::net::{UnixListener, UnixStream};
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
    /// UnixListener for socket-type chardev.
    listener: Option<UnixListener>,
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
                // Safe because `master_arc` is the only one owner for the file descriptor.
                let master_arc = unsafe { Arc::new(Mutex::new(File::from_raw_fd(master))) };
                self.input = Some(master_arc.clone());
                self.output = Some(master_arc);
            }
            ChardevType::Socket {
                path,
                server,
                nowait,
            } => {
                if !*server || !*nowait {
                    bail!(
                        "Argument \'server\' and \'nowait\' are both required for chardev \'{}\'",
                        path
                    );
                }
                clear_file(path.clone())?;
                let sock = UnixListener::bind(path.clone())
                    .with_context(|| format!("Failed to bind socket for chardev, path:{}", path))?;
                self.listener = Some(sock);
                // add file to temporary pool, so it could be cleaned when vm exit.
                TempCleaner::add_path(path.clone());
                limit_permission(path).with_context(|| {
                    format!(
                        "Failed to change file permission for chardev, path:{}",
                        path
                    )
                })?;
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

fn get_notifier_handler(
    chardev: Arc<Mutex<Chardev>>,
    backend: ChardevType,
) -> Rc<NotifierCallback> {
    match backend {
        ChardevType::Stdio | ChardevType::Pty => Rc::new(move |_, _| {
            let locked_chardev = chardev.lock().unwrap();
            if locked_chardev.receiver.is_none() {
                error!("Failed to get chardev receiver");
                return None;
            }
            if locked_chardev.input.is_none() {
                error!("Failed to get chardev input fd");
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
            if let Ok(index) = input.lock().unwrap().chr_read_raw(&mut buffer) {
                locked_receiver.receive(&buffer[..index]);
            } else {
                error!("Failed to read input data");
            }
            None
        }),
        ChardevType::Socket { .. } => Rc::new(move |_, _| {
            let mut locked_chardev = chardev.lock().unwrap();
            let (stream, _) = locked_chardev.listener.as_ref().unwrap().accept().unwrap();
            let listener_fd = locked_chardev.listener.as_ref().unwrap().as_raw_fd();
            let stream_fd = stream.as_raw_fd();
            locked_chardev.stream_fd = Some(stream_fd);
            let stream_arc = Arc::new(Mutex::new(stream));
            locked_chardev.input = Some(stream_arc.clone());
            locked_chardev.output = Some(stream_arc);

            if let Some(dev) = &locked_chardev.dev {
                dev.lock().unwrap().chardev_notify(ChardevStatus::Open);
            }

            let cloned_chardev = chardev.clone();
            let inner_handler: Rc<NotifierCallback> = Rc::new(move |event, _| {
                let mut locked_chardev = cloned_chardev.lock().unwrap();
                if event == EventSet::IN {
                    if locked_chardev.receiver.is_none() {
                        error!("Failed to get chardev receiver");
                        return None;
                    }
                    if locked_chardev.input.is_none() {
                        error!("Failed to get chardev input fd");
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
                    if let Ok(index) = input.lock().unwrap().chr_read_raw(&mut buffer) {
                        locked_receiver.receive(&buffer[..index]);
                    } else {
                        error!("Failed to read input data");
                    }
                    None
                } else if event & EventSet::HANG_UP == EventSet::HANG_UP {
                    // Always allow disconnect even if has deactivated.
                    if let Some(dev) = &locked_chardev.dev {
                        dev.lock().unwrap().chardev_notify(ChardevStatus::Close);
                    }
                    locked_chardev.input = None;
                    locked_chardev.output = None;
                    locked_chardev.stream_fd = None;
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
        }),
        ChardevType::File(_) => Rc::new(move |_, _| None),
    }
}

impl EventNotifierHelper for Chardev {
    fn internal_notifiers(chardev: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        let backend = chardev.lock().unwrap().backend.clone();
        let cloned_chardev = chardev.clone();
        match backend {
            ChardevType::Stdio | ChardevType::Pty => {
                if let Some(input) = chardev.lock().unwrap().input.clone() {
                    notifiers.push(EventNotifier::new(
                        NotifierOperation::AddShared,
                        input.lock().unwrap().as_raw_fd(),
                        None,
                        EventSet::IN,
                        vec![get_notifier_handler(cloned_chardev, backend)],
                    ));
                }
            }
            ChardevType::Socket { .. } => {
                if chardev.lock().unwrap().stream_fd.is_some() {
                    notifiers.push(EventNotifier::new(
                        NotifierOperation::Resume,
                        chardev.lock().unwrap().stream_fd.unwrap(),
                        None,
                        EventSet::IN | EventSet::HANG_UP,
                        Vec::new(),
                    ));
                } else if let Some(listener) = chardev.lock().unwrap().listener.as_ref() {
                    notifiers.push(EventNotifier::new(
                        NotifierOperation::AddShared,
                        listener.as_raw_fd(),
                        None,
                        EventSet::IN,
                        vec![get_notifier_handler(cloned_chardev, backend)],
                    ));
                }
            }
            ChardevType::File(_) => (),
        }
        notifiers
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

impl CommunicatInInterface for UnixStream {}
impl CommunicatInInterface for File {}
impl CommunicatInInterface for Stdin {}

impl CommunicatOutInterface for UnixStream {}
impl CommunicatOutInterface for File {}
impl CommunicatOutInterface for Stdout {}
