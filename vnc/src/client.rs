// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights r&eserved.
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

use super::errors::{ErrorKind, Result};
use error_chain::ChainedError;
use machine_manager::event_loop::EventLoop;
use sscanf::scanf;
use std::{
    cmp,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    os::unix::prelude::{AsRawFd, RawFd},
    sync::{Arc, Mutex},
};
use util::{
    bitmap::Bitmap,
    loop_context::{EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation},
};
use vmm_sys_util::epoll::EventSet;

use crate::{VncServer, VNC_SERVERS};

/// RFB protocol version.
struct VncVersion {
    major: u16,
    minor: u16,
}

impl VncVersion {
    pub fn new(major: u16, minor: u16) -> Self {
        VncVersion { major, minor }
    }
}

impl Default for VncVersion {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// VncClient struct to record the information of connnection.
pub struct VncClient {
    /// TcpStream connected with client.
    pub stream: TcpStream,
    /// Size of buff in next handle.
    pub expect: usize,
    /// Connection status.
    pub dis_conn: bool,
    /// RFB protocol version.
    version: VncVersion,
    /// The function handling the connection.
    pub handlers: Vec<Arc<Mutex<Box<NotifierCallback>>>>,
    /// Pointer to VncServer.
    pub server: Arc<Mutex<VncServer>>,
    /// Data storage type for client.
    big_endian: bool,
    /// Tcp listening address.
    pub addr: String,
    /// Image width.
    width: i32,
    /// Image height.
    height: i32,
    /// Image display feature.
    feature: i32,
    /// The pixel need to convert.
    pixel_convert: bool,
}

impl VncClient {
    pub fn new(stream: TcpStream, addr: String, server: Arc<Mutex<VncServer>>) -> Self {
        VncClient {
            stream,
            expect: 12,
            dis_conn: false,
            version: VncVersion::default(),
            handlers: Vec::new(),
            server,
            big_endian: false,
            addr,
            width: 0,
            height: 0,
            feature: 0,
            pixel_convert: false,
        }
    }

    /// Modify event notifiers to  event loop
    ///
    /// # Arguments
    ///
    /// * `op` - Notifier operation.
    /// * `idx` - Idx of event in server.handlers
    pub fn modify_event(&mut self, op: NotifierOperation, idx: usize) -> Result<()> {
        let mut handlers = Vec::new();

        if let NotifierOperation::Modify = op {
            if self.handlers.len() <= idx {
                return Ok(());
            }
            handlers.push(self.handlers[idx].clone());
        }

        EventLoop::update_event(
            vec![EventNotifier::new(
                op,
                self.stream.as_raw_fd(),
                None,
                EventSet::IN | EventSet::READ_HANG_UP,
                handlers,
            )],
            None,
        )?;

        Ok(())
    }

    /// Send plain txt.
    pub fn write_plain_msg(&mut self, buf: &[u8]) {
        let buf_size = buf.len();
        let mut offset = 0;
        loop {
            let tmp_buf = &buf[offset..];
            match self.stream.write(tmp_buf) {
                Ok(ret) => {
                    offset += ret;
                }
                Err(e) => {
                    error!("write msg error: {:?}", e);
                }
            }
            self.stream.flush().unwrap();
            if offset >= buf_size {
                break;
            }
        }
    }

    /// write buf to stream
    /// Choose different channel according to whether or not to encrypt
    ///
    /// # Arguments
    /// * `buf` - Data to be send.
    pub fn write_msg(&mut self, buf: &[u8]) {
        self.write_plain_msg(buf);
    }

    /// Clear the data  when disconnected from client.
    pub fn disconnect(&mut self) {
        let server = VNC_SERVERS.lock().unwrap()[0].clone();
        let mut locked_server = server.lock().unwrap();
        locked_server.clients.remove(&self.addr);

        drop(locked_server);

        if let Err(e) = self.modify_event(NotifierOperation::Delete, 0) {
            error!("Failed to delete event, error is {}", e.display_chain());
        }

        if let Err(e) = self.stream.shutdown(Shutdown::Both) {
            info!("Shutdown stream failed: {}", e);
        }
        self.handlers.clear();
    }
}

/// Internal_notifiers for VncClient.
impl EventNotifierHelper for VncClient {
    fn internal_notifiers(client_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let client = client_handler.clone();
        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |event, _| {
                let mut dis_conn = false;

                if dis_conn {
                    client.lock().unwrap().disconnect();
                }

                None as Option<Vec<EventNotifier>>
            });

        let mut locked_client = client_handler.lock().unwrap();
        locked_client.handlers.push(Arc::new(Mutex::new(handler)));

        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            locked_client.stream.as_raw_fd(),
            None,
            EventSet::IN | EventSet::READ_HANG_UP,
            vec![locked_client.handlers[0].clone()],
        )]
    }
}
