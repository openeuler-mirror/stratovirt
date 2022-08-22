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
use machine_manager::{
    config::{ObjConfig, VncConfig},
    event_loop::EventLoop,
};
use std::{
    cmp,
    collections::HashMap,
    net::{Shutdown, TcpListener},
    os::unix::prelude::{AsRawFd, RawFd},
    ptr,
    sync::{Arc, Mutex},
};
use util::{
    bitmap::Bitmap,
    loop_context::{read_fd, EventNotifier, EventNotifierHelper, NotifierOperation},
    pixman::{
        pixman_format_bpp, pixman_format_code_t, pixman_image_composite, pixman_image_create_bits,
        pixman_image_t, pixman_op_t,
    },
};
use vmm_sys_util::epoll::EventSet;

use crate::{
    bytes_per_pixel, get_image_data, get_image_format, get_image_height, get_image_stride,
    get_image_width, round_up_div, update_client_surface, AuthState, SubAuthState, VncClient,
    DIRTY_PIXELS_NUM, MAX_WINDOW_HEIGHT, MAX_WINDOW_WIDTH, REFRESH_EVT, VNC_BITMAP_WIDTH,
    VNC_SERVERS,
};

/// VncServer
pub struct VncServer {
    // Tcp connection listened by server.
    listener: Arc<Mutex<TcpListener>>,
    // Clients connected to vnc.
    pub clients: HashMap<String, Arc<Mutex<VncClient>>>,
    /// Image refresh to VncClient.
    pub server_image: *mut pixman_image_t,
    /// Image from gpu.
    pub guest_image: *mut pixman_image_t,
    /// Identify the image update area for guest image.
    pub guest_dirtymap: Bitmap<u64>,
    /// Image format of pixman.
    pub guest_format: pixman_format_code_t,
    // Connection limit.
    conn_limits: usize,
    /// Width of current image.
    pub true_width: i32,
}

unsafe impl Send for VncServer {}

impl VncServer {
    /// Create a new VncServer.
    pub fn new(listener: Arc<Mutex<TcpListener>>, guest_image: *mut pixman_image_t) -> Self {
        VncServer {
            listener,
            clients: HashMap::new(),
            server_image: ptr::null_mut(),
            guest_image,
            guest_dirtymap: Bitmap::<u64>::new(
                MAX_WINDOW_HEIGHT as usize
                    * round_up_div(
                        (MAX_WINDOW_WIDTH / DIRTY_PIXELS_NUM) as u64,
                        u64::BITS as u64,
                    ) as usize,
            ),
            guest_format: pixman_format_code_t::PIXMAN_x8r8g8b8,
            conn_limits: 1,
            true_width: 0,
        }
    }

    /// Make configuration for VncServer.
    pub fn make_config(
        &mut self,
        vnc_cfg: &VncConfig,
        object: &HashMap<String, ObjConfig>,
    ) -> Result<()> {
        Ok(())
    }

    /// Listen to the port and accpet client's connection.
    pub fn handle_connection(&mut self) -> Result<()> {
        match self.listener.lock().unwrap().accept() {
            Ok((stream, addr)) => {
                if self.clients.len() >= self.conn_limits {
                    stream.shutdown(Shutdown::Both).unwrap();
                    return Ok(());
                }
                info!("new client: {:?}", addr);
                stream
                    .set_nonblocking(true)
                    .expect("set nonblocking failed");

                let server = VNC_SERVERS.lock().unwrap()[0].clone();
                let mut client =
                    VncClient::new(stream, addr.to_string(), server, self.server_image);
                client.write_msg("RFB 003.008\n".to_string().as_bytes());
                info!("{:?}", client.stream);

                let tmp_client = Arc::new(Mutex::new(client));
                self.clients.insert(addr.to_string(), tmp_client.clone());

                EventLoop::update_event(EventNotifierHelper::internal_notifiers(tmp_client), None)?;
            }
            Err(e) => {
                info!("Connect failed: {:?}", e);
            }
        }

        update_client_surface(self);

        Ok(())
    }
}

/// Internal_notifiers for VncServer.
impl EventNotifierHelper for VncServer {
    fn internal_notifiers(server_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let server = server_handler.clone();
        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |event, fd: RawFd| {
                read_fd(fd);

                if event & EventSet::HANG_UP == EventSet::HANG_UP {
                    info!("Client Closed");
                } else if event == EventSet::IN {
                    let mut locked_handler = server.lock().unwrap();
                    if let Err(e) = locked_handler.handle_connection() {
                        error!("Failed to handle vnc client connection, error is {}", e);
                    }
                    drop(locked_handler);
                }

                None as Option<Vec<EventNotifier>>
            });

        let mut notifiers = vec![
            (EventNotifier::new(
                NotifierOperation::AddShared,
                server_handler
                    .lock()
                    .unwrap()
                    .listener
                    .lock()
                    .unwrap()
                    .as_raw_fd(),
                None,
                EventSet::IN | EventSet::HANG_UP,
                vec![Arc::new(Mutex::new(handler))],
            )),
        ];

        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |_event, fd: RawFd| {
                read_fd(fd);
                vnc_refresh();
                None as Option<Vec<EventNotifier>>
            });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            REFRESH_EVT.lock().unwrap().as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));
        notifiers
    }
}

/// Refresh server_image to guest_image
fn vnc_refresh() {
    if VNC_SERVERS.lock().unwrap().is_empty() {
        return;
    }
}
