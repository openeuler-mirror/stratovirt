// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::{io::FromRawFd, net::UnixStream};
use std::slice::from_raw_parts;
use std::{
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    mem::size_of,
    ptr,
    rc::Rc,
    sync::{Arc, Mutex, Once, Weak},
};

use anyhow::{anyhow, bail, Context, Result};
use bytemuck::{Pod, Zeroable};
use clap::{ArgAction, Parser};
use libc::{c_void, iovec};
use log::{error, info, warn};
use vhost::vhost_user::gpu_message::{
    VhostUserGpuCursorPos, VhostUserGpuCursorUpdate, VhostUserGpuDMABUFScanout,
    VhostUserGpuDMABUFScanout2, VhostUserGpuEdidRequest, VhostUserGpuScanout, VhostUserGpuUpdate,
    VirtioGpuRespDisplayInfo, VirtioGpuRespGetEdid,
};
use vhost::vhost_user::message::{VhostUserEmpty, VhostUserMsgValidator};
use vm_memory::ByteValued;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use address_space::AddressSpace;
use machine_manager::config::{
    get_chardev_socket_path, get_pci_df, valid_block_device_virtqueue_size, valid_id,
    ChardevConfig, MAX_VIRTIO_QUEUE,
};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use ui::console::{
    console_close, console_init, display_cursor_define, display_replace_surface, ConsoleType,
    DisplayConsole, DisplayMouse, DisplaySurface,
};
use util::byte_code::ByteCode;
use util::edid::EdidInfo;
use util::gen_base_func;
use util::loop_context::{EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation};
use util::pixman::{pixman_format_bpp, pixman_format_code_t, pixman_image_create_bits};

use crate::vhost::VhostOps;
use crate::VhostUser::client::{
    VhostBackendType, VhostUserClient, VHOST_USER_PROTOCOL_F_CONFIG, VHOST_USER_PROTOCOL_F_MQ,
    VHOST_USER_PROTOCOL_F_REPLY_ACK,
};
use crate::VhostUser::listen_guest_notifier;
use crate::VhostUser::message::{MAX_ATTACHED_FD_ENTRIES, VHOST_USER_F_PROTOCOL_FEATURES};
use crate::{
    check_config_space_rw, read_config_default, virtio_has_feature, GpuOpts, VirtioBase,
    VirtioDevice, VirtioGpuConfig, VirtioGpuOutputState, VirtioInterrupt, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1, VIRTIO_GPU_F_EDID, VIRTIO_GPU_F_MONOCHROME,
    VIRTIO_GPU_F_VIRGL, VIRTIO_GPU_MAX_OUTPUTS, VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
    VIRTIO_GPU_RESP_OK_EDID, VIRTIO_TYPE_GPU,
};
const BYTES_PER_PIXELS: u32 = 8;
const VHOST_USER_GPU_MSG_FLAG_REPLY: u32 = 0x4;
const VHOST_USER_GPU_PROTOCOL_F_EDID: u32 = 0;
const VHOST_USER_GPU_PROTOCOL_F_DMABUF2: u32 = 1;
const VHOST_USER_GPU_CURSOR_SIZE: usize = 64;

static LOG_ONCE: Once = Once::new();

#[repr(transparent)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VhostUserU64 {
    /// The encapsulated 64-bit common value.
    pub value: u64,
}

impl VhostUserU64 {
    pub fn new(value: u64) -> Self {
        VhostUserU64 { value }
    }
}

// SAFETY: Safe because all fields of VhostUserU64 are POD.
unsafe impl ByteValued for VhostUserU64 {}

impl VhostUserMsgValidator for VhostUserU64 {}

#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name = true)]
pub struct VhostUserGpuDevConfig {
    #[arg(long, value_parser = ["vhost-user-gpu-pci"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, alias = "max_outputs", default_value="1", value_parser = clap::value_parser!(u32).range(1..=VIRTIO_GPU_MAX_OUTPUTS as i64))]
    pub max_outputs: u32,
    #[arg(long, default_value="true", action = ArgAction::Append)]
    pub edid: bool,
    #[arg(long, default_value = "1024")]
    pub xres: u32,
    #[arg(long, default_value = "768")]
    pub yres: u32,
    #[arg(long, alias = "num-queues", default_value="2", value_parser = clap::value_parser!(u16).range(1..=MAX_VIRTIO_QUEUE as i64))]
    pub num_queues: Option<u16>,
    #[arg(long)]
    pub chardev: String,
    #[arg(long, alias = "queue-size", default_value = "256", value_parser = valid_block_device_virtqueue_size)]
    pub queue_size: u16,
    #[arg(long, default_value="true", action = ArgAction::Append)]
    pub virgl: bool,
}

pub struct VhostUserGpu {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the gpu device.
    cfg: VhostUserGpuDevConfig,
    /// Configuration of the vhost user gpu's socket chardev.
    chardev_cfg: ChardevConfig,
    /// Config space of the gpu device.
    config_space: Arc<Mutex<VirtioGpuConfig>>,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Vhost user client
    client: Option<Arc<Mutex<VhostUserClient>>>,
    /// Whether irqfd can be used.
    pub enable_irqfd: bool,
    /// Vhost user protocol features.
    protocol_features: u64,
    /// Status of the emulated physical outputs.
    output_states: Arc<Mutex<[VirtioGpuOutputState; VIRTIO_GPU_MAX_OUTPUTS]>>,
    consoles: Vec<Option<Weak<Mutex<DisplayConsole>>>>,
    sender_fd: UnixStream,
    receiver_fd: Arc<Mutex<UnixStream>>,
    pub max_outputs: u32,
}

impl VhostUserGpu {
    pub fn new(
        cfg: &VhostUserGpuDevConfig,
        chardev_cfg: ChardevConfig,
        mem_space: &Arc<AddressSpace>,
    ) -> Result<Self> {
        let queue_num = cfg.num_queues.unwrap_or(1) as usize;
        let queue_size = cfg.queue_size;
        let (sender_fd, receiver_fd) = UnixStream::pair()?;
        let gpu = VhostUserGpu {
            base: VirtioBase::new(VIRTIO_TYPE_GPU, queue_num, queue_size),
            cfg: cfg.clone(),
            chardev_cfg: chardev_cfg.clone(),
            config_space: Default::default(),
            mem_space: mem_space.clone(),
            client: None,
            enable_irqfd: false,
            protocol_features: 0_u64,
            output_states: Default::default(),
            consoles: vec![],
            sender_fd,
            receiver_fd: Arc::new(Mutex::new(receiver_fd)),
            max_outputs: cfg.max_outputs,
        };
        Ok(gpu)
    }

    fn build_device_config_space(&mut self) {
        let mut config_space = self.config_space.lock().unwrap();
        config_space.num_scanouts = self.cfg.max_outputs;
    }

    /// Connect with vug and register update event.
    fn init_client(&mut self) -> Result<()> {
        let socket_path = get_chardev_socket_path(self.chardev_cfg.clone())?;
        let client = VhostUserClient::new(
            &self.mem_space,
            &socket_path,
            self.queue_num() as u64,
            VhostBackendType::TypeGpu,
        )
        .with_context(|| {
            "Failed to create the client which communicates with the server for vhost-user gpu"
        })?;

        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;
        self.client = Some(client);
        Ok(())
    }

    fn init_consoles(&mut self) -> Result<()> {
        if self.cfg.max_outputs > VIRTIO_GPU_MAX_OUTPUTS as u32 {
            bail!(
                "Invalid max_outputs {} which is bigger than {}",
                self.cfg.max_outputs,
                VIRTIO_GPU_MAX_OUTPUTS
            );
        }

        let mut output_states = self.output_states.lock().unwrap();
        output_states[0].width = self.cfg.xres;
        output_states[0].height = self.cfg.yres;

        let gpu_opts = Arc::new(GpuOpts {
            output_states: self.output_states.clone(),
            config_space: self.config_space.clone(),
            interrupt_cb: None,
            enable_bar0: false,
        });
        for i in 0..self.cfg.max_outputs {
            let dev_name = format!("vhost-user-gpu{}", i);
            let con = console_init(dev_name, ConsoleType::Graphic, gpu_opts.clone());
            let con_ref = con.as_ref().unwrap().upgrade().unwrap();
            output_states[i as usize].con_id = con_ref.lock().unwrap().con_id;
            self.consoles.push(con);
        }

        drop(output_states);
        Ok(())
    }
}

impl VirtioDevice for VhostUserGpu {
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

    fn realize(&mut self) -> Result<()> {
        info!("vhost-user-gpu do realize");
        self.init_client()?;
        self.init_consoles()?;
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let locked_client = self.client.as_ref().unwrap().lock().unwrap();
        let features = locked_client
            .get_features()
            .with_context(|| "Failed to get features for vhost-user gpu")?;

        if !virtio_has_feature(features, VHOST_USER_F_PROTOCOL_FEATURES) {
            bail!("Bad vug feature: {:#b}", features);
        }
        let protocol_features = locked_client
            .get_protocol_features()
            .with_context(|| "Failed to get protocol features for vhost-user gpu")?;
        if !virtio_has_feature(protocol_features, u32::from(VHOST_USER_PROTOCOL_F_CONFIG)) {
            bail!(
                "Failed to get protocol features, config doesn't support, protocol features: {:#b}",
                protocol_features
            );
        }
        let supported_protocol_features = (1 << VHOST_USER_PROTOCOL_F_MQ)
            | (1 << VHOST_USER_PROTOCOL_F_CONFIG)
            | (1 << VHOST_USER_PROTOCOL_F_REPLY_ACK);
        self.protocol_features = supported_protocol_features & protocol_features;
        locked_client
            .set_protocol_features(self.protocol_features)
            .with_context(|| "Failed to set protocol features for vhost-user gpu")?;

        let config = locked_client
            .get_virtio_config::<VirtioGpuConfig>()
            .with_context(|| "Failed to get config for vhost-user gpu")?;
        let mut config_space = self.config_space.lock().unwrap();
        *config_space = config;
        drop(config_space);

        if virtio_has_feature(protocol_features, u32::from(VHOST_USER_PROTOCOL_F_MQ)) {
            let max_queue_num = locked_client
                .get_max_queue_num()
                .with_context(|| "Failed to get queue num for vhost-user gpu")?;
            if self.queue_num() > max_queue_num as usize {
                bail!(
                    "Exceed the max queue num that vug supported ({} queues)",
                    max_queue_num
                );
            }
        } else if self.cfg.num_queues.unwrap_or(1) > 1 {
            bail!(
                "vug doesn't support multi queue, vug protocol features: {:#b}",
                protocol_features
            );
        }
        drop(locked_client);

        self.base.device_features = (1_u64 << VIRTIO_GPU_F_EDID)
            | (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_F_RING_INDIRECT_DESC)
            | (1u64 << VIRTIO_F_RING_EVENT_IDX)
            | (1u64 << VIRTIO_GPU_F_MONOCHROME);
        if self.cfg.virgl {
            self.base.device_features |= 1_u64 << VIRTIO_GPU_F_VIRGL;
            // TODO. VIRTIO_GPU_F_RESOURCE_BLOB not support now.
            // self.base.device_features |= (1_u64 << VIRTIO_GPU_F_RESOURCE_BLOB);
        }

        self.base.device_features &= features;

        self.build_device_config_space();
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let config_space = self.config_space.lock().unwrap();
        read_config_default(config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let mut config_space = self.config_space.lock().unwrap();
        check_config_space_rw(config_space.as_bytes(), offset, data)?;

        let offset = offset as usize;
        let end = offset + data.len();
        let config_slice = config_space.as_mut_bytes();
        config_slice[offset..end].copy_from_slice(data);

        if config_space.events_clear > 0 {
            config_space.events_read &= !config_space.events_clear;
        }

        self.client
            .as_ref()
            .with_context(|| "Failed to get client when writing config")?
            .lock()
            .unwrap()
            .set_virtio_config(*config_space)
            .with_context(|| "Failed to set config for vhost-user gpu")?;

        Ok(())
    }

    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        info!("vhost-user-gpu do activate");
        let mut client = self.client.as_ref().unwrap().lock().unwrap();
        // Add VHOST_USER_F_PROTOCOL_FEATURES bit for enabling protocol features.
        client.features = self.base.driver_features | (1 << VHOST_USER_F_PROTOCOL_FEATURES);
        client.protocol_features = self.protocol_features;
        client.set_queues(&self.base.queues);
        client.set_queue_evts(&queue_evts);

        if !self.enable_irqfd {
            let queue_num = self.base.queues.len();
            listen_guest_notifier(
                &mut self.base,
                &mut client,
                None,
                queue_num,
                interrupt_cb.clone(),
            )?;
        }

        client.activate_vhost_user()?;
        client.set_socket(&self.sender_fd)?;

        let mut scanouts = vec![];
        let gpu_opts = Arc::new(GpuOpts {
            output_states: self.output_states.clone(),
            config_space: self.config_space.clone(),
            interrupt_cb: Some(interrupt_cb),
            enable_bar0: false,
        });
        for con in &self.consoles {
            let con_ref = con.as_ref().unwrap().upgrade().unwrap();
            con_ref.lock().unwrap().dev_opts = gpu_opts.clone();

            let scanout = VUGpuScanout {
                con: con.clone(),
                ..Default::default()
            };
            scanouts.push(scanout);
        }

        let handler = VhostUserGpuProcessor::new(
            self.receiver_fd.clone(),
            self.max_outputs,
            self.output_states.clone(),
            scanouts,
        );
        let notifiers = VhostUserGpuProcessor::internal_notifiers(Arc::new(Mutex::new(handler)));
        register_event_helper(notifiers, None, &mut self.base.deactivate_evts)?;
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        info!("vhost-user-gpu do deactivate");
        self.client
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .reset_vhost_user(true);
        unregister_event_helper(None, &mut self.base.deactivate_evts)?;
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        info!("vhost-user-gpu do unrealize");
        self.client
            .as_ref()
            .with_context(|| "Failed to get client when stopping event")?
            .lock()
            .unwrap()
            .delete_event()
            .with_context(|| "Failed to delete vhost-user gpu event")?;
        self.client = None;

        for con in &self.consoles {
            console_close(con)?;
        }
        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        info!("vhost-user-gpu do set_guest_notifiers");
        self.enable_irqfd = true;
        self.client
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .set_call_events(queue_evts);
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        info!("vhost-user-gpu do reset");
        self.enable_irqfd = false;
        Ok(())
    }
}

pub const VHOST_USER_GPU_GET_PROTOCOL_FEATURES: u32 = 1;
pub const VHOST_USER_GPU_SET_PROTOCOL_FEATURES: u32 = 2;
pub const VHOST_USER_GPU_GET_DISPLAY_INFO: u32 = 3;
pub const VHOST_USER_GPU_CURSOR_POS: u32 = 4;
pub const VHOST_USER_GPU_CURSOR_POS_HIDE: u32 = 5;
pub const VHOST_USER_GPU_CURSOR_UPDATE: u32 = 6;
pub const VHOST_USER_GPU_SCANOUT: u32 = 7;
pub const VHOST_USER_GPU_UPDATE: u32 = 8;
pub const VHOST_USER_GPU_DMABUF_SCANOUT: u32 = 9;
pub const VHOST_USER_GPU_DMABUF_UPDATE: u32 = 10;
pub const VHOST_USER_GPU_GET_EDID: u32 = 11;
pub const VHOST_USER_GPU_DMABUF_SCANOUT2: u32 = 12;

pub fn vhost_user_gpu_get_request_type_string(request: u32) -> &'static str {
    match request {
        VHOST_USER_GPU_GET_PROTOCOL_FEATURES => "VHOST_USER_GPU_GET_PROTOCOL_FEATURES",
        VHOST_USER_GPU_SET_PROTOCOL_FEATURES => "VHOST_USER_GPU_SET_PROTOCOL_FEATURES",
        VHOST_USER_GPU_GET_DISPLAY_INFO => "VHOST_USER_GPU_GET_DISPLAY_INFO",
        VHOST_USER_GPU_CURSOR_POS => "VHOST_USER_GPU_CURSOR_POS",
        VHOST_USER_GPU_CURSOR_POS_HIDE => "VHOST_USER_GPU_CURSOR_POS_HIDE",
        VHOST_USER_GPU_CURSOR_UPDATE => "VHOST_USER_GPU_CURSOR_UPDATE",
        VHOST_USER_GPU_SCANOUT => "VHOST_USER_GPU_SCANOUT",
        VHOST_USER_GPU_UPDATE => "VHOST_USER_GPU_UPDATE",
        VHOST_USER_GPU_DMABUF_SCANOUT => "VHOST_USER_GPU_DMABUF_SCANOUT",
        VHOST_USER_GPU_DMABUF_UPDATE => "VHOST_USER_GPU_DMABUF_UPDATE",
        VHOST_USER_GPU_GET_EDID => "VHOST_USER_GPU_GET_EDID",
        VHOST_USER_GPU_DMABUF_SCANOUT2 => "VHOST_USER_GPU_DMABUF_SCANOUT2",
        _ => "invalid request type",
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone, Debug, Pod, Zeroable)]
pub struct VhostUserGpuMsgHdr {
    /// The request id for vhost-user-gpu message
    pub request: u32,
    /// The flags for property setting
    pub flags: u32,
    /// The total length of vhost-user-gpu message
    pub size: u32,
}

#[derive(Default, Clone)]
pub struct VUGpuScanout {
    con: Option<Weak<Mutex<DisplayConsole>>>,
    dmabuf_info: Option<VhostUserGpuDMABUFScanout>,
    modifier: Option<u64>,
    fd: Option<Arc<File>>,
    mouse: Option<DisplayMouse>,
    cursor_visible: bool,
    width: u32,
    height: u32,
}

#[derive(Clone)]
struct VhostUserGpuProcessor {
    pub receiver_fd: Arc<Mutex<UnixStream>>,
    /// The number of scanouts
    max_outputs: u32,
    /// The bit mask of whether scanout is enabled or not.
    enable_output_bitmask: u32,
    /// States of all output_states.
    output_states: Arc<Mutex<[VirtioGpuOutputState; VIRTIO_GPU_MAX_OUTPUTS]>>,
    /// Scanouts of gpu, mouse doesn't realize copy trait, so it is a vector.
    scanouts: Vec<VUGpuScanout>,
    /// pixman_image buffer.
    ram: Vec<u32>,
}

// SAFETY: Logically the VhostUserGpuProcessor structure will not be used
// in multiple threads at the same time
unsafe impl Sync for VhostUserGpuProcessor {}
// SAFETY: Same as above
unsafe impl Send for VhostUserGpuProcessor {}

impl EventNotifierHelper for VhostUserGpuProcessor {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let handler_raw = handler.lock().unwrap();
        let mut notifiers = Vec::new();

        // Register event notifier for ctrl_queue_evt.
        let handler_clone = handler.clone();
        let h: Rc<NotifierCallback> = Rc::new(move |_, _fd: RawFd| {
            if let Err(e) = handler_clone.lock().unwrap().process_cmd() {
                error!("Failed to process ctrlq for virtio gpu, err: {:?}", e);
            }
            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            handler_raw.receiver_fd.lock().unwrap().as_raw_fd(),
            None,
            EventSet::IN,
            vec![h],
        ));
        notifiers
    }
}

impl VhostUserGpuProcessor {
    fn new(
        receiver_fd: Arc<Mutex<UnixStream>>,
        max_outputs: u32,
        output_states: Arc<Mutex<[VirtioGpuOutputState; VIRTIO_GPU_MAX_OUTPUTS]>>,
        scanouts: Vec<VUGpuScanout>,
    ) -> Self {
        Self {
            receiver_fd,
            max_outputs,
            enable_output_bitmask: 1,
            output_states,
            scanouts,
            ram: vec![0; 256 * 1024 * 1024],
        }
    }

    pub fn recv_header(&mut self) -> Result<(VhostUserGpuMsgHdr, Option<Vec<File>>)> {
        let mut hdr = VhostUserGpuMsgHdr::default();
        let mut fd_array = vec![0; MAX_ATTACHED_FD_ENTRIES];
        let hdr_len = size_of::<VhostUserGpuMsgHdr>();
        let mut iovs = [iovec {
            iov_base: (&mut hdr as *mut VhostUserGpuMsgHdr) as *mut c_void,
            iov_len: hdr_len,
        }];
        let stream: std::sync::MutexGuard<'_, UnixStream> = self.receiver_fd.lock().unwrap();
        // SAFETY: `iovs` and `fd_array` has enough buffer size to recv message.
        let (bytes, fds) = unsafe { stream.recv_with_fds(&mut iovs, &mut fd_array)? };
        if bytes != hdr_len {
            bail! {"recv_header fail. expect len {}, recv len {}",hdr_len, bytes };
        }
        let files = match fds {
            0 => None,
            n => {
                let files = fd_array
                    .iter()
                    .take(n)
                    .map(|fd| {
                        // SAFETY: because we have the ownership of `fd`.
                        unsafe { File::from_raw_fd(*fd) }
                    })
                    .collect();
                Some(files)
            }
        };
        Ok((hdr, files))
    }

    pub fn recv_data(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut rbuf = vec![0u8; len];
        let mut stream: std::sync::MutexGuard<'_, UnixStream> = self.receiver_fd.lock().unwrap();
        stream.read_exact(&mut rbuf)?;
        Ok(rbuf)
    }

    fn check_attached_files(
        &self,
        hdr: &VhostUserGpuMsgHdr,
        files: &Option<Vec<File>>,
    ) -> Result<()> {
        match hdr.request {
            VHOST_USER_GPU_DMABUF_SCANOUT | VHOST_USER_GPU_DMABUF_SCANOUT2 => {
                if files.is_none() {
                    bail!("check_attached_files. file is none.")
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn take_single_file(&self, files: Option<Vec<File>>) -> Option<File> {
        let mut files = files?;
        if files.len() != 1 {
            return None;
        }
        Some(files.swap_remove(0))
    }

    fn check_request_size(&self, hdr: &VhostUserGpuMsgHdr, expected: u32) -> Result<()> {
        if hdr.size != expected {
            bail!(
                "check_request_size check fail. hdr.size:{},  expected:{}",
                hdr.size,
                expected
            );
        }
        Ok(())
    }

    fn extract_request_body<T: Sized + VhostUserMsgValidator + Debug>(
        &self,
        buf: &[u8],
    ) -> Result<T> {
        let size = size_of::<T>();
        if size > buf.len() {
            bail!(
                "extract_request_body. invalid cmd buf. expect size:{},  buflen:{}",
                size,
                buf.len()
            );
        }
        // SAFETY: Safe because we checked that `buf` size is not smaller than T size.
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };
        // info!("msg: {:?}", msg);
        if !msg.is_valid() {
            bail!("InvalidMessage");
        }
        Ok(msg)
    }

    fn vhost_user_gpu_send_msg(
        &mut self,
        hdr_rsp: &VhostUserGpuMsgHdr,
        payload: &[u8],
    ) -> Result<()> {
        self.check_request_size(hdr_rsp, payload.len() as u32)?;
        let hdr = bytemuck::bytes_of(hdr_rsp);
        let mut stream = self.receiver_fd.lock().unwrap();
        let mut buf = Vec::with_capacity(hdr.len() + payload.len());
        buf.extend_from_slice(hdr);
        buf.extend_from_slice(payload);
        stream.write_all(&buf)?;
        Ok(())
    }

    fn send_reply_message<T: ByteValued>(
        &mut self,
        hdr: &VhostUserGpuMsgHdr,
        msg: &T,
    ) -> Result<()> {
        let hdr_rsp = VhostUserGpuMsgHdr {
            request: hdr.request,
            flags: hdr.flags,
            size: size_of::<T>() as u32,
        };

        let payload = msg.as_slice();
        self.vhost_user_gpu_send_msg(&hdr_rsp, payload)?;
        Ok(())
    }

    fn check_scanout_id_is_valid(&self, scanout_id: u32) -> Result<()> {
        if scanout_id >= self.max_outputs {
            bail!(
                "GuestError: The scanouts {} of request exceeds the max_outputs {}.",
                scanout_id,
                self.max_outputs
            );
        }
        Ok(())
    }

    fn cmd_get_protocol_features(&mut self, hdr: &VhostUserGpuMsgHdr) -> Result<()> {
        let reply = VhostUserGpuMsgHdr {
            request: hdr.request,
            flags: VHOST_USER_GPU_MSG_FLAG_REPLY,
            size: size_of::<u64>() as u32,
        };

        let protocol_features: VhostUserU64 = VhostUserU64::new(
            (1 << VHOST_USER_GPU_PROTOCOL_F_EDID) | (1 << VHOST_USER_GPU_PROTOCOL_F_DMABUF2),
        );
        self.send_reply_message(&reply, &protocol_features)
    }

    fn cmd_set_protocol_features(
        &mut self,
        _hdr: &VhostUserGpuMsgHdr,
        _u64: &VhostUserU64,
    ) -> Result<()> {
        // do nothing
        Ok(())
    }

    fn cmd_get_display_info(&mut self, hdr: &VhostUserGpuMsgHdr) -> Result<()> {
        let reply = VhostUserGpuMsgHdr {
            request: hdr.request,
            flags: VHOST_USER_GPU_MSG_FLAG_REPLY,
            size: size_of::<VirtioGpuRespDisplayInfo>() as u32,
        };
        let mut display_info = VirtioGpuRespDisplayInfo::default();
        display_info.hdr.type_ = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;
        let output_states = self.output_states.lock().unwrap();
        for i in 0..self.max_outputs {
            if (self.enable_output_bitmask & (1 << i)) != 0 {
                let i = i as usize;
                display_info.pmodes[i].enabled = 1;
                display_info.pmodes[i].r.width = output_states[i].width;
                display_info.pmodes[i].r.height = output_states[i].height;
                display_info.pmodes[i].flags = 0;
            }
        }
        drop(output_states);
        self.send_reply_message(&reply, &display_info)
    }

    fn cmd_cursor_pos(
        &mut self,
        _hdr: &VhostUserGpuMsgHdr,
        _cursor_pos: &VhostUserGpuCursorPos,
    ) -> Result<()> {
        // do notiong
        Ok(())
    }

    fn cmd_cursor_pos_hide(
        &mut self,
        _hdr: &VhostUserGpuMsgHdr,
        cursor_pos: &VhostUserGpuCursorPos,
    ) -> Result<()> {
        self.check_scanout_id_is_valid(cursor_pos.scanout_id)
            .with_context(|| "cmd_cursor_pos_hide. invalid scanout_id")?;

        let scanout = &mut self.scanouts[cursor_pos.scanout_id as usize];
        if !scanout.cursor_visible || scanout.mouse.is_none() {
            return Ok(());
        }

        let data = &mut scanout.mouse.as_mut().unwrap().data;
        // In order to improve performance, displaying cursor by virtio-gpu.
        // But we have to displaying it in guest img if virtio-gpu can't do display job.
        // In this case, to avoid overlapping displaying two cursor imgs, change
        // cursor (render by virtio-gpu) color to transparent.
        //
        // Only A or X byte in RGBA\X needs to be set.
        // We sure that the data is assembled in format like RGBA and the minimum unit
        // is byte, so there is no size end problem.
        for (i, item) in data.iter_mut().enumerate() {
            if i % 4 == 3 {
                *item = 0_u8;
            }
        }
        display_cursor_define(&scanout.con, scanout.mouse.as_ref().unwrap())?;
        scanout.cursor_visible = false;

        Ok(())
    }

    fn cmd_cursor_update(
        &mut self,
        _hdr: &VhostUserGpuMsgHdr,
        msg: &VhostUserGpuCursorUpdate,
        image: &[u8],
    ) -> Result<()> {
        self.check_scanout_id_is_valid(msg.pos.scanout_id)
            .with_context(|| "cmd_cursor_pos_hide. invalid scanout_id")?;

        let scanout = &mut self.scanouts[msg.pos.scanout_id as usize];
        match &mut scanout.mouse {
            None => {
                let mouse = DisplayMouse::new(
                    VHOST_USER_GPU_CURSOR_SIZE as u32,
                    VHOST_USER_GPU_CURSOR_SIZE as u32,
                    msg.hot_x,
                    msg.hot_y,
                );
                scanout.mouse = Some(mouse);
            }
            Some(mouse) => {
                mouse.hot_x = msg.hot_x;
                mouse.hot_y = msg.hot_y;
            }
        }

        if image.len() > scanout.mouse.as_ref().unwrap().data.len() {
            bail!(
                "image buffer size:{} is lager than data buffer:{}",
                image.len(),
                scanout.mouse.as_ref().unwrap().data.len()
            );
        }
        // SAFETY: the length of the source and dest pointers can be ensured to be same
        unsafe {
            ptr::copy(
                image.as_ptr(),
                scanout.mouse.as_mut().unwrap().data.as_mut_ptr(),
                image.len(),
            );
        }
        let scanout = &mut self.scanouts[msg.pos.scanout_id as usize];
        display_cursor_define(&scanout.con, scanout.mouse.as_ref().unwrap())?;
        scanout.cursor_visible = true;
        Ok(())
    }

    fn cmd_set_scanout(
        &mut self,
        _hdr: &VhostUserGpuMsgHdr,
        _msg: &VhostUserGpuScanout,
    ) -> Result<()> {
        // todo rjf
        Ok(())
    }

    fn get_image_len(&mut self, hdr: &VhostUserGpuMsgHdr, msg_size: usize) -> Result<usize> {
        if hdr.size < msg_size as u32 {
            bail!(
                "invalid image buf. msg body size is {}, expected at least {}",
                hdr.size,
                msg_size
            );
        }

        let image_size = hdr.size as usize - msg_size;
        if !image_size.is_multiple_of(4) {
            bail!("invalid image buf. image_size is {}", image_size);
        }
        Ok(image_size)
    }
    fn cmd_update(
        &mut self,
        _hdr: &VhostUserGpuMsgHdr,
        _msg: &VhostUserGpuUpdate,
        _image: &[u8],
    ) -> Result<()> {
        // todo rjf
        Ok(())
    }

    fn create_surface(&mut self, width: u32, height: u32) -> Result<DisplaySurface> {
        let format: pixman_format_code_t = pixman_format_code_t::PIXMAN_x8r8g8b8;
        let linesize = width
            * pixman_format_bpp(pixman_format_code_t::PIXMAN_x8r8g8b8 as u32) as u32
            / BYTES_PER_PIXELS;
        let stride = linesize;
        let required_size = u64::from(width)
            .checked_mul(u64::from(height))
            .and_then(|v| v.checked_mul(4))
            .ok_or_else(|| anyhow::anyhow!("invalid surface size"))?;
        if (self.ram.len() as u64) < required_size {
            bail!("ram size is not enough");
        }
        let mut ds = DisplaySurface {
            format,
            ..Default::default()
        };
        // SAFETY: width, height and vram_ptr have been checked
        unsafe {
            ds.image = pixman_image_create_bits(
                format,
                width as i32,
                height as i32,
                self.ram.as_mut_ptr(),
                stride as i32,
            );
        }

        if ds.image.is_null() {
            error!("Failed to create the surface of dxvk");
            return Err(anyhow!("Failed to create pixman image"));
        }
        Ok(ds)
    }

    fn cmd_set_dmabuf_scanout(
        &mut self,
        _hdr: &VhostUserGpuMsgHdr,
        msg: &VhostUserGpuDMABUFScanout,
        files: Option<Vec<File>>,
    ) -> Result<()> {
        self.check_scanout_id_is_valid(msg.scanout_id)
            .with_context(|| "cmd_set_dmabuf_scanout. invalid scanout_id")?;
        if (msg.width != self.scanouts[msg.scanout_id as usize].width)
            || (msg.height != self.scanouts[msg.scanout_id as usize].height)
        {
            self.scanouts[msg.scanout_id as usize].width = msg.width;
            self.scanouts[msg.scanout_id as usize].height = msg.height;
            let surface = self.create_surface(msg.width, msg.height)?;
            display_replace_surface(
                &self.scanouts[msg.scanout_id as usize].con.clone(),
                Some(surface),
            )?;
        }
        self.scanouts[msg.scanout_id as usize].fd = self.take_single_file(files).map(Arc::new);
        self.scanouts[msg.scanout_id as usize].dmabuf_info = Some(*msg);
        self.scanouts[msg.scanout_id as usize].modifier = None;
        let mut output_states = self.output_states.lock().unwrap();
        output_states[msg.scanout_id as usize].width = msg.width;
        output_states[msg.scanout_id as usize].height = msg.height;
        Ok(())
    }

    fn cmd_set_dmabuf_scanout2(
        &mut self,
        hdr: &VhostUserGpuMsgHdr,
        msg: &VhostUserGpuDMABUFScanout2,
        files: Option<Vec<File>>,
    ) -> Result<()> {
        self.check_scanout_id_is_valid(msg.dmabuf_scanout.scanout_id)
            .with_context(|| "cmd_set_dmabuf_scanout2. invalid scanout_id")?;
        self.scanouts[msg.dmabuf_scanout.scanout_id as usize].modifier = Some(msg.modifier);
        // SAFETY: Safe because we have checked msg size before.
        let dmabuf_scanout_msg = unsafe { ptr::read_unaligned(ptr::addr_of!(msg.dmabuf_scanout)) };
        self.cmd_set_dmabuf_scanout(hdr, &dmabuf_scanout_msg, files)
    }

    fn cmd_dmabuf_update(
        &mut self,
        hdr: &VhostUserGpuMsgHdr,
        _msg: &VhostUserGpuUpdate,
    ) -> Result<()> {
        let reply = VhostUserGpuMsgHdr {
            request: hdr.request,
            flags: VHOST_USER_GPU_MSG_FLAG_REPLY,
            size: size_of::<VirtioGpuRespGetEdid>() as u32,
        };
        self.send_reply_message(&reply, &VhostUserEmpty)
    }

    fn cmd_get_edid(
        &mut self,
        hdr: &VhostUserGpuMsgHdr,
        msg: &VhostUserGpuEdidRequest,
    ) -> Result<()> {
        self.check_scanout_id_is_valid(msg.scanout_id)
            .with_context(|| "cmd_get_edid. invalid scanout_id")?;

        let reply = VhostUserGpuMsgHdr {
            request: hdr.request,
            flags: VHOST_USER_GPU_MSG_FLAG_REPLY,
            size: size_of::<VirtioGpuRespGetEdid>() as u32,
        };
        let mut edid = VirtioGpuRespGetEdid::default();
        edid.hdr.type_ = VIRTIO_GPU_RESP_OK_EDID;
        edid.size = size_of_val(&edid.edid) as u32;
        let output_states = self
            .output_states
            .lock()
            .expect("Failed to lock output_states");
        let mut edid_info = EdidInfo::new(
            "HWV",
            "STRA Monitor",
            100,
            output_states[msg.scanout_id as usize].width,
            output_states[msg.scanout_id as usize].height,
        );
        drop(output_states);
        edid_info.edid_array_fulfill(&mut edid.edid);

        self.send_reply_message(&reply, &edid)
    }

    pub fn process_cmd(&mut self) -> Result<()> {
        let (hdr, files) = self.recv_header()?;

        let buf = match hdr.size {
            0 => vec![0u8; 0],
            len => match self.recv_data(len as usize) {
                Ok(buf) => buf,
                Err(e) => bail!("InvalidMessage. {:?}", e),
            },
        };

        if let Err(_e) = self.check_attached_files(&hdr, &files) {
            // do nothing. dmabuf not support now
            LOG_ONCE.call_once(|| {
                warn!("vhost-user-gpu. dmabuf not support now");
            });
        }

        if let Err(e) = match hdr.request {
            VHOST_USER_GPU_GET_PROTOCOL_FEATURES => {
                self.check_request_size(&hdr, 0_u32)?;
                self.cmd_get_protocol_features(&hdr)
            }
            VHOST_USER_GPU_SET_PROTOCOL_FEATURES => {
                let msg = self.extract_request_body::<VhostUserU64>(&buf)?;
                self.cmd_set_protocol_features(&hdr, &msg)
            }
            VHOST_USER_GPU_GET_DISPLAY_INFO => self.cmd_get_display_info(&hdr),
            VHOST_USER_GPU_CURSOR_POS => {
                let msg = self.extract_request_body::<VhostUserGpuCursorPos>(&buf)?;
                self.cmd_cursor_pos(&hdr, &msg)
            }
            VHOST_USER_GPU_CURSOR_POS_HIDE => {
                let msg = self.extract_request_body::<VhostUserGpuCursorPos>(&buf)?;
                self.cmd_cursor_pos_hide(&hdr, &msg)
            }
            VHOST_USER_GPU_CURSOR_UPDATE => {
                let msg_size = size_of::<VhostUserGpuCursorUpdate>();
                let image_size = self.get_image_len(&hdr, msg_size)?;
                let msg = self.extract_request_body::<VhostUserGpuCursorUpdate>(&buf)?;
                // SAFETY: Safe because we checked that `buf` size is not smaller than image_size size.
                let image = unsafe { from_raw_parts(buf.as_ptr().add(msg_size), image_size) };
                self.cmd_cursor_update(&hdr, &msg, image)
            }
            VHOST_USER_GPU_SCANOUT => {
                let msg = self.extract_request_body::<VhostUserGpuScanout>(&buf)?;
                self.cmd_set_scanout(&hdr, &msg)
            }
            VHOST_USER_GPU_UPDATE => {
                let msg_size = size_of::<VhostUserGpuUpdate>();
                let image_size = self.get_image_len(&hdr, msg_size)?;
                let msg = self.extract_request_body::<VhostUserGpuUpdate>(&buf)?;
                // SAFETY: Safe because we checked that `buf` size is not smaller than image_size size.
                let image = unsafe { from_raw_parts(buf.as_ptr().add(msg_size), image_size) };
                self.cmd_update(&hdr, &msg, image)
            }
            VHOST_USER_GPU_DMABUF_SCANOUT => {
                let msg = self.extract_request_body::<VhostUserGpuDMABUFScanout>(&buf)?;
                self.cmd_set_dmabuf_scanout(&hdr, &msg, files)
            }
            VHOST_USER_GPU_DMABUF_SCANOUT2 => {
                let msg = self.extract_request_body::<VhostUserGpuDMABUFScanout2>(&buf)?;
                self.cmd_set_dmabuf_scanout2(&hdr, &msg, files)
            }
            VHOST_USER_GPU_DMABUF_UPDATE => {
                let msg = self.extract_request_body::<VhostUserGpuUpdate>(&buf)?;
                self.cmd_dmabuf_update(&hdr, &msg)
            }
            VHOST_USER_GPU_GET_EDID => {
                let msg = self.extract_request_body::<VhostUserGpuEdidRequest>(&buf)?;
                self.cmd_get_edid(&hdr, &msg)
            }
            _ => Err::<(), anyhow::Error>(anyhow!(
                "Failed to process unsupported command: {}",
                hdr.request
            )),
        } {
            bail!(
                "process_gpu_request error, request:{:?}, {:?}",
                vhost_user_gpu_get_request_type_string(hdr.request),
                e
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use vhost::vhost_user::{
        gpu_message::{VhostUserGpuCursorPos, VhostUserGpuEdidRequest, VirtioGpuRect},
        message::VhostUserU64 as VhostUserU64Test,
        GpuBackend,
    };

    use super::*;
    use machine_manager::config::str_slip_to_clap;

    const DEFAULT_WIDTH: u32 = 1024;
    const DEFAULT_HEIGHT: u32 = 768;

    #[cfg(test)]
    fn init_test() -> (VhostUserGpuProcessor, GpuBackend) {
        let output_states: Arc<Mutex<[VirtioGpuOutputState; VIRTIO_GPU_MAX_OUTPUTS]>> =
            Default::default();
        let mut output_states_temp = output_states.lock().unwrap();
        output_states_temp[0].width = DEFAULT_WIDTH;
        output_states_temp[0].height = DEFAULT_HEIGHT;
        drop(output_states_temp);

        let socket = UnixStream::pair();
        assert!(socket.is_ok());
        let (sender_fd, receiver_fd) = socket.unwrap();

        let mut scanouts = vec![];
        let scanout = VUGpuScanout {
            con: None,
            ..Default::default()
        };
        scanouts.push(scanout);

        let handler = VhostUserGpuProcessor::new(
            Arc::new(Mutex::new(receiver_fd)),
            1,
            output_states,
            scanouts,
        );
        let backend = GpuBackend::from_stream(sender_fd);
        (handler, backend)
    }

    #[test]
    fn test_vhost_user_gpu_pci_parse_cmdline() {
        // Test0: Right.
        let gpu_cmd = "vhost-user-gpu-pci,id=vhost-user-gpu-id,bus=pcie.0,addr=0x4.0x0,xres=2160,yres=1440,chardev=vhost-user-gpu,virgl=true";
        let gpu_cfg =
            VhostUserGpuDevConfig::try_parse_from(str_slip_to_clap(gpu_cmd, true, false)).unwrap();
        assert_eq!(gpu_cfg.classtype, "vhost-user-gpu-pci");
        assert_eq!(gpu_cfg.id, "vhost-user-gpu-id");
        assert_eq!(gpu_cfg.bus, Some("pcie.0".to_string()));
        assert_eq!(gpu_cfg.addr, Some((4, 0)));
        assert_eq!(gpu_cfg.max_outputs, 1);
        assert_eq!(gpu_cfg.edid, true);
        assert_eq!(gpu_cfg.xres, 2160);
        assert_eq!(gpu_cfg.yres, 1440);
        assert_eq!(gpu_cfg.num_queues, Some(2));
        assert_eq!(gpu_cfg.chardev, "vhost-user-gpu");
        assert_eq!(gpu_cfg.queue_size, 256);
        assert_eq!(gpu_cfg.virgl, true);
        println!("parse success");

        // Test1: Right.
        let gpu_cmd1 = "vhost-user-gpu-pci,id=vhost-user-gpu-id,bus=pcie.0,addr=0x4.0x0,xres=2160,yres=1440,max_outputs=13,edid=false,num-queues=3,queue-size=512,chardev=vhost-user-gpu,virgl=false";
        let gpu_cfg =
            VhostUserGpuDevConfig::try_parse_from(str_slip_to_clap(gpu_cmd1, true, false)).unwrap();
        assert_eq!(gpu_cfg.classtype, "vhost-user-gpu-pci");
        assert_eq!(gpu_cfg.id, "vhost-user-gpu-id");
        assert_eq!(gpu_cfg.bus, Some("pcie.0".to_string()));
        assert_eq!(gpu_cfg.addr, Some((4, 0)));
        assert_eq!(gpu_cfg.max_outputs, 13);
        assert_eq!(gpu_cfg.edid, false);
        assert_eq!(gpu_cfg.xres, 2160);
        assert_eq!(gpu_cfg.yres, 1440);
        assert_eq!(gpu_cfg.num_queues, Some(3));
        assert_eq!(gpu_cfg.chardev, "vhost-user-gpu");
        assert_eq!(gpu_cfg.queue_size, 512);
        assert_eq!(gpu_cfg.virgl, false);

        // Test2: Default.
        let gpu_cmd2 = "vhost-user-gpu-pci,id=vhost-user-gpu-id,bus=pcie.0,addr=0x3.0x0,chardev=vhost-user-gpu";
        let gpu_cfg =
            VhostUserGpuDevConfig::try_parse_from(str_slip_to_clap(gpu_cmd2, true, false)).unwrap();
        assert_eq!(gpu_cfg.classtype, "vhost-user-gpu-pci");
        assert_eq!(gpu_cfg.id, "vhost-user-gpu-id");
        assert_eq!(gpu_cfg.bus, Some("pcie.0".to_string()));
        assert_eq!(gpu_cfg.addr, Some((3, 0)));
        assert_eq!(gpu_cfg.max_outputs, 1);
        assert_eq!(gpu_cfg.edid, true);
        assert_eq!(gpu_cfg.xres, 1024);
        assert_eq!(gpu_cfg.yres, 768);
        assert_eq!(gpu_cfg.num_queues, Some(2));
        assert_eq!(gpu_cfg.chardev, "vhost-user-gpu");
        assert_eq!(gpu_cfg.queue_size, 256);
        assert_eq!(gpu_cfg.virgl, true);

        // Test3/4: max_outputs is illegal.
        let gpu_cmd3 = "vhost-user-gpu-pci,id=gpu_1,bus=pcie.0,addr=0x4.0x0,max_outputs=17";
        let result = VhostUserGpuDevConfig::try_parse_from(str_slip_to_clap(gpu_cmd3, true, false));
        assert!(result.is_err());
        let gpu_cmd4 = "vhost-user-gpu-pci,id=gpu_1,bus=pcie.0,addr=0x4.0x0,max_outputs=0";
        let result = VhostUserGpuDevConfig::try_parse_from(str_slip_to_clap(gpu_cmd4, true, false));
        assert!(result.is_err());

        // Test5: queue_size is illegal.
        let gpu_cmd5 = "vhost-user-gpu-pci,id=gpu_1,bus=pcie.0,addr=0x4.0x0,queue_size=1025";
        let result = VhostUserGpuDevConfig::try_parse_from(str_slip_to_clap(gpu_cmd5, true, false));
        assert!(result.is_err());
    }

    #[test]
    fn test_vhost_user_gpu_pci_get_protocol_features() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(VhostUserU64Test::new(0)));
        let response_cloned = response.clone();
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = backend.get_protocol_features().unwrap();
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        let expected_value: VhostUserU64Test = VhostUserU64Test::new(
            (1 << VHOST_USER_GPU_PROTOCOL_F_EDID) | (1 << VHOST_USER_GPU_PROTOCOL_F_DMABUF2),
        );
        assert_eq!(response.lock().unwrap().value, expected_value.value);
    }

    #[test]
    fn test_vhost_user_gpu_pci_set_protocol_features() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let set_value: VhostUserU64Test = VhostUserU64Test::new(
            (1 << VHOST_USER_GPU_PROTOCOL_F_EDID) | (1 << VHOST_USER_GPU_PROTOCOL_F_DMABUF2),
        );
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.set_protocol_features(&set_value));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());
    }

    #[test]
    fn test_vhost_user_gpu_pci_get_display_info() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(VirtioGpuRespDisplayInfo::default()));
        let response_cloned = response.clone();
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = backend.get_display_info().unwrap();
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        let resp = response.lock().unwrap();
        let expect_rect = VirtioGpuRect {
            x: 0,
            y: 0,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
        };
        assert_eq!(resp.pmodes[0].r, expect_rect);
        assert_eq!(resp.pmodes[0].enabled, 1);
        assert_eq!(resp.pmodes[0].flags, 0);
    }

    #[test]
    fn test_vhost_user_gpu_pci_cursor_pos() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let cursor_pos: VhostUserGpuCursorPos = VhostUserGpuCursorPos {
            scanout_id: 0,
            x: DEFAULT_WIDTH,
            y: DEFAULT_HEIGHT,
        };
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.cursor_pos(&cursor_pos));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());
    }

    #[test]
    fn test_vhost_user_gpu_pci_cursor_pos_hide() {
        let (mut handler, backend) = init_test();
        // valid scanout_id
        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let cursor_pos: VhostUserGpuCursorPos = VhostUserGpuCursorPos {
            scanout_id: 0,
            x: DEFAULT_WIDTH,
            y: DEFAULT_HEIGHT,
        };
        let cursor_update: VhostUserGpuCursorUpdate = VhostUserGpuCursorUpdate {
            pos: cursor_pos.clone(),
            hot_x: 0,
            hot_y: 0,
        };
        let data = [0_u8; 4 * 64 * 64];
        let backend_cloned = backend.clone();
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend_cloned.cursor_update(&cursor_update, &data));
            if resp.is_some() && resp.as_ref().unwrap().is_err() {
                return;
            }
            *resp = Some(backend_cloned.cursor_pos_hide(&cursor_pos));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());

        // invalid scanout_id
        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let cursor_pos: VhostUserGpuCursorPos = VhostUserGpuCursorPos {
            scanout_id: 1,
            x: DEFAULT_WIDTH,
            y: DEFAULT_HEIGHT,
        };
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.cursor_pos_hide(&cursor_pos));
        });

        // process msg
        assert!(handler.process_cmd().is_err());

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());
    }

    #[test]
    fn test_vhost_user_gpu_pci_cursor_update() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let cursor_pos: VhostUserGpuCursorPos = VhostUserGpuCursorPos {
            scanout_id: 0,
            x: DEFAULT_WIDTH,
            y: DEFAULT_HEIGHT,
        };
        let cursor_update: VhostUserGpuCursorUpdate = VhostUserGpuCursorUpdate {
            pos: cursor_pos,
            hot_x: 0,
            hot_y: 0,
        };
        let data = [0_u8; 4 * 64 * 64];
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.cursor_update(&cursor_update, &data));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());
    }

    #[test]
    fn test_vhost_user_gpu_pci_set_scanout() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let scanout: VhostUserGpuScanout = VhostUserGpuScanout {
            scanout_id: 0,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
        };
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.set_scanout(&scanout));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());
    }

    #[test]
    fn test_vhost_user_gpu_pci_update_scanout() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let update: VhostUserGpuUpdate = VhostUserGpuUpdate {
            scanout_id: 0,
            x: 0,
            y: 0,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
        };
        let data = [0_u8; 12];
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.update_scanout(&update, &data));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());
    }

    #[test]
    fn test_vhost_user_gpu_pci_dambuf_scanout() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let scanout: VhostUserGpuDMABUFScanout = VhostUserGpuDMABUFScanout {
            scanout_id: 0,
            x: 0,
            y: 0,
            width: 1920,
            height: 1280,
            fd_width: 0,
            fd_height: 0,
            fd_stride: 0,
            fd_flags: 0,
            fd_drm_fourcc: 0,
        };
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.set_dmabuf_scanout(&scanout, None::<&File>));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());

        assert_eq!(handler.scanouts[0].width, 1920);
        assert_eq!(handler.scanouts[0].height, 1280);
    }

    #[test]
    fn test_vhost_user_gpu_pci_dmabuf_scanout2() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let scanout: VhostUserGpuDMABUFScanout = VhostUserGpuDMABUFScanout {
            scanout_id: 0,
            x: 0,
            y: 0,
            width: 1920,
            height: 1280,
            fd_width: 0,
            fd_height: 0,
            fd_stride: 0,
            fd_flags: 0,
            fd_drm_fourcc: 0,
        };
        let scanout2 = VhostUserGpuDMABUFScanout2 {
            dmabuf_scanout: scanout,
            modifier: 1,
        };
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.set_dmabuf_scanout2(&scanout2, None::<&File>));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());

        assert_eq!(handler.scanouts[0].width, 1920);
        assert_eq!(handler.scanouts[0].height, 1280);
    }

    #[test]
    fn test_vhost_user_gpu_pci_dmabuf_update() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(None::<Result<(), std::io::Error>>));
        let response_cloned = response.clone();
        let update: VhostUserGpuUpdate = VhostUserGpuUpdate {
            scanout_id: 0,
            x: 0,
            y: 0,
            width: 1920,
            height: 1280,
        };
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = Some(backend.update_dmabuf_scanout(&update));
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        assert!(response.lock().unwrap().is_some());
        assert!(response.lock().unwrap().as_ref().unwrap().is_ok());
    }

    #[test]
    fn test_vhost_user_gpu_pci_get_edid() {
        let (mut handler, backend) = init_test();

        let response = Arc::new(Mutex::new(VirtioGpuRespGetEdid::default()));
        let response_cloned = response.clone();
        let edid_requert: VhostUserGpuEdidRequest = VhostUserGpuEdidRequest { scanout_id: 0 };
        let sender_thread = thread::spawn(move || {
            let mut resp = response_cloned.lock().unwrap();
            *resp = backend.get_edid(&edid_requert).unwrap();
        });

        // process msg
        if let Err(e) = handler.process_cmd() {
            panic!("process_cmd failed: {:?}", e);
        }

        assert!(sender_thread.join().is_ok());
        let resp = response.lock().unwrap();
        assert_eq!(resp.hdr.type_, VIRTIO_GPU_RESP_OK_EDID);
        assert_eq!(resp.size, 1024);

        let mut expect_edid = [0_u8; 1024];
        let mut edid_info =
            EdidInfo::new("HWV", "STRA Monitor", 100, DEFAULT_WIDTH, DEFAULT_HEIGHT);
        edid_info.edid_array_fulfill(&mut expect_edid);
        assert_eq!(resp.edid, expect_edid);
    }
}
