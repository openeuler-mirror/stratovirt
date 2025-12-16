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

use std::os::unix::net::UnixStream;
use std::{
    fmt::Debug,
    path::Path,
    sync::{Arc, Mutex, Weak},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use log::info;
use vmm_sys_util::eventfd::EventFd;

use address_space::AddressSpace;
use machine_manager::config::{
    get_chardev_socket_path, get_pci_df, valid_block_device_virtqueue_size, valid_id,
    ChardevConfig, MAX_VIRTIO_QUEUE,
};
use machine_manager::event_loop::unregister_event_helper;
use ui::console::{console_close, console_init, ConsoleType, DisplayConsole};
use util::byte_code::ByteCode;
use util::gen_base_func;

use crate::vhost::VhostOps;
use crate::VhostUser::client::{
    VhostBackendType, VhostUserClient, VHOST_USER_PROTOCOL_F_CONFIG, VHOST_USER_PROTOCOL_F_MQ,
    VHOST_USER_PROTOCOL_F_REPLY_ACK,
};
use crate::VhostUser::listen_guest_notifier;
use crate::VhostUser::message::VHOST_USER_F_PROTOCOL_FEATURES;
use crate::{
    check_config_space_rw, read_config_default, virtio_has_feature, GpuOpts, VirtioBase,
    VirtioDevice, VirtioGpuConfig, VirtioGpuOutputState, VirtioInterrupt, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1, VIRTIO_GPU_F_EDID,
    VIRTIO_GPU_F_MONOCHROME, VIRTIO_GPU_F_VIRGL, VIRTIO_GPU_MAX_OUTPUTS, VIRTIO_TYPE_GPU,
};

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
        let vgud_sock = Path::new(&socket_path);
        // Wait totally 10s for that the vhost user fs socket is being created.
        for _ in 0..100 {
            if vgud_sock.exists() {
                // After the vhost-user-gpu socket file is created, it will be unavailable
                // for a short period of time (0.1-3ms on ohos), so we wait a moment.
                std::thread::sleep(std::time::Duration::from_millis(20));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if !vgud_sock.exists() {
            bail!("Failed to create vhost-user-gpu socket");
        }
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

        if virtio_has_feature(features, VHOST_USER_F_PROTOCOL_FEATURES) {
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
            self.protocol_features = protocol_features;
            locked_client
                .set_protocol_features(self.protocol_features)
                .with_context(|| "Failed to set protocol features for vhost-user gpu")?;

            let config = locked_client
                .get_virtio_config::<VirtioGpuConfig>()
                .with_context(|| "Failed to get config for vhost-user gpu")?;
            let mut config_space = self.config_space.lock().unwrap();
            *config_space = config;

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
        } else {
            bail!("Bad vug feature: {:#b}", features);
        }
        drop(locked_client);

        self.base.device_features = (1_u64 << VIRTIO_GPU_F_EDID)
            | (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_F_RING_INDIRECT_DESC)
            | (1u64 << VIRTIO_F_RING_EVENT_IDX)
            | (1u64 << VIRTIO_GPU_F_MONOCHROME);
        if self.cfg.virgl {
            self.base.device_features = self.base.device_features | (1_u64 << VIRTIO_GPU_F_VIRGL);
            // self.base.device_features = self.base.device_features  | (1_u64 << VIRTIO_GPU_F_RESOURCE_BLOB);     // not support now
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
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for vhost-user gpu")),
        };
        client.features = self.base.driver_features | (1 << VHOST_USER_F_PROTOCOL_FEATURES); // add VHOST_USER_F_PROTOCOL_FEATURES bit for enabling protocol features.
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
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        info!("vhost-user-gpu do deactivate");
        if let Some(client) = &self.client {
            client.lock().unwrap().reset_vhost_user(true);
        }
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
        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for vhost-user gpu")),
        };

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        info!("vhost-user-gpu do reset");
        self.enable_irqfd = false;
        Ok(())
    }
}
