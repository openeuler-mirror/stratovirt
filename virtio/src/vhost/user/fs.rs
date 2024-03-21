// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

// The num of high priority queue
const VIRIOT_FS_HIGH_PRIO_QUEUE_NUM: usize = 1;
// The num of request queue
const VIRTIO_FS_REQ_QUEUES_NUM: usize = 1;
// The size of queue for virtio fs
const VIRTIO_FS_QUEUE_SIZE: u16 = 128;

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use vmm_sys_util::eventfd::EventFd;

use super::super::super::{VirtioDevice, VIRTIO_TYPE_FS};
use super::super::VhostOps;
use super::{listen_guest_notifier, VhostBackendType, VhostUserClient};
use crate::{read_config_default, VirtioBase, VirtioInterrupt};
use address_space::AddressSpace;
use machine_manager::config::{
    get_pci_df, parse_bool, valid_id, ChardevConfig, ConfigError, SocketType,
};
use machine_manager::event_loop::unregister_event_helper;
use util::byte_code::ByteCode;

const MAX_TAG_LENGTH: usize = 36;

/// Config struct for `fs`.
/// Contains fs device's attr.
#[derive(Parser, Debug, Clone)]
#[command(no_binary_name(true))]
pub struct FsConfig {
    #[arg(long, value_parser = ["vhost-user-fs-pci", "vhost-user-fs-device"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub chardev: String,
    #[arg(long, value_parser = valid_tag)]
    pub tag: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser = parse_bool)]
    pub multifunction: Option<bool>,
}

fn valid_tag(tag: &str) -> Result<String> {
    if tag.len() >= MAX_TAG_LENGTH {
        return Err(anyhow!(ConfigError::StringLengthTooLong(
            "fs device tag".to_string(),
            MAX_TAG_LENGTH - 1,
        )));
    }
    Ok(tag.to_string())
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; MAX_TAG_LENGTH],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; MAX_TAG_LENGTH],
            num_request_queues: 0,
        }
    }
}

impl ByteCode for VirtioFsConfig {}

pub struct Fs {
    base: VirtioBase,
    fs_cfg: FsConfig,
    chardev_cfg: ChardevConfig,
    config_space: VirtioFsConfig,
    client: Option<Arc<Mutex<VhostUserClient>>>,
    mem_space: Arc<AddressSpace>,
    enable_irqfd: bool,
}

impl Fs {
    /// The construct function of the Fs device.
    ///
    /// # Arguments
    ///
    /// `fs_cfg` - The config of this Fs device.
    /// `chardev_cfg` - The config of this Fs device's chardev.
    /// `mem_space` - The address space of this Fs device.
    pub fn new(fs_cfg: FsConfig, chardev_cfg: ChardevConfig, mem_space: Arc<AddressSpace>) -> Self {
        let queue_num = VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM;
        let queue_size = VIRTIO_FS_QUEUE_SIZE;

        Fs {
            base: VirtioBase::new(VIRTIO_TYPE_FS, queue_num, queue_size),
            fs_cfg,
            chardev_cfg,
            config_space: VirtioFsConfig::default(),
            client: None,
            mem_space,
            enable_irqfd: false,
        }
    }
}

impl VirtioDevice for Fs {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        let queues_num = VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM;

        let socket_path = match self.chardev_cfg.classtype.socket_type()? {
            SocketType::Unix { path } => path,
            _ => bail!("Vhost-user-fs Chardev backend should be unix-socket type."),
        };

        let client = VhostUserClient::new(
            &self.mem_space,
            &socket_path,
            queues_num as u64,
            VhostBackendType::TypeFs,
        )
        .with_context(|| {
            "Failed to create the client which communicates with the server for virtio fs"
        })?;
        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;
        self.client = Some(client);

        self.init_config_features()?;

        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let tag_bytes_vec = self.fs_cfg.tag.clone().into_bytes();
        self.config_space.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
        self.config_space.num_request_queues = VIRTIO_FS_REQ_QUEUES_NUM as u32;

        let client = self.client.as_ref().unwrap();
        self.base.device_features = client
            .lock()
            .unwrap()
            .get_features()
            .with_context(|| "Failed to get features for virtio fs")?;

        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        read_config_default(self.config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = &self.base.queues;
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for virtio fs")),
        };
        client.features = self.base.driver_features;
        client.set_queues(queues);
        client.set_queue_evts(&queue_evts);

        if !self.enable_irqfd {
            let queue_num = queues.len();
            listen_guest_notifier(&mut self.base, &mut client, None, queue_num, interrupt_cb)?;
        }

        client.activate_vhost_user()?;

        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        self.enable_irqfd = true;
        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for virtio fs")),
        }
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        if let Some(client) = &self.client {
            client.lock().unwrap().reset_vhost_user(true);
        }
        unregister_event_helper(None, &mut self.base.deactivate_evts)?;
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.base.device_features = 0_u64;
        self.base.driver_features = 0_u64;
        self.config_space = VirtioFsConfig::default();
        self.enable_irqfd = false;

        let client = match &self.client {
            None => return Err(anyhow!("Failed to get client when resetting virtio fs")),
            Some(client_) => client_,
        };
        client
            .lock()
            .unwrap()
            .delete_event()
            .with_context(|| "Failed to delete virtio fs event")?;
        self.client = None;

        self.realize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use machine_manager::config::str_slip_to_clap;

    #[test]
    fn test_vhostuserfs_cmdline_parser() {
        // Test1: Right.
        let fs_cmd = "vhost-user-fs-device,id=fs0,chardev=chardev0,tag=tag0";
        let fs_config = FsConfig::try_parse_from(str_slip_to_clap(fs_cmd, true, false)).unwrap();
        assert_eq!(fs_config.id, "fs0");
        assert_eq!(fs_config.chardev, "chardev0");
        assert_eq!(fs_config.tag, "tag0");

        // Test2: Illegal value.
        let fs_cmd = "vhost-user-fs-device,id=fs0,chardev=chardev0,tag=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = FsConfig::try_parse_from(str_slip_to_clap(fs_cmd, true, false));
        assert!(result.is_err());
    }
}
