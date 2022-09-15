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

use std::cmp;
use std::io::Write;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};

use super::super::{Queue, VirtioDevice, VirtioInterrupt, VIRTIO_TYPE_SCSI};
use crate::VirtioError;
use address_space::AddressSpace;
use log::warn;
use machine_manager::config::{ConfigCheck, ScsiCntlrConfig};
use util::byte_code::ByteCode;
use util::num_ops::{read_u32, write_u32};
use vmm_sys_util::eventfd::EventFd;

/// Virtio Scsi Controller has 1 ctrl queue, 1 event queue and at least 1 cmd queue.
const SCSI_CTRL_QUEUE_NUM: usize = 1;
const SCSI_EVENT_QUEUE_NUM: usize = 1;
const SCSI_MIN_QUEUE_NUM: usize = 3;
/// Size of each virtqueue.
const QUEUE_SIZE_SCSI: u16 = 256;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioScsiConfig {
    num_queues: u32,
    seg_max: u32,
    max_sectors: u32,
    cmd_per_lun: u32,
    event_info_size: u32,
    sense_size: u32,
    cdb_size: u32,
    max_channel: u32,
    max_target: u32,
    max_lun: u32,
}

impl ByteCode for VirtioScsiConfig {}

/// State of virtio scsi controller.
#[derive(Clone, Copy, Default)]
pub struct ScsiCntlrState {
    /// Bitmask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Config space of the virtio scsi controller.
    config_space: VirtioScsiConfig,
}

/// Virtio Scsi Controller device structure.
#[derive(Default)]
pub struct ScsiCntlr {
    /// Configuration of the virtio scsi controller.
    config: ScsiCntlrConfig,
    /// Status of virtio scsi controller.
    state: ScsiCntlrState,
}

impl ScsiCntlr {
    pub fn new(config: ScsiCntlrConfig) -> ScsiCntlr {
        Self {
            config,
            state: ScsiCntlrState::default(),
        }
    }
}

impl VirtioDevice for ScsiCntlr {
    /// Realize virtio scsi controller, which is a pci device.
    fn realize(&mut self) -> Result<()> {
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_SCSI
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        self.config.queues as usize + SCSI_CTRL_QUEUE_NUM + SCSI_EVENT_QUEUE_NUM
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_SCSI
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut features = write_u32(value, page);
        let unrequested_features = features & !self.state.device_features;
        if unrequested_features != 0 {
            warn!(
                "Received acknowledge request with unsupported feature for virtio scsi: 0x{:x}",
                features
            );
            features &= !unrequested_features;
        }
        self.state.driver_features |= features;
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.driver_features, features_select)
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.state.config_space.as_bytes();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_len)));
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])?;
        }

        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_slice = self.state.config_space.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(
                offset,
                config_len as u64
            )));
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);

        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        _interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        _queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let queue_num = queues.len();
        if queue_num < SCSI_MIN_QUEUE_NUM {
            bail!("virtio scsi controller queues num can not be less than 3!");
        }
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        Ok(())
    }

    fn update_config(&mut self, _dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        Ok(())
    }
}
