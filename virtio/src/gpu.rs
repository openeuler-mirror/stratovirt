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

use super::errors::{ErrorKind, Result, ResultExt};
use super::{Queue, VirtioDevice, VirtioInterrupt, VIRTIO_F_VERSION_1, VIRTIO_TYPE_GPU};
use address_space::AddressSpace;
use error_chain::bail;
use log::warn;
use machine_manager::config::{GpuConfig, VIRTIO_GPU_MAX_SCANOUTS};
use migration::{DeviceStateDesc, FieldDesc};
use migration_derive::{ByteCode, Desc};
use std::cmp;
use std::io::Write;
use std::sync::{Arc, Mutex};
use util::byte_code::ByteCode;
use util::num_ops::{read_u32, write_u32};
use vmm_sys_util::eventfd::EventFd;

/// Number of virtqueues.
const QUEUE_NUM_GPU: usize = 2;
/// Size of each virtqueue.
const QUEUE_SIZE_GPU: u16 = 256;
/// Flags for virtio gpu base conf.
const VIRTIO_GPU_FLAG_VIRGL_ENABLED: u32 = 1;
//const VIRTIO_GPU_FLAG_STATS_ENABLED: u32 = 2;
const VIRTIO_GPU_FLAG_EDID_ENABLED: u32 = 3;

#[derive(Clone, Copy, Debug, ByteCode)]
pub struct VirtioGpuConfig {
    events_read: u32,
    events_clear: u32,
    num_scanouts: u32,
    reserved: u32,
}

#[derive(Clone, Copy, Debug, ByteCode)]
pub struct VirtioGpuBaseConf {
    max_outputs: u32,
    flags: u32,
    xres: u32,
    yres: u32,
}

/// State of gpu device.
#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct GpuState {
    /// Bitmask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Config space of the GPU device.
    config: VirtioGpuConfig,
    /// Baisc Configure of GPU device.
    base_conf: VirtioGpuBaseConf,
}

/// GPU device structure.
pub struct Gpu {
    /// Configuration of the GPU device.
    gpu_conf: GpuConfig,
    /// Status of the GPU device.
    state: GpuState,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Eventfd for device deactivate.
    deactivate_evt: EventFd,
}

impl Default for Gpu {
    fn default() -> Self {
        Gpu {
            gpu_conf: GpuConfig::default(),
            state: GpuState::default(),
            interrupt_cb: None,
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl Gpu {
    pub fn new(gpu_conf: GpuConfig) -> Gpu {
        let mut state = GpuState::default();
        state.base_conf.xres = gpu_conf.xres;
        state.base_conf.yres = gpu_conf.yres;
        if gpu_conf.edid {
            state.base_conf.flags &= 1 << VIRTIO_GPU_FLAG_EDID_ENABLED;
        }
        state.base_conf.max_outputs = gpu_conf.max_outputs;
        state.device_features = 1u64 << VIRTIO_F_VERSION_1;
        Self {
            gpu_conf,
            state,
            interrupt_cb: None,
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl VirtioDevice for Gpu {
    /// Realize virtio gpu device.
    fn realize(&mut self) -> Result<()> {
        if self.gpu_conf.max_outputs > VIRTIO_GPU_MAX_SCANOUTS as u32 {
            bail!(
                "Invalid max_outputs {} which is bigger than {}",
                self.gpu_conf.max_outputs,
                VIRTIO_GPU_MAX_SCANOUTS
            );
        }

        // Virgl is not supported.
        self.state.base_conf.flags &= !(1 << VIRTIO_GPU_FLAG_VIRGL_ENABLED);
        self.state.config.num_scanouts = self.state.base_conf.max_outputs;
        self.state.config.reserved = 0;
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_GPU
    }

    /// Get the count of virtio gpu queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_GPU
    }

    /// Get the queue size of virtio gpu.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_GPU
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut v = write_u32(value, page);
        let unrequested_features = v & !self.state.device_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request with unknown feature: {:x}", v);
            v &= !unrequested_features;
        }
        self.state.driver_features |= v;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.state.config.as_bytes();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len).into());
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])?;
        }
        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_slice = self.state.config.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);

        if self.state.config.events_clear != 0 {
            self.state.config.events_read &= !self.state.config.events_clear;
        }

        Ok(())
    }

    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        mut _queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        if queues.len() != QUEUE_NUM_GPU {
            return Err(ErrorKind::IncorrectQueueNum(QUEUE_NUM_GPU, queues.len()).into());
        }
        self.interrupt_cb = Some(interrupt_cb.clone());

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.deactivate_evt
            .write(1)
            .chain_err(|| ErrorKind::EventFdWrite)
    }
}
