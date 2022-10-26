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

pub mod error;
pub use error::VfioError;

mod vfio_dev;
mod vfio_pci;

pub use vfio_dev::{
    VfioContainer, VfioDevice, VFIO_CHECK_EXTENSION, VFIO_DEVICE_GET_INFO,
    VFIO_DEVICE_GET_IRQ_INFO, VFIO_DEVICE_GET_REGION_INFO, VFIO_DEVICE_RESET, VFIO_DEVICE_SET_IRQS,
    VFIO_GET_API_VERSION, VFIO_GROUP_GET_DEVICE_FD, VFIO_GROUP_GET_STATUS,
    VFIO_GROUP_SET_CONTAINER, VFIO_IOMMU_MAP_DMA, VFIO_IOMMU_UNMAP_DMA, VFIO_SET_IOMMU,
};
pub use vfio_pci::VfioPciDevice;

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use hypervisor::kvm::KVM_FDS;
use kvm_bindings::{kvm_create_device, kvm_device_type_KVM_DEV_TYPE_VFIO};
use kvm_ioctls::DeviceFd;
use log::error;
use once_cell::sync::Lazy;
use vfio_dev::VfioGroup;

pub static KVM_DEVICE_FD: Lazy<Option<DeviceFd>> = Lazy::new(create_kvm_vfio_device);
pub static CONTAINERS: Lazy<Mutex<HashMap<RawFd, Arc<Mutex<VfioContainer>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
pub static GROUPS: Lazy<Mutex<HashMap<u32, Arc<VfioGroup>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn create_kvm_vfio_device() -> Option<DeviceFd> {
    let mut device = kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
        fd: 0,
        flags: 0,
    };
    match KVM_FDS
        .load()
        .vm_fd
        .as_ref()
        .unwrap()
        .create_device(&mut device)
    {
        Ok(fd) => Some(fd),
        Err(e) => {
            error!("{:?}", e);
            None
        }
    }
}
