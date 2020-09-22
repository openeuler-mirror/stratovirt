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

use kvm_bindings::{kvm_device_attr, KVMIO};
use kvm_ioctls::DeviceFd;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};

pub type Result<T> = std::result::Result<T, errno::Error>;

/// Gets a specified piece of device configuration and/or state.
///
/// See the documentation for `KVM_GET_DEVICE_ATTR`.
///
/// # Arguments
///
/// * `device_attr` - The device attribute to be read.
pub fn get_device_attr(device_fd: &DeviceFd, device_attr: &mut kvm_device_attr) -> Result<()> {
    let ret = unsafe {
        // Here we trust the kernel not to read past the end of the kvm_device_attr struct.
        ioctl_with_mut_ref(device_fd, KVM_GET_DEVICE_ATTR(), device_attr)
    };
    if ret != 0 {
        return Err(errno::Error::last());
    }
    Ok(())
}

/// Check a specified piece of device feature.
///
/// See the documentation for `KVM_HAS_DEVICE_ATTR`.
/// # Arguments
///
/// * `device_attr` - The device attribute to be check.
pub fn check_device_attr(device_fd: &DeviceFd, device_attr: &kvm_device_attr) -> Result<u32> {
    let ret = unsafe {
        // Here we trust the kernel not to read past the end of the kvm_device_attr struct.
        ioctl_with_ref(device_fd, KVM_HAS_DEVICE_ATTR(), device_attr)
    };
    if ret < 0 {
        return Err(errno::Error::last());
    }
    Ok(ret as u32)
}

ioctl_iow_nr!(KVM_GET_DEVICE_ATTR, KVMIO, 0xe2, kvm_device_attr);
ioctl_iow_nr!(KVM_HAS_DEVICE_ATTR, KVMIO, 0xe3, kvm_device_attr);
