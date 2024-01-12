// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod balloon_test;
mod block_test;
mod fwcfg_test;
mod memory_test;
mod net_test;
mod pci_test;
mod rng_test;
mod scream_test;
mod scsi_test;
mod serial_test;
mod usb_camera_test;
mod usb_storage_test;
mod usb_test;
mod virtio_gpu_test;
mod virtio_test;
mod virtiofs_test;
mod vnc_test;
#[cfg(target_arch = "x86_64")]
mod x86_64;
