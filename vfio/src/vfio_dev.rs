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

/// The guest OS memory pages should be previously pinned before mapping into the IOMMU tables.
/// This provides structure to save all guest OS memory regions information from `AddressSpace`.
#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq)]
pub struct VfioMemoryRegion {
    // Guest physical address.
    pub guest_phys_addr: u64,
    // Size of the memory region.
    pub memory_size: u64,
    // Host virtual address.
    pub userspace_addr: u64,
    // No flags specified for now.
    flags_padding: u64,
}

/// `VfioMemInfo` structure contains pinning pages information. If any pages need to be zapped from
/// the virtual address space or new pages are added to guest OS memory, it can re-establish regions
///  with updated page info.
#[derive(Clone)]
pub struct VfioMemInfo {
    pub regions: Arc<Mutex<Vec<VfioMemoryRegion>>>,
}

/// Vfio container class can hold one or more groups. In IOMMUs, page tables are shared between
/// different groups, vfio container can reduce TLB thrashing and duplicate page tables.
/// A container can be created by simply opening the `/dev/vfio/vfio` file.
pub struct VfioContainer {
    // `/dev/vfio/vfio` file fd, empowered by the attached groups.
    container: File,
    // A set of groups in the same container.
    groups: Mutex<HashMap<u32, Arc<VfioGroup>>>,
    // The fd for kvm device, which type is VFIO.
    kvm_device: Arc<DeviceFd>,
    // Guest memory regions information.
    pub vfio_mem_info: VfioMemInfo,
}

/// Vfio group is a member of IOMMU group, which contains a set of devices isolated from all
/// other devices in the system.
/// A vfio group can be created by opening `/dev/vfio/$group_id`, where $group_id represents the
/// IOMMU group number.
struct VfioGroup {
    // `/dev/vfio/group_id` file fd.
    group: File,
    #[allow(dead_code)]
    group_id: u32,
}

pub struct VfioDevInfo {
    pub num_irqs: u32,
    pub flags: u32,
}

/// Vfio device includes the group and container it belongs to, I/O regions and interrupt
/// notifications info.
pub struct VfioDevice {
    pub device: File,
    #[allow(dead_code)]
    group: Arc<VfioGroup>,
    pub container: Arc<VfioContainer>,
    pub dev_info: VfioDevInfo,
}
