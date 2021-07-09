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

/// Refer to VFIO in https://github.com/torvalds/linux/blob/master/include/uapi/linux/vfio.h
const IOMMU_GROUP: &str = "iommu_group";
const GROUP_PATH: &str = "/dev/vfio";
const CONTAINER_PATH: &str = "/dev/vfio/vfio";

ioctl_io_nr!(VFIO_GET_API_VERSION, vfio::VFIO_TYPE, vfio::VFIO_BASE);
ioctl_io_nr!(
    VFIO_CHECK_EXTENSION,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x01
);
ioctl_io_nr!(VFIO_SET_IOMMU, vfio::VFIO_TYPE, vfio::VFIO_BASE + 0x02);
ioctl_io_nr!(
    VFIO_GROUP_GET_STATUS,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x03
);
ioctl_io_nr!(
    VFIO_GROUP_SET_CONTAINER,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x04
);
ioctl_io_nr!(
    VFIO_GROUP_UNSET_CONTAINER,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x05
);
ioctl_io_nr!(
    VFIO_GROUP_GET_DEVICE_FD,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x06
);
ioctl_io_nr!(
    VFIO_DEVICE_GET_INFO,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x07
);
ioctl_io_nr!(
    VFIO_DEVICE_GET_REGION_INFO,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x08
);
ioctl_io_nr!(
    VFIO_DEVICE_GET_IRQ_INFO,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x09
);
ioctl_io_nr!(
    VFIO_DEVICE_SET_IRQS,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x0a
);
ioctl_io_nr!(VFIO_DEVICE_RESET, vfio::VFIO_TYPE, vfio::VFIO_BASE + 0x0b);
ioctl_io_nr!(VFIO_IOMMU_MAP_DMA, vfio::VFIO_TYPE, vfio::VFIO_BASE + 0x0d);

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

impl VfioMemInfo {
    fn new() -> VfioMemInfo {
        VfioMemInfo {
            regions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_listener_region(&self, fr: &FlatRange) -> address_space::errors::Result<()> {
        if fr.owner.region_type() != address_space::RegionType::Ram {
            return Ok(());
        }

        let guest_phys_addr = fr.addr_range.base.raw_value();
        let memory_size = fr.addr_range.size;
        let hva = match fr.owner.get_host_address() {
            Some(addr) => addr,
            None => bail!("Failed to get host address"),
        };
        let userspace_addr = hva + fr.offset_in_region;
        self.regions.lock().unwrap().push(VfioMemoryRegion {
            guest_phys_addr,
            memory_size,
            userspace_addr,
            flags_padding: 0_u64,
        });

        Ok(())
    }

    fn del_listener_region(&self, fr: &FlatRange) -> address_space::errors::Result<()> {
        if fr.owner.region_type() != address_space::RegionType::Ram {
            return Ok(());
        }

        let hva = match fr.owner.get_host_address() {
            Some(addr) => addr,
            None => bail!("Failed to get host address"),
        };
        let target = VfioMemoryRegion {
            guest_phys_addr: fr.addr_range.base.raw_value(),
            memory_size: fr.addr_range.size,
            userspace_addr: hva + fr.offset_in_region,
            flags_padding: 0_u64,
        };
        let mut mem_regions = self.regions.lock().unwrap();
        for (index, mr) in mem_regions.iter().enumerate() {
            if *mr == target {
                mem_regions.remove(index);
                return Ok(());
            }
        }

        Ok(())
    }
}

impl Listener for VfioMemInfo {
    fn priority(&self) -> i32 {
        0
    }

    fn handle_request(
        &self,
        range: Option<&FlatRange>,
        _evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> address_space::errors::Result<()> {
        match req_type {
            ListenerReqType::AddRegion => {
                self.add_listener_region(range.unwrap())?;
            }
            ListenerReqType::DeleteRegion => {
                self.del_listener_region(range.unwrap())?;
            }
            _ => {}
        }
        Ok(())
    }
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

impl VfioContainer {
    /// Create a VFIO container.
    ///
    /// # Arguments
    ///
    /// * `kvm_device` - The fd of kvm device.
    /// * `mem_space` - Memory address space.
    ///
    /// Return Error if
    /// * Fail to open `/dev/vfio/vfio` file.
    /// * Fail to match container api version or extension.
    /// * Only support api version type1v2 IOMMU.
    /// * Fail to register flat_view into vfio region info.
    pub fn new(kvm_device: Arc<DeviceFd>, mem_space: &Arc<AddressSpace>) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(CONTAINER_PATH)
            .chain_err(|| format!("Failed to open {} for VFIO container.", CONTAINER_PATH))?;

        // Ioctl is safe. Called file is `/dev/vfio/vfio` fd and we check the return.
        let v = unsafe { ioctl(&file, VFIO_GET_API_VERSION()) };
        if v as u32 != vfio::VFIO_API_VERSION {
            return Err(ErrorKind::VfioIoctl("VFIO_GET_API_VERSION".to_string(), v).into());
        };

        // Ioctl is safe. Called file is `/dev/vfio/vfio` fd and we check the return.
        let ret = unsafe {
            ioctl_with_val(
                &file,
                VFIO_CHECK_EXTENSION(),
                vfio::VFIO_TYPE1v2_IOMMU.into(),
            )
        };
        if ret != 1 {
            return Err(ErrorKind::VfioIoctl("VFIO_CHECK_EXTENSION".to_string(), ret).into());
        }

        let vfio_mem_info = VfioMemInfo::new();
        mem_space
            .register_listener(Box::new(vfio_mem_info.clone()))
            .chain_err(|| "Failed to register memory to listener")?;

        let container = VfioContainer {
            container: file,
            kvm_device,
            groups: Mutex::new(HashMap::new()),
            vfio_mem_info,
        };

        Ok(container)
    }

    /// Set specific IOMMU type for the container.
    ///
    /// # Arguments
    ///
    /// * `val` - IOMMU type.
    ///
    /// Return Error if
    /// * Fail to match IOMMU type.
    /// * Fail to set container IOMMU.
    fn set_iommu(&self, val: u32) -> Result<()> {
        if val != vfio::VFIO_TYPE1_IOMMU && val != vfio::VFIO_TYPE1v2_IOMMU {
            bail!("Unsupported IOMMU type val.");
        }

        // Ioctl is safe. Called container file is `/dev/vfio/vfio` fd and we check the return.
        let ret = unsafe { ioctl_with_val(&self.container, VFIO_SET_IOMMU(), val.into()) };
        if ret < 0 {
            return Err(ErrorKind::VfioIoctl("VFIO_SET_IOMMU".to_string(), ret).into());
        }

        Ok(())
    }

    /// Add group to kvm VFIO device.
    /// Return Error if
    /// * Fail to set group to container kvm device.
    fn kvm_device_add_group(&self, group_fd: &RawFd) -> Result<()> {
        let attr = kvm_device_attr {
            flags: 0,
            group: KVM_DEV_VFIO_GROUP,
            attr: u64::from(KVM_DEV_VFIO_GROUP_ADD),
            addr: group_fd as *const i32 as u64,
        };
        self.kvm_device
            .set_device_attr(&attr)
            .chain_err(|| "Failed to add group to kvm device")?;

        Ok(())
    }

    /// Try to add a region of guest memory map into IOMMU table.
    ///
    /// # Arguments
    ///
    /// * `iova` - GPA of Guest memory region.
    /// * `user_addr` - HVA of Guest memory region.
    ///
    /// Return Error if
    /// * Fail to map memory into IOMMU table.
    pub fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        let map = vfio::vfio_iommu_type1_dma_map {
            argsz: size_of::<vfio::vfio_iommu_type1_dma_map>() as u32,
            flags: vfio::VFIO_DMA_MAP_FLAG_READ | vfio::VFIO_DMA_MAP_FLAG_WRITE,
            vaddr: user_addr,
            iova,
            size,
        };

        // Ioctl is safe. Called container file is `/dev/vfio/vfio` fd and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.container, VFIO_IOMMU_MAP_DMA(), &map) };
        if ret != 0 {
            return Err(ErrorKind::VfioIoctl("VFIO_IOMMU_MAP_DMA".to_string(), ret).into());
        }

        Ok(())
    }
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
