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

impl VfioGroup {
    fn new(group_id: u32) -> Result<Self> {
        let group_path = Path::new(GROUP_PATH).join(group_id.to_string());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&group_path)
            .chain_err(|| {
                format!(
                    "Failed to open {} for iommu_group.",
                    group_path.to_str().unwrap()
                )
            })?;

        let mut status = vfio::vfio_group_status {
            argsz: size_of::<vfio::vfio_group_status>() as u32,
            flags: 0,
        };
        // Safe as file is `iommu_group` fd, and we check the return.
        let ret = unsafe { ioctl_with_mut_ref(&file, VFIO_GROUP_GET_STATUS(), &mut status) };
        if ret < 0 {
            return Err(ErrorKind::VfioIoctl("VFIO_GROUP_GET_STATUS".to_string(), ret).into());
        }
        if status.flags != vfio::VFIO_GROUP_FLAGS_VIABLE {
            bail!(
                "Group is not viable, ensure all devices within the IOMMU group are bound to \
                their VFIO bus driver."
            );
        }

        Ok(VfioGroup {
            group: file,
            group_id,
        })
    }

    fn connect_container(&self, container: &VfioContainer) -> Result<()> {
        let raw_fd = container.container.as_raw_fd();
        // Safe as group is the owner of file, and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.group, VFIO_GROUP_SET_CONTAINER(), &raw_fd) };
        if ret < 0 {
            return Err(ErrorKind::VfioIoctl("VFIO_GROUP_SET_CONTAINER".to_string(), ret).into());
        }

        if let Err(e) = container.set_iommu(vfio::VFIO_TYPE1v2_IOMMU) {
            unsafe { ioctl_with_ref(&self.group, VFIO_GROUP_UNSET_CONTAINER(), &raw_fd) };
            return Err(e).chain_err(|| "Failed to set IOMMU");
        }

        if let Err(e) = container.kvm_device_add_group(&self.group.as_raw_fd()) {
            unsafe { ioctl_with_ref(&self.group, VFIO_GROUP_UNSET_CONTAINER(), &raw_fd) };
            return Err(e).chain_err(|| "Failed to add group to kvm device");
        }

        Ok(())
    }
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

impl VfioDevice {
    pub fn new(container: Arc<VfioContainer>, path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("No provided host PCI device, use -device vfio-pci,host=DDDD:BB:DD.F");
        }
        let group =
            Self::vfio_get_group(&container, &path).chain_err(|| "Fail to get iommu group")?;
        let device =
            Self::vfio_get_device(&group, &path).chain_err(|| "Fail to get vfio device")?;
        let dev_info = Self::get_dev_info(&device).chain_err(|| "Fail to get device info")?;

        Ok(VfioDevice {
            device,
            group,
            container,
            dev_info,
        })
    }

    fn vfio_get_group(container: &Arc<VfioContainer>, dev_path: &Path) -> Result<Arc<VfioGroup>> {
        let iommu_group: PathBuf = [dev_path, Path::new(IOMMU_GROUP)]
            .iter()
            .collect::<PathBuf>()
            .read_link()
            .chain_err(|| "Invaild iommu group path")?;
        let group_name = iommu_group
            .file_name()
            .chain_err(|| "Invaild iommu group name")?;
        let mut group_id = 0;
        if let Some(n) = group_name.to_str() {
            group_id = n.parse::<u32>().chain_err(|| "Invaild iommu group id")?;
        }

        let mut groups = container.groups.lock().unwrap();
        if let Some(g) = groups.get(&group_id) {
            return Ok(g.clone());
        }
        let group = Arc::new(VfioGroup::new(group_id)?);
        group
            .connect_container(&container)
            .chain_err(|| "Fail to connect container")?;
        groups.insert(group_id, group.clone());

        Ok(group)
    }

    fn vfio_get_device(group: &VfioGroup, name: &Path) -> Result<File> {
        let mut dev_name: &str = "";
        if let Some(n) = name.file_name() {
            dev_name = n.to_str().chain_err(|| "Invaild device path")?;
        }
        let path: CString = CString::new(dev_name.as_bytes())
            .chain_err(|| "Failed to convert device name to CString type of data")?;
        let ptr = path.as_ptr();
        // Safe as group is the owner of file and make sure ptr is valid.
        let fd = unsafe { ioctl_with_ptr(&group.group, VFIO_GROUP_GET_DEVICE_FD(), ptr) };
        if fd < 0 {
            return Err(ErrorKind::VfioIoctl("VFIO_GROUP_GET_DEVICE_FD".to_string(), fd).into());
        }

        // Safe as we have verified that fd is a valid FD.
        let device = unsafe { File::from_raw_fd(fd) };
        Ok(device)
    }

    fn get_dev_info(device: &File) -> Result<VfioDevInfo> {
        let mut dev_info = vfio::vfio_device_info {
            argsz: size_of::<vfio::vfio_device_info>() as u32,
            flags: 0,
            num_regions: 0,
            num_irqs: 0,
        };

        // Safe as device is the owner of file, and we will verify the result is valid.
        let ret = unsafe { ioctl_with_mut_ref(device, VFIO_DEVICE_GET_INFO(), &mut dev_info) };
        if ret < 0
            || (dev_info.flags & vfio::VFIO_DEVICE_FLAGS_PCI) == 0
            || dev_info.num_regions < vfio::VFIO_PCI_CONFIG_REGION_INDEX + 1
            || dev_info.num_irqs < vfio::VFIO_PCI_MSIX_IRQ_INDEX + 1
        {
            return Err(ErrorKind::VfioIoctl("VFIO_DEVICE_GET_INFO".to_string(), ret).into());
        }

        Ok(VfioDevInfo {
            num_irqs: dev_info.num_irqs,
            flags: dev_info.flags,
        })
    }
}
