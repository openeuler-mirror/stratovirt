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

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use address_space::{AddressSpace, FlatRange, Listener, ListenerReqType, RegionIoEventFd};
use byteorder::{ByteOrder, LittleEndian};
use kvm_bindings::{kvm_device_attr, KVM_DEV_VFIO_GROUP, KVM_DEV_VFIO_GROUP_ADD};
use vfio_bindings::bindings::vfio;
use vmm_sys_util::ioctl::{
    ioctl, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
};

use super::errors::{ErrorKind, Result, ResultExt};
use super::KVM_DEVICE_FD;

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
    // IOMMU mapped flag.
    pub iommu_mapped: bool,
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
            iommu_mapped: false,
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
            iommu_mapped: false,
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
    // Guest memory regions information.
    pub vfio_mem_info: VfioMemInfo,
}

impl VfioContainer {
    /// Create a VFIO container.
    ///
    /// # Arguments
    ///
    /// * `mem_space` - Memory address space.
    ///
    /// Return Error if
    /// * Fail to open `/dev/vfio/vfio` file.
    /// * Fail to match container api version or extension.
    /// * Only support api version type1v2 IOMMU.
    /// * Fail to register flat_view into vfio region info.
    pub fn new(mem_space: &Arc<AddressSpace>) -> Result<Self> {
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
        match KVM_DEVICE_FD.as_ref() {
            Some(fd) => fd
                .set_device_attr(&attr)
                .chain_err(|| "Failed to add group to kvm device.")?,
            None => bail!("Failed to create kvm device."),
        }
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
    // `/dev/vfio/$group_id` file fd.
    group: File,
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

        Ok(VfioGroup { group: file })
    }

    fn connect_container(&self, container: &VfioContainer) -> Result<()> {
        let raw_fd = container.container.as_raw_fd();
        // Safe as group is the owner of file, and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.group, VFIO_GROUP_SET_CONTAINER(), &raw_fd) };
        if ret < 0 {
            return Err(ErrorKind::VfioIoctl("VFIO_GROUP_SET_CONTAINER".to_string(), ret).into());
        }

        if container.groups.lock().unwrap().is_empty() {
            if let Err(e) = container.set_iommu(vfio::VFIO_TYPE1v2_IOMMU) {
                unsafe { ioctl_with_ref(&self.group, VFIO_GROUP_UNSET_CONTAINER(), &raw_fd) };
                return Err(e).chain_err(|| "Failed to set IOMMU");
            }
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

#[derive(Debug, Copy, Clone, Default)]
pub struct MmapInfo {
    pub size: u64,
    pub offset: u64,
}

pub struct VfioRegion {
    // Size of device region.
    pub size: u64,
    // Offset of device region.
    pub region_offset: u64,
    // Region flags.
    pub flags: u32,
    // Region size and offset that can be mapped.
    pub mmaps: Vec<MmapInfo>,
    // Guest physical address.
    pub guest_phys_addr: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct VfioRegionWithCap {
    region_info: vfio::vfio_region_info,
    cap_info: vfio::__IncompleteArrayField<u8>,
}

#[allow(dead_code)]
pub struct VfioIrq {
    count: u32,
    flags: u32,
    index: u32,
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
            .chain_err(|| "Invalid iommu group path")?;
        let group_name = iommu_group
            .file_name()
            .chain_err(|| "Invalid iommu group name")?;
        let mut group_id = 0;
        if let Some(n) = group_name.to_str() {
            group_id = n.parse::<u32>().chain_err(|| "Invalid iommu group id")?;
        }

        if let Some(g) = container.groups.lock().unwrap().get(&group_id) {
            return Ok(g.clone());
        }
        let group = Arc::new(VfioGroup::new(group_id)?);
        group
            .connect_container(&container)
            .chain_err(|| "Fail to connect container")?;
        container
            .groups
            .lock()
            .unwrap()
            .insert(group_id, group.clone());

        Ok(group)
    }

    fn vfio_get_device(group: &VfioGroup, name: &Path) -> Result<File> {
        let mut dev_name: &str = "";
        if let Some(n) = name.file_name() {
            dev_name = n.to_str().chain_err(|| "Invalid device path")?;
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

    fn region_mmap_info(&self, info: vfio::vfio_region_info) -> Result<Vec<MmapInfo>> {
        let mut mmaps = Vec::new();
        if info.flags & vfio::VFIO_REGION_INFO_FLAG_MMAP != 0 {
            mmaps.push(MmapInfo {
                size: info.size,
                offset: 0,
            });

            let argsz = size_of::<vfio::vfio_region_info>() as u32;
            if info.flags & vfio::VFIO_REGION_INFO_FLAG_CAPS != 0 && info.argsz > argsz {
                let cap_size = (info.argsz - argsz) as usize;
                let mut new_info = array_to_vec::<VfioRegionWithCap, u8>(cap_size);
                new_info[0].region_info = info;
                // Safe as device is the owner of file, and we will verify the result is valid.
                let ret = unsafe {
                    ioctl_with_mut_ref(
                        &self.device,
                        VFIO_DEVICE_GET_REGION_INFO(),
                        &mut (new_info[0].region_info),
                    )
                };
                if ret < 0 {
                    return Err(ErrorKind::VfioIoctl(
                        "VFIO_DEVICE_GET_REGION_INFO".to_string(),
                        ret,
                    )
                    .into());
                }

                // Safe as we make sure there is enough memory space to convert cap info into
                // specific structure.
                let sparse = unsafe {
                    new_info[0].cap_info.as_ptr() as *mut vfio::vfio_region_info_cap_sparse_mmap
                };
                if unsafe { (*sparse).header.id } == vfio::VFIO_REGION_INFO_CAP_SPARSE_MMAP as u16 {
                    let nr_areas = unsafe { (*sparse).nr_areas as usize };
                    let areas: &mut [vfio::vfio_region_sparse_mmap_area] =
                        unsafe { (*sparse).areas.as_mut_slice(nr_areas) };
                    mmaps = Vec::with_capacity(nr_areas);
                    for area in areas.iter() {
                        if area.size > 0 {
                            mmaps.push(MmapInfo {
                                size: area.size,
                                offset: area.offset,
                            });
                        }
                    }
                }
            }
        }

        Ok(mmaps)
    }

    fn region_info(&self, index: u32) -> Result<vfio::vfio_region_info> {
        let argsz = size_of::<vfio::vfio_region_info>() as u32;
        let mut info = vfio::vfio_region_info {
            argsz,
            flags: 0,
            index,
            cap_offset: 0,
            size: 0,
            offset: 0,
        };

        // Safe as device is the owner of file, and we will verify the result is valid.
        let ret =
            unsafe { ioctl_with_mut_ref(&self.device, VFIO_DEVICE_GET_REGION_INFO(), &mut info) };
        if ret < 0 {
            return Err(
                ErrorKind::VfioIoctl("VFIO_DEVICE_GET_REGION_INFO".to_string(), ret).into(),
            );
        }

        Ok(info)
    }

    pub fn get_regions_info(&self) -> Result<Vec<VfioRegion>> {
        let mut regions: Vec<VfioRegion> = Vec::new();
        for index in vfio::VFIO_PCI_BAR0_REGION_INDEX..vfio::VFIO_PCI_ROM_REGION_INDEX {
            let info = self
                .region_info(index)
                .chain_err(|| "Fail to get region info")?;

            let mut mmaps = Vec::new();
            if info.size > 0 {
                mmaps = self
                    .region_mmap_info(info)
                    .chain_err(|| "Fail to get region mmap info")?;
            }

            regions.push(VfioRegion {
                size: info.size,
                region_offset: info.offset,
                flags: info.flags,
                mmaps,
                guest_phys_addr: 0,
            });
        }

        Ok(regions)
    }

    pub fn get_irqs_info(&self, num_irqs: u32) -> Result<HashMap<u32, VfioIrq>> {
        let mut irqs: HashMap<u32, VfioIrq> = HashMap::new();

        for index in 0..num_irqs {
            let mut info = vfio::vfio_irq_info {
                argsz: size_of::<vfio::vfio_irq_info>() as u32,
                flags: 0,
                index,
                count: 0,
            };

            // Safe as device is the owner of file, and we will verify the result is valid.
            let ret =
                unsafe { ioctl_with_mut_ref(&self.device, VFIO_DEVICE_GET_IRQ_INFO(), &mut info) };
            if ret < 0 {
                return Err(
                    ErrorKind::VfioIoctl("VFIO_DEVICE_GET_IRQ_INFO".to_string(), ret).into(),
                );
            }

            let irq = VfioIrq {
                flags: info.flags,
                count: info.count,
                index,
            };
            irqs.insert(index, irq);
        }

        Ok(irqs)
    }

    /// Read region information from VFIO device.
    ///
    /// # Arguments
    ///
    /// * `buf` - The destination that the data would be read to.
    /// * `region_offset` - Vfio device region offset from its device descriptor.
    /// * `addr` - Offset in the region to read data.
    pub fn read_region(&self, buf: &mut [u8], region_offset: u64, addr: u64) -> Result<()> {
        self.device
            .read_exact_at(buf, region_offset + addr)
            .chain_err(|| "Failed to read vfio region")?;

        Ok(())
    }

    /// Write region information to VFIO device.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data that would be written to.
    /// * `region_offset` - Vfio device region offset from its device descriptor.
    /// * `addr` - Offset in the region to write.
    pub fn write_region(&self, buf: &[u8], region_offset: u64, addr: u64) -> Result<()> {
        self.device
            .write_all_at(buf, region_offset + addr)
            .chain_err(|| "Failed to write vfio region")?;

        Ok(())
    }

    /// Bind irqs to kvm interrupts.
    ///
    /// # Arguments
    ///
    /// * `irq_fds` - Irq fds that will be registered to kvm.
    pub fn enable_irqs(&self, irq_fds: Vec<RawFd>) -> Result<()> {
        let mut irq_set = array_to_vec::<vfio::vfio_irq_set, u32>(irq_fds.len());
        irq_set[0].argsz =
            (size_of::<vfio::vfio_irq_set>() + irq_fds.len() * size_of::<RawFd>()) as u32;
        irq_set[0].flags = vfio::VFIO_IRQ_SET_DATA_EVENTFD | vfio::VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = vfio::VFIO_PCI_MSIX_IRQ_INDEX;
        irq_set[0].start = 0u32;
        irq_set[0].count = irq_fds.len() as u32;
        // It is safe as enough memory space to save irq_set data.
        let mut data: &mut [u8] = unsafe {
            irq_set[0]
                .data
                .as_mut_slice(irq_fds.len() * size_of::<RawFd>())
        };
        LittleEndian::write_i32_into(irq_fds.as_slice(), &mut data);
        // Safe as device is the owner of file, and we will verify the result is valid.
        let ret = unsafe { ioctl_with_ref(&self.device, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            return Err(ErrorKind::VfioIoctl("VFIO_DEVICE_SET_IRQS".to_string(), ret).into());
        }

        Ok(())
    }

    /// Unbind irqs from kvm interrupts.
    ///
    /// # Arguments
    ///
    /// * `irq_fds` - Irq fds that will be registered to kvm.
    pub fn disable_irqs(&self) -> Result<()> {
        let mut irq_set = array_to_vec::<vfio::vfio_irq_set, u32>(0);
        irq_set[0].argsz = size_of::<vfio::vfio_irq_set>() as u32;
        irq_set[0].flags = vfio::VFIO_IRQ_SET_DATA_NONE | vfio::VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = vfio::VFIO_PCI_MSIX_IRQ_INDEX;
        irq_set[0].start = 0u32;
        irq_set[0].count = 0u32;
        // Safe as device is the owner of file, and we will verify the result is valid.
        let ret = unsafe { ioctl_with_ref(&self.device, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            return Err(ErrorKind::VfioIoctl("VFIO_DEVICE_SET_IRQS".to_string(), ret).into());
        }

        Ok(())
    }

    pub fn reset(&self) -> Result<()> {
        // Safe as device is the owner of file, and we verify the device supports being reset.
        if self.dev_info.flags & vfio::VFIO_DEVICE_FLAGS_RESET != 0 {
            let ret = unsafe { ioctl(&self.device, VFIO_DEVICE_RESET()) };
            if ret < 0 {
                return Err(ErrorKind::VfioIoctl("VFIO_DEVICE_RESET".to_string(), ret).into());
            }
        }

        Ok(())
    }
}

/// In VFIO, there are several structures contains zero-length array, as follows:
/// ```
/// use vfio_bindings::bindings::vfio::__IncompleteArrayField;
/// struct Foo {
///     info: u8,
///     array: __IncompleteArrayField<u8>,
/// }
/// ```
/// Size_of::<Foo>() is too small to keep array data. Because array is zero-length array, we are not
/// sure how much memory is required, and the array memory must be contiguous with info data.
/// The function is used to allocate enough memory space for info and array data.
fn array_to_vec<T: Default, F>(len: usize) -> Vec<T> {
    let round = (len * size_of::<F>() + 2 * size_of::<T>() - 1) / size_of::<T>();
    let mut vec = Vec::with_capacity(round);
    for _ in 0..round {
        vec.push(T::default());
    }
    vec
}

#[cfg(test)]
mod tests {
    use crate::vfio_dev::array_to_vec;

    #[test]
    fn test_array_to_vec() {
        let vec1 = array_to_vec::<u8, u8>(1);
        assert_eq!(vec1.len(), 2);

        let vec2 = array_to_vec::<u16, u8>(2);
        assert_eq!(vec2.len(), 2);

        let vec3 = array_to_vec::<u8, u32>(2);
        assert_eq!(vec3.len(), 9);
    }
}
