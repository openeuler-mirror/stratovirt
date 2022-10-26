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

use log::warn;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use address_space::{AddressSpace, FlatRange, Listener, ListenerReqType, RegionIoEventFd};
use byteorder::{ByteOrder, LittleEndian};
use kvm_bindings::{
    kvm_device_attr, KVM_DEV_VFIO_GROUP, KVM_DEV_VFIO_GROUP_ADD, KVM_DEV_VFIO_GROUP_DEL,
};
use vfio_bindings::bindings::vfio;
use vmm_sys_util::ioctl::{
    ioctl, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
};
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr};

use super::{CONTAINERS, GROUPS, KVM_DEVICE_FD};
use crate::VfioError;
use anyhow::{anyhow, bail, Context, Result};

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
ioctl_io_nr!(
    VFIO_IOMMU_UNMAP_DMA,
    vfio::VFIO_TYPE,
    vfio::VFIO_BASE + 0x0e
);

/// Vfio container class can hold one or more groups. In IOMMUs, page tables are shared between
/// different groups, vfio container can reduce TLB thrashing and duplicate page tables.
/// A container can be created by simply opening the `/dev/vfio/vfio` file.
pub struct VfioContainer {
    /// `/dev/vfio/vfio` file fd, empowered by the attached groups.
    pub fd: File,
    /// A set of groups in the same container.
    pub groups: Mutex<HashMap<u32, Arc<VfioGroup>>>,
    // Whether enabled as a memory listener.
    enabled: bool,
}

impl VfioContainer {
    /// Create a VFIO container.
    ///
    /// Return Error if
    /// * Fail to open `/dev/vfio/vfio` file.
    /// * Fail to match container api version or extension.
    /// * Only support api version type1v2 IOMMU.
    pub fn new() -> Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(CONTAINER_PATH)
            .with_context(|| format!("Failed to open {} for VFIO container.", CONTAINER_PATH))?;

        // Ioctl is safe. Called file is `/dev/vfio/vfio` fd and we check the return.
        let v = unsafe { ioctl(&fd, VFIO_GET_API_VERSION()) };
        if v as u32 != vfio::VFIO_API_VERSION {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_GET_API_VERSION".to_string(),
                std::io::Error::last_os_error(),
            )));
        };

        // Ioctl is safe. Called file is `/dev/vfio/vfio` fd and we check the return.
        let ret =
            unsafe { ioctl_with_val(&fd, VFIO_CHECK_EXTENSION(), vfio::VFIO_TYPE1v2_IOMMU.into()) };
        if ret != 1 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_CHECK_EXTENSION".to_string(),
                std::io::Error::last_os_error(),
            )));
        }

        Ok(VfioContainer {
            fd,
            groups: Mutex::new(HashMap::new()),
            enabled: false,
        })
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
        // Ioctl is safe. Called container file is `/dev/vfio/vfio` fd and we check the return.
        let ret = unsafe { ioctl_with_val(&self.fd, VFIO_SET_IOMMU(), val.into()) };
        if ret < 0 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_SET_IOMMU".to_string(),
                std::io::Error::last_os_error(),
            )));
        }
        Ok(())
    }

    /// Try to add a region of guest memory map into IOMMU table.
    ///
    /// # Arguments
    ///
    /// * `iova` - GPA of Guest memory region.
    /// * `size` - Region size.
    /// * `user_addr` - HVA of Guest memory region.
    ///
    /// Return Error if
    /// * Fail to map memory into IOMMU table.
    fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        let map = vfio::vfio_iommu_type1_dma_map {
            argsz: size_of::<vfio::vfio_iommu_type1_dma_map>() as u32,
            flags: vfio::VFIO_DMA_MAP_FLAG_READ | vfio::VFIO_DMA_MAP_FLAG_WRITE,
            vaddr: user_addr,
            iova,
            size,
        };

        // Ioctl is safe. Called container file is `/dev/vfio/vfio` fd and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.fd, VFIO_IOMMU_MAP_DMA(), &map) };
        if ret != 0 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_IOMMU_MAP_DMA".to_string(),
                std::io::Error::last_os_error(),
            )));
        }
        Ok(())
    }

    /// Unmap DMA region for the "type1" IOMMU interface.
    ///
    /// # Arguments
    ///
    /// * `iova` - GPA of Guest memory region.
    /// * `size` - Region size.
    ///
    /// Return Error if
    /// * Fail to unmap DMA region.
    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        let unmap = vfio::vfio_iommu_type1_dma_unmap {
            argsz: size_of::<vfio::vfio_iommu_type1_dma_unmap>() as u32,
            flags: 0,
            iova,
            size,
        };

        // Ioctl is safe. Called container file is `/dev/vfio/vfio` fd and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.fd, VFIO_IOMMU_UNMAP_DMA(), &unmap) };
        if ret != 0 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_IOMMU_UNMAP_DMA".to_string(),
                std::io::Error::last_os_error(),
            )));
        }
        Ok(())
    }

    fn add_listener_region(&self, fr: &FlatRange) -> address_space::Result<()> {
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
        address_space::Result::with_context(
            self.vfio_dma_map(guest_phys_addr, memory_size, userspace_addr),
            || {
                format!(
                    "Failed to do dma map: gpa 0x{:x}, size 0x{:x}, hva 0x{:x}",
                    guest_phys_addr, memory_size, userspace_addr
                )
            },
        )?;
        Ok(())
    }

    fn del_listener_region(&self, fr: &FlatRange) -> address_space::Result<()> {
        if fr.owner.region_type() != address_space::RegionType::Ram {
            return Ok(());
        }

        let guest_phys_addr = fr.addr_range.base.raw_value();
        let size = fr.addr_range.size;
        address_space::Result::with_context(self.vfio_dma_unmap(guest_phys_addr, size), || {
            format!(
                "Failed to do dma unmap: gpa 0x{:x}, size 0x{:x}.",
                guest_phys_addr, size
            )
        })?;
        Ok(())
    }
}

impl Listener for VfioContainer {
    fn priority(&self) -> i32 {
        0
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }

    fn handle_request(
        &self,
        range: Option<&FlatRange>,
        _evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> address_space::Result<()> {
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

/// Vfio group is a member of IOMMU group, which contains a set of devices isolated from all
/// other devices in the system.
/// A vfio group can be created by opening `/dev/vfio/$group_id`, where $group_id represents the
/// IOMMU group number.
pub struct VfioGroup {
    /// Group id.
    pub id: u32,
    /// `/dev/vfio/$group_id` file fd.
    pub fd: File,
    container: Weak<Mutex<VfioContainer>>,
    /// Devices in the group.
    pub devices: Mutex<HashMap<RawFd, Arc<Mutex<VfioDevice>>>>,
}

impl VfioGroup {
    fn new(group_id: u32) -> Result<Self> {
        let group_path = Path::new(GROUP_PATH).join(group_id.to_string());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&group_path)
            .with_context(|| {
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
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_GROUP_GET_STATUS".to_string(),
                std::io::Error::last_os_error(),
            )));
        }
        if status.flags != vfio::VFIO_GROUP_FLAGS_VIABLE {
            bail!(
                "Group is not viable, ensure all devices within the IOMMU group are bound to \
                their VFIO bus driver."
            );
        }

        Ok(VfioGroup {
            id: group_id,
            fd: file,
            container: Weak::new(),
            devices: Mutex::new(HashMap::new()),
        })
    }

    /// Add group to kvm VFIO device.
    ///
    /// Return Error if
    /// * Fail to set group to kvm device.
    fn add_to_kvm_device(&self) -> Result<()> {
        let attr = kvm_device_attr {
            flags: 0,
            group: KVM_DEV_VFIO_GROUP,
            attr: u64::from(KVM_DEV_VFIO_GROUP_ADD),
            addr: &self.fd.as_raw_fd() as *const i32 as u64,
        };
        match KVM_DEVICE_FD.as_ref() {
            Some(fd) => fd
                .set_device_attr(&attr)
                .with_context(|| "Failed to add group to kvm device.")?,
            None => bail!("Failed to create kvm device."),
        }
        Ok(())
    }

    /// Delete group from kvm VFIO device.
    ///
    /// Return Error if
    /// * Fail to delete group.
    pub fn del_from_kvm_device(&self) -> Result<()> {
        let attr = kvm_device_attr {
            flags: 0,
            group: KVM_DEV_VFIO_GROUP,
            attr: u64::from(KVM_DEV_VFIO_GROUP_DEL),
            addr: &self.fd.as_raw_fd() as *const i32 as u64,
        };
        match KVM_DEVICE_FD.as_ref() {
            Some(fd) => fd
                .set_device_attr(&attr)
                .with_context(|| "Failed to delete group from kvm device.")?,
            None => bail!("Kvm device hasn't been created."),
        }
        Ok(())
    }

    fn set_container(&mut self, container: &Arc<Mutex<VfioContainer>>) -> Result<()> {
        let fd = &container.lock().unwrap().fd.as_raw_fd();
        // Safe as group is the owner of file, and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.fd, VFIO_GROUP_SET_CONTAINER(), fd) };
        if ret < 0 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_GROUP_SET_CONTAINER".to_string(),
                std::io::Error::last_os_error(),
            )));
        }
        self.container = Arc::downgrade(container);
        Ok(())
    }

    fn unset_container(&mut self) {
        let container = self.container.upgrade().unwrap();
        let fd = container.lock().unwrap().fd.as_raw_fd();
        unsafe { ioctl_with_ref(&self.fd, VFIO_GROUP_UNSET_CONTAINER(), &fd) };
        self.container = Weak::new();
    }

    fn connect_container(&mut self, mem_as: &Arc<AddressSpace>) -> Result<()> {
        for (_fd, container) in CONTAINERS.lock().unwrap().iter() {
            if self.set_container(container).is_ok() {
                self.add_to_kvm_device()?;
                return Ok(());
            }
        }

        // No containers existed or can not be attached to the existed containers.
        if self.container.upgrade().is_none() {
            let container = Arc::new(Mutex::new(VfioContainer::new()?));
            self.set_container(&container)?;
            container
                .lock()
                .unwrap()
                .set_iommu(vfio::VFIO_TYPE1v2_IOMMU)?;

            let fd = container.lock().unwrap().fd.as_raw_fd();
            CONTAINERS.lock().unwrap().insert(fd, container);
        }
        self.add_to_kvm_device()?;
        mem_as
            .register_listener(self.container.upgrade().unwrap())
            .with_context(|| "Failed to register memory listener.")?;
        Ok(())
    }
}

pub struct VfioDevInfo {
    pub num_irqs: u32,
    flags: u32,
}

/// Vfio device includes the group and container it belongs to, I/O regions and interrupt
/// notifications info.
pub struct VfioDevice {
    /// File descriptor for a VFIO device instance.
    pub fd: File,
    /// Identify the unique VFIO device.
    pub name: String,
    /// Vfio group the device belongs to.
    pub group: Weak<VfioGroup>,
    /// Vfio container the device belongs to.
    pub container: Weak<Mutex<VfioContainer>>,
    /// Information of the vfio device instance.
    pub dev_info: VfioDevInfo,
    /// Unmasked MSI-X vectors.
    pub nr_vectors: usize,
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
    pub fn new(path: &Path, mem_as: &Arc<AddressSpace>) -> Result<Arc<Mutex<Self>>> {
        if !path.exists() {
            bail!("No provided host PCI device, use -device vfio-pci,host=DDDD:BB:DD.F");
        }

        let group =
            Self::vfio_get_group(path, mem_as).with_context(|| "Failed to get iommu group")?;
        let (name, fd) =
            Self::vfio_get_device(&group, path).with_context(|| "Failed to get vfio device")?;
        let dev_info = Self::get_dev_info(&fd).with_context(|| "Failed to get device info")?;
        let vfio_dev = Arc::new(Mutex::new(VfioDevice {
            fd,
            name,
            group: Arc::downgrade(&group),
            container: group.container.clone(),
            dev_info,
            nr_vectors: 0,
        }));
        group
            .devices
            .lock()
            .unwrap()
            .insert(vfio_dev.lock().unwrap().fd.as_raw_fd(), vfio_dev.clone());
        Ok(vfio_dev)
    }

    fn vfio_get_group(dev_path: &Path, mem_as: &Arc<AddressSpace>) -> Result<Arc<VfioGroup>> {
        let iommu_group: PathBuf = [dev_path, Path::new(IOMMU_GROUP)]
            .iter()
            .collect::<PathBuf>()
            .read_link()
            .with_context(|| "Invalid iommu group path")?;
        let group_name = iommu_group
            .file_name()
            .with_context(|| "Invalid iommu group name")?;
        let mut group_id = 0;
        if let Some(n) = group_name.to_str() {
            group_id = n.parse::<u32>().with_context(|| "Invalid iommu group id")?;
        }

        if let Some(g) = GROUPS.lock().unwrap().get(&group_id) {
            return Ok(g.clone());
        }
        let mut group = VfioGroup::new(group_id)?;
        if let Err(e) = group.connect_container(mem_as) {
            group.unset_container();
            return Err(e);
        }
        let group = Arc::new(group);
        GROUPS.lock().unwrap().insert(group_id, group.clone());
        group
            .container
            .upgrade()
            .unwrap()
            .lock()
            .unwrap()
            .groups
            .lock()
            .unwrap()
            .insert(group_id, group.clone());
        Ok(group)
    }

    fn vfio_get_device(group: &VfioGroup, name: &Path) -> Result<(String, File)> {
        let mut dev_name: &str = "";
        if let Some(n) = name.file_name() {
            dev_name = n.to_str().with_context(|| "Invalid device path")?;
        }

        for device in group.devices.lock().unwrap().iter() {
            if device.1.lock().unwrap().name == dev_name {
                bail!("Device {} is already attached", dev_name);
            }
        }

        let path: CString = CString::new(dev_name.as_bytes())
            .with_context(|| "Failed to convert device name to CString type of data")?;
        let ptr = path.as_ptr();
        // Safe as group is the owner of file and make sure ptr is valid.
        let fd = unsafe { ioctl_with_ptr(&group.fd, VFIO_GROUP_GET_DEVICE_FD(), ptr) };
        if fd < 0 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_GROUP_GET_DEVICE_FD".to_string(),
                std::io::Error::last_os_error(),
            )));
        }

        // Safe as we have verified that fd is a valid FD.
        let device = unsafe { File::from_raw_fd(fd) };
        Ok((String::from(dev_name), device))
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
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_DEVICE_GET_INFO".to_string(),
                std::io::Error::last_os_error(),
            )));
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
                        &self.fd,
                        VFIO_DEVICE_GET_REGION_INFO(),
                        &mut (new_info[0].region_info),
                    )
                };
                if ret < 0 {
                    return Err(anyhow!(VfioError::VfioIoctl(
                        "VFIO_DEVICE_GET_REGION_INFO".to_string(),
                        std::io::Error::last_os_error(),
                    )));
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
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, VFIO_DEVICE_GET_REGION_INFO(), &mut info) };
        if ret < 0 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_DEVICE_GET_REGION_INFO".to_string(),
                std::io::Error::last_os_error(),
            )));
        }

        Ok(info)
    }

    pub fn get_regions_info(&self) -> Result<Vec<VfioRegion>> {
        let mut regions: Vec<VfioRegion> = Vec::new();
        for index in vfio::VFIO_PCI_BAR0_REGION_INDEX..vfio::VFIO_PCI_ROM_REGION_INDEX {
            let info = self
                .region_info(index)
                .with_context(|| "Fail to get region info")?;

            let mut mmaps = Vec::new();
            if info.size > 0 {
                mmaps = self
                    .region_mmap_info(info)
                    .with_context(|| "Fail to get region mmap info")?;
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
                unsafe { ioctl_with_mut_ref(&self.fd, VFIO_DEVICE_GET_IRQ_INFO(), &mut info) };
            if ret < 0 {
                warn!(
                    "VFIO_DEVICE_GET_IRQ_INFO return irq type{} not supported",
                    index
                );
                continue;
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
        self.fd
            .read_exact_at(buf, region_offset + addr)
            .with_context(|| "Failed to read vfio region")?;

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
        self.fd
            .write_all_at(buf, region_offset + addr)
            .with_context(|| "Failed to write vfio region")?;

        Ok(())
    }

    /// Bind irqs to kvm interrupts.
    ///
    /// # Arguments
    ///
    /// * `irq_fds` - Irq fds that will be registered to kvm.
    /// * `start` - The start of subindexes being specified.
    pub fn enable_irqs(&mut self, irq_fds: Vec<RawFd>, start: u32) -> Result<()> {
        let mut irq_set = array_to_vec::<vfio::vfio_irq_set, u32>(irq_fds.len());
        irq_set[0].argsz =
            (size_of::<vfio::vfio_irq_set>() + irq_fds.len() * size_of::<RawFd>()) as u32;
        irq_set[0].flags = vfio::VFIO_IRQ_SET_DATA_EVENTFD | vfio::VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = vfio::VFIO_PCI_MSIX_IRQ_INDEX;
        irq_set[0].start = start;
        irq_set[0].count = irq_fds.len() as u32;

        // It is safe as enough memory space to save irq_set data.
        let data: &mut [u8] = unsafe {
            irq_set[0]
                .data
                .as_mut_slice(irq_fds.len() * size_of::<RawFd>())
        };
        LittleEndian::write_i32_into(irq_fds.as_slice(), data);
        // Safe as device is the owner of file, and we will verify the result is valid.
        let ret = unsafe { ioctl_with_ref(&self.fd, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_DEVICE_SET_IRQS".to_string(),
                std::io::Error::last_os_error(),
            )));
        }
        Ok(())
    }

    /// Unbind irqs from kvm interrupts.
    ///
    /// # Arguments
    ///
    /// * `irq_fds` - Irq fds that will be registered to kvm.
    pub fn disable_irqs(&mut self) -> Result<()> {
        if self.nr_vectors == 0 {
            return Ok(());
        }

        let mut irq_set = array_to_vec::<vfio::vfio_irq_set, u32>(0);
        irq_set[0].argsz = size_of::<vfio::vfio_irq_set>() as u32;
        irq_set[0].flags = vfio::VFIO_IRQ_SET_DATA_NONE | vfio::VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = vfio::VFIO_PCI_MSIX_IRQ_INDEX;
        irq_set[0].start = 0u32;
        irq_set[0].count = 0u32;

        // Safe as device is the owner of file, and we will verify the result is valid.
        let ret = unsafe { ioctl_with_ref(&self.fd, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            return Err(anyhow!(VfioError::VfioIoctl(
                "VFIO_DEVICE_SET_IRQS".to_string(),
                std::io::Error::last_os_error(),
            )));
        }
        self.nr_vectors = 0;
        Ok(())
    }

    pub fn reset(&self) -> Result<()> {
        // Safe as device is the owner of file, and we verify the device supports being reset.
        if self.dev_info.flags & vfio::VFIO_DEVICE_FLAGS_RESET != 0 {
            let ret = unsafe { ioctl(&self.fd, VFIO_DEVICE_RESET()) };
            if ret < 0 {
                return Err(anyhow!(VfioError::VfioIoctl(
                    "VFIO_DEVICE_RESET".to_string(),
                    std::io::Error::last_os_error(),
                )));
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
