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

//! # Micro VM
//!
//! Micro VM is a extremely light machine type.
//! It has a very simple machine model, which benefits to a very short
//! boot-time and tiny memory usage.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. Create and manage lifecycle for `Micro VM`.
//! 2. Set cmdline arguments parameters for `Micro VM`.
//! 3. Manage mainloop to handle events for `Micro VM` and its devices.
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`

pub mod syscall;

use std::fmt;
use std::fmt::Debug;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info};

#[cfg(target_arch = "aarch64")]
use crate::aarch64::micro::{LayoutEntryType, MEM_LAYOUT};
#[cfg(target_arch = "x86_64")]
use crate::x86_64::micro::{LayoutEntryType, MEM_LAYOUT};
use crate::{MachineBase, MachineError, MachineOps};
use cpu::CpuLifecycleState;
use devices::sysbus::{IRQ_BASE, IRQ_MAX};
use machine_manager::config::{
    parse_blk, parse_incoming_uri, parse_net, BlkDevConfig, ConfigCheck, DiskFormat, MigrateMode,
    NetworkInterfaceConfig, VmConfig, DEFAULT_VIRTQUEUE_SIZE,
};
use machine_manager::event;
use machine_manager::event_loop::EventLoop;
use machine_manager::machine::{
    DeviceInterface, MachineAddressInterface, MachineExternalInterface, MachineInterface,
    MachineLifecycle, MigrateInterface, VmState,
};
use machine_manager::qmp::{
    qmp_channel::QmpChannel, qmp_response::Response, qmp_schema, qmp_schema::UpdateRegionArgument,
};
use migration::MigrationManager;
use util::aio::WriteZeroesState;
use util::{loop_context::EventLoopManager, num_ops::str_to_num, set_termi_canon_mode};
use virtio::{
    create_tap, qmp_balloon, qmp_query_balloon, Block, BlockState, Net, VhostKern, VhostUser,
    VirtioDevice, VirtioMmioDevice, VirtioMmioState, VirtioNetState,
};

// The replaceable block device maximum count.
const MMIO_REPLACEABLE_BLK_NR: usize = 4;
// The replaceable network device maximum count.
const MMIO_REPLACEABLE_NET_NR: usize = 2;

// The config of replaceable device.
#[derive(Debug)]
struct MmioReplaceableConfig {
    // Device id.
    id: String,
    // The dev_config of the related backend device.
    dev_config: Arc<dyn ConfigCheck>,
}

// The device information of replaceable device.
struct MmioReplaceableDevInfo {
    // The related MMIO device.
    device: Arc<Mutex<dyn VirtioDevice>>,
    // Device id.
    id: String,
    // Identify if this device is be used.
    used: bool,
}

impl fmt::Debug for MmioReplaceableDevInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmioReplaceableDevInfo")
            .field("device_type", &self.device.lock().unwrap().device_type())
            .field("id", &self.id)
            .field("used", &self.used)
            .finish()
    }
}

// The gather of config, info and count of all replaceable devices.
#[derive(Debug)]
pub(crate) struct MmioReplaceableInfo {
    // The arrays of all replaceable configs.
    configs: Arc<Mutex<Vec<MmioReplaceableConfig>>>,
    // The arrays of all replaceable device information.
    devices: Arc<Mutex<Vec<MmioReplaceableDevInfo>>>,
    // The count of block device which is plugin.
    pub(crate) block_count: usize,
    // The count of network device which is plugin.
    pub(crate) net_count: usize,
}

impl MmioReplaceableInfo {
    fn new() -> Self {
        MmioReplaceableInfo {
            configs: Arc::new(Mutex::new(Vec::new())),
            devices: Arc::new(Mutex::new(Vec::new())),
            block_count: 0_usize,
            net_count: 0_usize,
        }
    }
}

/// A wrapper around creating and using a micro VM.
pub struct LightMachine {
    // Machine base members.
    pub(crate) base: MachineBase,
    // All replaceable device information.
    pub(crate) replaceable_info: MmioReplaceableInfo,
}

impl LightMachine {
    /// Constructs a new `LightMachine`.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - Represents the configuration for VM.
    pub fn new(vm_config: &VmConfig) -> Result<Self> {
        let free_irqs: (i32, i32) = (IRQ_BASE, IRQ_MAX);
        let mmio_region: (u64, u64) = (
            MEM_LAYOUT[LayoutEntryType::Mmio as usize].0,
            MEM_LAYOUT[LayoutEntryType::Mmio as usize + 1].0,
        );
        let base = MachineBase::new(vm_config, free_irqs, mmio_region)?;

        Ok(LightMachine {
            base,
            replaceable_info: MmioReplaceableInfo::new(),
        })
    }

    pub(crate) fn create_replaceable_devices(&mut self) -> Result<()> {
        let mut rpl_devs: Vec<VirtioMmioDevice> = Vec::new();
        for id in 0..MMIO_REPLACEABLE_BLK_NR {
            let block = Arc::new(Mutex::new(Block::new(
                BlkDevConfig::default(),
                self.get_drive_files(),
            )));
            let virtio_mmio = VirtioMmioDevice::new(&self.base.sys_mem, block.clone());
            rpl_devs.push(virtio_mmio);

            MigrationManager::register_device_instance(
                BlockState::descriptor(),
                block,
                &id.to_string(),
            );
        }
        for id in 0..MMIO_REPLACEABLE_NET_NR {
            let net = Arc::new(Mutex::new(Net::new(NetworkInterfaceConfig::default())));
            let virtio_mmio = VirtioMmioDevice::new(&self.base.sys_mem, net.clone());
            rpl_devs.push(virtio_mmio);

            MigrationManager::register_device_instance(
                VirtioNetState::descriptor(),
                net,
                &id.to_string(),
            );
        }

        let mut region_base = self.base.sysbus.min_free_base;
        let region_size = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;
        for (id, dev) in rpl_devs.into_iter().enumerate() {
            self.replaceable_info
                .devices
                .lock()
                .unwrap()
                .push(MmioReplaceableDevInfo {
                    device: dev.device.clone(),
                    id: id.to_string(),
                    used: false,
                });

            MigrationManager::register_transport_instance(
                VirtioMmioState::descriptor(),
                VirtioMmioDevice::realize(
                    dev,
                    &mut self.base.sysbus,
                    region_base,
                    MEM_LAYOUT[LayoutEntryType::Mmio as usize].1,
                    #[cfg(target_arch = "x86_64")]
                    &self.base.boot_source,
                )
                .with_context(|| MachineError::RlzVirtioMmioErr)?,
                &id.to_string(),
            );
            region_base += region_size;
        }
        self.base.sysbus.min_free_base = region_base;
        Ok(())
    }

    pub(crate) fn fill_replaceable_device(
        &mut self,
        id: &str,
        dev_config: Arc<dyn ConfigCheck>,
        index: usize,
    ) -> Result<()> {
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        if let Some(device_info) = replaceable_devices.get_mut(index) {
            if device_info.used {
                bail!("{}: index {} is already used.", id, index);
            }

            device_info.id = id.to_string();
            device_info.used = true;
            device_info
                .device
                .lock()
                .unwrap()
                .update_config(Some(dev_config.clone()))
                .with_context(|| MachineError::UpdCfgErr(id.to_string()))?;
        }

        self.add_replaceable_config(id, dev_config)
    }

    fn add_replaceable_config(&self, id: &str, dev_config: Arc<dyn ConfigCheck>) -> Result<()> {
        let mut configs_lock = self.replaceable_info.configs.lock().unwrap();
        let limit = MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR;
        if configs_lock.len() >= limit {
            return Err(anyhow!(MachineError::RplDevLmtErr("".to_string(), limit)));
        }

        for config in configs_lock.iter() {
            if config.id == id {
                bail!("{} is already registered.", id);
            }
        }

        let config = MmioReplaceableConfig {
            id: id.to_string(),
            dev_config,
        };

        trace::mmio_replaceable_config(&config);
        configs_lock.push(config);
        Ok(())
    }

    fn add_replaceable_device(&self, id: &str, driver: &str, slot: usize) -> Result<()> {
        // Find the configuration by id.
        let configs_lock = self.replaceable_info.configs.lock().unwrap();
        let mut dev_config = None;
        for config in configs_lock.iter() {
            if config.id == id {
                dev_config = Some(config.dev_config.clone());
            }
        }
        if dev_config.is_none() {
            bail!("Failed to find device configuration.");
        }

        // Sanity check for config, driver and slot.
        let cfg_any = dev_config.as_ref().unwrap().as_any();
        let index = if driver.contains("net") {
            if slot >= MMIO_REPLACEABLE_NET_NR {
                return Err(anyhow!(MachineError::RplDevLmtErr(
                    "net".to_string(),
                    MMIO_REPLACEABLE_NET_NR
                )));
            }
            if cfg_any.downcast_ref::<NetworkInterfaceConfig>().is_none() {
                return Err(anyhow!(MachineError::DevTypeErr("net".to_string())));
            }
            slot + MMIO_REPLACEABLE_BLK_NR
        } else if driver.contains("blk") {
            if slot >= MMIO_REPLACEABLE_BLK_NR {
                return Err(anyhow!(MachineError::RplDevLmtErr(
                    "block".to_string(),
                    MMIO_REPLACEABLE_BLK_NR
                )));
            }
            if cfg_any.downcast_ref::<BlkDevConfig>().is_none() {
                return Err(anyhow!(MachineError::DevTypeErr("blk".to_string())));
            }
            slot
        } else {
            bail!("Unsupported replaceable device type.");
        };

        // Find the replaceable device and replace it.
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        if let Some(device_info) = replaceable_devices.get_mut(index) {
            if device_info.used {
                bail!("The slot {} is occupied already.", slot);
            }

            device_info.id = id.to_string();
            device_info.used = true;
            device_info
                .device
                .lock()
                .unwrap()
                .update_config(dev_config)
                .with_context(|| MachineError::UpdCfgErr(id.to_string()))?;
        }
        Ok(())
    }

    fn del_replaceable_device(&self, id: &str) -> Result<String> {
        // find the index of configuration by name and remove it
        let mut is_exist = false;
        let mut configs_lock = self.replaceable_info.configs.lock().unwrap();
        for (index, config) in configs_lock.iter().enumerate() {
            if config.id == id {
                if let Some(blkconf) = config.dev_config.as_any().downcast_ref::<BlkDevConfig>() {
                    self.unregister_drive_file(&blkconf.path_on_host)?;
                }
                configs_lock.remove(index);
                is_exist = true;
                break;
            }
        }

        // set the status of the device to 'unused'
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        for device_info in replaceable_devices.iter_mut() {
            if device_info.id == id {
                device_info.id = "".to_string();
                device_info.used = false;
                device_info
                    .device
                    .lock()
                    .unwrap()
                    .update_config(None)
                    .with_context(|| MachineError::UpdCfgErr(id.to_string()))?;
            }
        }

        if !is_exist {
            bail!("Device {} not found", id);
        }
        Ok(id.to_string())
    }

    pub(crate) fn add_virtio_mmio_net(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
    ) -> Result<()> {
        let device_cfg = parse_net(vm_config, cfg_args)?;
        if device_cfg.vhost_type.is_some() {
            let device = if device_cfg.vhost_type == Some(String::from("vhost-kernel")) {
                let net = Arc::new(Mutex::new(VhostKern::Net::new(
                    &device_cfg,
                    &self.base.sys_mem,
                )));
                VirtioMmioDevice::new(&self.base.sys_mem, net)
            } else {
                let net = Arc::new(Mutex::new(VhostUser::Net::new(
                    &device_cfg,
                    &self.base.sys_mem,
                )));
                VirtioMmioDevice::new(&self.base.sys_mem, net)
            };
            self.realize_virtio_mmio_device(device)?;
        } else {
            let index = MMIO_REPLACEABLE_BLK_NR + self.replaceable_info.net_count;
            if index >= MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR {
                bail!(
                    "A maximum of {} net replaceable devices are supported.",
                    MMIO_REPLACEABLE_NET_NR
                );
            }
            self.fill_replaceable_device(&device_cfg.id, Arc::new(device_cfg.clone()), index)?;
            self.replaceable_info.net_count += 1;
        }
        Ok(())
    }

    pub(crate) fn add_virtio_mmio_block(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
    ) -> Result<()> {
        let device_cfg = parse_blk(vm_config, cfg_args, None)?;
        if self.replaceable_info.block_count >= MMIO_REPLACEABLE_BLK_NR {
            bail!(
                "A maximum of {} block replaceable devices are supported.",
                MMIO_REPLACEABLE_BLK_NR
            );
        }
        let index = self.replaceable_info.block_count;
        self.fill_replaceable_device(&device_cfg.id, Arc::new(device_cfg.clone()), index)?;
        self.replaceable_info.block_count += 1;
        Ok(())
    }

    pub(crate) fn realize_virtio_mmio_device(
        &mut self,
        dev: VirtioMmioDevice,
    ) -> Result<Arc<Mutex<VirtioMmioDevice>>> {
        let region_base = self.base.sysbus.min_free_base;
        let region_size = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;
        let realized_virtio_mmio_device = VirtioMmioDevice::realize(
            dev,
            &mut self.base.sysbus,
            region_base,
            region_size,
            #[cfg(target_arch = "x86_64")]
            &self.base.boot_source,
        )
        .with_context(|| MachineError::RlzVirtioMmioErr)?;
        self.base.sysbus.min_free_base += region_size;
        Ok(realized_virtio_mmio_device)
    }
}

impl MachineLifecycle for LightMachine {
    fn pause(&self) -> bool {
        if self.notify_lifecycle(VmState::Running, VmState::Paused) {
            event!(Stop);
            true
        } else {
            false
        }
    }

    fn resume(&self) -> bool {
        if !self.notify_lifecycle(VmState::Paused, VmState::Running) {
            return false;
        }

        event!(Resume);
        true
    }

    fn destroy(&self) -> bool {
        let vmstate = {
            let state = self.base.vm_state.deref().0.lock().unwrap();
            *state
        };

        if !self.notify_lifecycle(vmstate, VmState::Shutdown) {
            return false;
        }

        info!("vm destroy");
        EventLoop::get_ctx(None).unwrap().kick();

        true
    }

    fn reset(&mut self) -> bool {
        // For micro vm, the reboot command is equivalent to the shutdown command.
        for cpu in self.base.cpus.iter() {
            let (cpu_state, _) = cpu.state();
            *cpu_state.lock().unwrap() = CpuLifecycleState::Stopped;
        }

        self.destroy()
    }

    fn notify_lifecycle(&self, old: VmState, new: VmState) -> bool {
        if let Err(e) = self.vm_state_transfer(
            &self.base.cpus,
            #[cfg(target_arch = "aarch64")]
            &self.base.irq_chip,
            &mut self.base.vm_state.0.lock().unwrap(),
            old,
            new,
        ) {
            error!("VM state transfer failed: {:?}", e);
            return false;
        }
        true
    }
}

impl MachineAddressInterface for LightMachine {
    #[cfg(target_arch = "x86_64")]
    fn pio_in(&self, addr: u64, data: &mut [u8]) -> bool {
        self.machine_base().pio_in(addr, data)
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_out(&self, addr: u64, mut data: &[u8]) -> bool {
        use address_space::GuestAddress;

        let count = data.len() as u64;
        self.base
            .sys_io
            .write(&mut data, GuestAddress(addr), count)
            .is_ok()
    }

    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> bool {
        self.machine_base().mmio_read(addr, data)
    }

    fn mmio_write(&self, addr: u64, data: &[u8]) -> bool {
        self.machine_base().mmio_write(addr, data)
    }
}

impl DeviceInterface for LightMachine {
    fn query_status(&self) -> Response {
        let vmstate = self.get_vm_state().deref().0.lock().unwrap();
        let qmp_state = match *vmstate {
            VmState::Running => qmp_schema::StatusInfo {
                singlestep: false,
                running: true,
                status: qmp_schema::RunState::running,
            },
            VmState::Paused => qmp_schema::StatusInfo {
                singlestep: false,
                running: false,
                status: qmp_schema::RunState::paused,
            },
            _ => Default::default(),
        };

        Response::create_response(serde_json::to_value(qmp_state).unwrap(), None)
    }

    fn query_cpus(&self) -> Response {
        let mut cpu_vec: Vec<serde_json::Value> = Vec::new();
        let cpu_topo = self.get_cpu_topo();
        let cpus = self.get_cpus();
        for cpu_index in 0..cpu_topo.max_cpus {
            if cpu_topo.get_mask(cpu_index as usize) == 1 {
                let thread_id = cpus[cpu_index as usize].tid();
                let cpu_instance = cpu_topo.get_topo_instance_for_qmp(cpu_index as usize);
                let cpu_common = qmp_schema::CpuInfoCommon {
                    current: true,
                    qom_path: String::from("/machine/unattached/device[")
                        + &cpu_index.to_string()
                        + "]",
                    halted: false,
                    props: Some(cpu_instance),
                    CPU: cpu_index as isize,
                    thread_id: thread_id as isize,
                };
                #[cfg(target_arch = "x86_64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::x86 {
                        common: cpu_common,
                        x86: qmp_schema::CpuInfoX86 {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
                #[cfg(target_arch = "aarch64")]
                {
                    let cpu_info = qmp_schema::CpuInfo::Arm {
                        common: cpu_common,
                        arm: qmp_schema::CpuInfoArm {},
                    };
                    cpu_vec.push(serde_json::to_value(cpu_info).unwrap());
                }
            }
        }
        Response::create_response(cpu_vec.into(), None)
    }

    fn query_hotpluggable_cpus(&self) -> Response {
        let mut hotplug_vec: Vec<serde_json::Value> = Vec::new();
        #[cfg(target_arch = "x86_64")]
        let cpu_type = String::from("host-x86-cpu");
        #[cfg(target_arch = "aarch64")]
        let cpu_type = String::from("host-aarch64-cpu");

        for cpu_index in 0..self.base.cpu_topo.max_cpus {
            if self.base.cpu_topo.get_mask(cpu_index as usize) == 0 {
                let cpu_instance = self
                    .base
                    .cpu_topo
                    .get_topo_instance_for_qmp(cpu_index as usize);
                let hotpluggable_cpu = qmp_schema::HotpluggableCPU {
                    type_: cpu_type.clone(),
                    vcpus_count: 1,
                    props: cpu_instance,
                    qom_path: None,
                };
                hotplug_vec.push(serde_json::to_value(hotpluggable_cpu).unwrap());
            } else {
                let cpu_instance = self
                    .base
                    .cpu_topo
                    .get_topo_instance_for_qmp(cpu_index as usize);
                let hotpluggable_cpu = qmp_schema::HotpluggableCPU {
                    type_: cpu_type.clone(),
                    vcpus_count: 1,
                    props: cpu_instance,
                    qom_path: Some(
                        String::from("/machine/unattached/device[") + &cpu_index.to_string() + "]",
                    ),
                };
                hotplug_vec.push(serde_json::to_value(hotpluggable_cpu).unwrap());
            }
        }
        Response::create_response(hotplug_vec.into(), None)
    }

    fn balloon(&self, value: u64) -> Response {
        if qmp_balloon(value) {
            return Response::create_empty_response();
        }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn query_balloon(&self) -> Response {
        if let Some(actual) = qmp_query_balloon() {
            let ret = qmp_schema::BalloonInfo { actual };
            return Response::create_response(serde_json::to_value(ret).unwrap(), None);
        }
        Response::create_error_response(
            qmp_schema::QmpErrorClass::DeviceNotActive(
                "No balloon device has been activated".to_string(),
            ),
            None,
        )
    }

    fn query_mem(&self) -> Response {
        self.mem_show();
        Response::create_empty_response()
    }

    /// VNC is not supported by light machine currently.
    fn query_vnc(&self) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "The service of VNC is not supported".to_string(),
            ),
            None,
        )
    }

    fn query_display_image(&self) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "query-display-image is not supported".to_string(),
            ),
            None,
        )
    }

    fn device_add(&mut self, args: Box<qmp_schema::DeviceAddArgument>) -> Response {
        // get slot of bus by addr or lun
        let mut slot = 0;
        if let Some(addr) = args.addr {
            if let Ok(num) = str_to_num::<usize>(&addr) {
                slot = num;
            } else {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(format!(
                        "Invalid addr for device {}",
                        args.id
                    )),
                    None,
                );
            }
        } else if let Some(lun) = args.lun {
            slot = lun + 1;
        }

        match self.add_replaceable_device(&args.id, &args.driver, slot) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                error!("Failed to add device: id {}, type {}", args.id, args.driver);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn device_del(&mut self, device_id: String) -> Response {
        match self.del_replaceable_device(&device_id) {
            Ok(path) => {
                let block_del_event = qmp_schema::DeviceDeleted {
                    device: Some(device_id),
                    path,
                };
                event!(DeviceDeleted; block_del_event);

                Response::create_empty_response()
            }
            Err(ref e) => {
                error!("Failed to delete device: {:?}", e);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn blockdev_add(&self, args: Box<qmp_schema::BlockDevAddArgument>) -> Response {
        let read_only = args.read_only.unwrap_or(false);
        let mut direct = true;
        if args.cache.is_some() && !args.cache.unwrap().direct.unwrap_or(true) {
            direct = false;
        }

        let config = BlkDevConfig {
            id: args.node_name.clone(),
            path_on_host: args.file.filename.clone(),
            read_only,
            direct,
            serial_num: None,
            iothread: None,
            iops: None,
            queues: 1,
            boot_index: None,
            chardev: None,
            socket_path: None,
            aio: args.file.aio,
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
            format: DiskFormat::Raw,
            l2_cache_size: None,
            refcount_cache_size: None,
        };
        if let Err(e) = config.check() {
            error!("{:?}", e);
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }
        // Register drive backend file for hotplugged drive.
        if let Err(e) = self.register_drive_file(&config.id, &args.file.filename, read_only, direct)
        {
            error!("{:?}", e);
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }
        match self.add_replaceable_config(&args.node_name, Arc::new(config)) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                // It's safe to unwrap as the path has been registered.
                self.unregister_drive_file(&args.file.filename).unwrap();
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn blockdev_del(&self, _node_name: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("blockdev_del not support yet".to_string()),
            None,
        )
    }

    fn netdev_add(&mut self, args: Box<qmp_schema::NetDevAddArgument>) -> Response {
        let mut config = NetworkInterfaceConfig {
            id: args.id.clone(),
            host_dev_name: "".to_string(),
            mac: None,
            tap_fds: None,
            vhost_type: None,
            vhost_fds: None,
            iothread: None,
            queues: 2,
            mq: false,
            socket_path: None,
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
        };

        if let Some(fds) = args.fds {
            let netdev_fd = if fds.contains(':') {
                let col: Vec<_> = fds.split(':').collect();
                String::from(col[col.len() - 1])
            } else {
                String::from(&fds)
            };

            if let Some(fd_num) = QmpChannel::get_fd(&netdev_fd) {
                config.tap_fds = Some(vec![fd_num]);
            } else {
                // try to convert string to RawFd
                let fd_num = match netdev_fd.parse::<i32>() {
                    Ok(fd) => fd,
                    _ => {
                        error!(
                            "Add netdev error: failed to convert {} to RawFd.",
                            netdev_fd
                        );
                        return Response::create_error_response(
                            qmp_schema::QmpErrorClass::GenericError(
                                "Add netdev error: failed to convert {} to RawFd.".to_string(),
                            ),
                            None,
                        );
                    }
                };
                config.tap_fds = Some(vec![fd_num]);
            }
        } else if let Some(if_name) = args.if_name {
            config.host_dev_name = if_name.clone();
            if create_tap(None, Some(&if_name), 1).is_err() {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "Tap device already in use".to_string(),
                    ),
                    None,
                );
            }
        }

        match self.add_replaceable_config(&args.id, Arc::new(config)) {
            Ok(()) => Response::create_empty_response(),
            Err(ref e) => {
                error!("{:?}", e);
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                    None,
                )
            }
        }
    }

    fn netdev_del(&mut self, _node_name: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("netdev_del not support yet".to_string()),
            None,
        )
    }

    fn chardev_add(&mut self, _args: qmp_schema::CharDevAddArgument) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "chardev_add not supported yet for microVM".to_string(),
            ),
            None,
        )
    }

    fn chardev_remove(&mut self, _id: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "chardev_remove not supported yet for microVM".to_string(),
            ),
            None,
        )
    }

    fn cameradev_add(&mut self, _args: qmp_schema::CameraDevAddArgument) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "cameradev_add not supported for MicroVM".to_string(),
            ),
            None,
        )
    }

    fn cameradev_del(&mut self, _id: String) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(
                "cameradev_del not supported for MicroVM".to_string(),
            ),
            None,
        )
    }

    fn getfd(&self, fd_name: String, if_fd: Option<RawFd>) -> Response {
        if let Some(fd) = if_fd {
            QmpChannel::set_fd(fd_name, fd);
            Response::create_empty_response()
        } else {
            let err_resp =
                qmp_schema::QmpErrorClass::GenericError("Invalid SCM message".to_string());
            Response::create_error_response(err_resp, None)
        }
    }

    fn update_region(&mut self, _args: UpdateRegionArgument) -> Response {
        Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError("The micro vm is not supported".to_string()),
            None,
        )
    }
}

impl MigrateInterface for LightMachine {
    fn migrate(&self, uri: String) -> Response {
        match parse_incoming_uri(&uri) {
            Ok((MigrateMode::File, path)) => migration::snapshot(path),
            Ok((MigrateMode::Unix, _)) | Ok((MigrateMode::Tcp, _)) => {
                Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "MicroVM does not support migration".to_string(),
                    ),
                    None,
                )
            }
            _ => Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(format!("Invalid uri: {}", uri)),
                None,
            ),
        }
    }

    fn query_migrate(&self) -> Response {
        migration::query_migrate()
    }
}

impl MachineInterface for LightMachine {}
impl MachineExternalInterface for LightMachine {}

impl EventLoopManager for LightMachine {
    fn loop_should_exit(&self) -> bool {
        let vmstate = self.base.vm_state.deref().0.lock().unwrap();
        *vmstate == VmState::Shutdown
    }

    fn loop_cleanup(&self) -> Result<()> {
        set_termi_canon_mode().with_context(|| "Failed to set terminal to canonical mode")?;
        Ok(())
    }
}
