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
use clap::Parser;
use log::error;
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_arch = "aarch64")]
use crate::aarch64::micro::{LayoutEntryType, MEM_LAYOUT};
#[cfg(target_arch = "x86_64")]
use crate::x86_64::micro::{LayoutEntryType, MEM_LAYOUT};
use crate::{MachineBase, MachineError, MachineOps};
use cpu::CpuLifecycleState;
#[cfg(target_arch = "x86_64")]
use devices::sysbus::SysBusDevOps;
use devices::sysbus::{IRQ_BASE, IRQ_MAX};
use devices::Device;
#[cfg(feature = "vhostuser_net")]
use machine_manager::config::get_chardev_socket_path;
#[cfg(target_arch = "x86_64")]
use machine_manager::config::Param;
use machine_manager::config::{
    parse_incoming_uri, str_slip_to_clap, ConfigCheck, DriveConfig, MigrateMode, NetDevcfg,
    NetworkInterfaceConfig, VmConfig,
};
use machine_manager::machine::{
    DeviceInterface, MachineAddressInterface, MachineExternalInterface, MachineInterface,
    MachineLifecycle, MigrateInterface, VmState,
};
use machine_manager::qmp::{
    qmp_channel::QmpChannel, qmp_response::Response, qmp_schema, qmp_schema::UpdateRegionArgument,
};
use machine_manager::{check_arg_nonexist, event};
use migration::MigrationManager;
use util::loop_context::{create_new_eventfd, EventLoopManager};
use util::{num_ops::str_to_num, set_termi_canon_mode};
use virtio::device::block::VirtioBlkDevConfig;
#[cfg(feature = "vhost_net")]
use virtio::VhostKern;
#[cfg(feature = "vhostuser_net")]
use virtio::VhostUser;
use virtio::{
    create_tap, qmp_balloon, qmp_query_balloon, Block, BlockState, Net, VirtioDevice,
    VirtioMmioDevice, VirtioMmioState, VirtioNetState,
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
    // The config of the related backend device.
    // Eg: Drive config of virtio mmio block. Netdev config of virtio mmio net.
    back_config: Arc<dyn ConfigCheck>,
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
    /// Shutdown request, handle VM `shutdown` event.
    pub(crate) shutdown_req: Arc<EventFd>,
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
            shutdown_req: Arc::new(
                create_new_eventfd()
                    .with_context(|| MachineError::InitEventFdErr("shutdown_req".to_string()))?,
            ),
        })
    }

    pub(crate) fn create_replaceable_devices(&mut self) -> Result<()> {
        for id in 0..MMIO_REPLACEABLE_BLK_NR {
            let block = Arc::new(Mutex::new(Block::new(
                VirtioBlkDevConfig::default(),
                DriveConfig::default(),
                self.get_drive_files(),
            )));
            MigrationManager::register_device_instance(
                BlockState::descriptor(),
                block.clone(),
                &id.to_string(),
            );

            let blk_mmio = self.add_virtio_mmio_device(id.to_string(), block.clone())?;
            let info = MmioReplaceableDevInfo {
                device: block,
                id: id.to_string(),
                used: false,
            };
            self.replaceable_info.devices.lock().unwrap().push(info);
            MigrationManager::register_transport_instance(
                VirtioMmioState::descriptor(),
                blk_mmio,
                &id.to_string(),
            );
        }
        for id in 0..MMIO_REPLACEABLE_NET_NR {
            let total_id = id + MMIO_REPLACEABLE_BLK_NR;
            let net = Arc::new(Mutex::new(Net::new(
                NetworkInterfaceConfig::default(),
                NetDevcfg::default(),
            )));
            MigrationManager::register_device_instance(
                VirtioNetState::descriptor(),
                net.clone(),
                &total_id.to_string(),
            );

            let net_mmio = self.add_virtio_mmio_device(total_id.to_string(), net.clone())?;
            let info = MmioReplaceableDevInfo {
                device: net,
                id: total_id.to_string(),
                used: false,
            };
            self.replaceable_info.devices.lock().unwrap().push(info);
            MigrationManager::register_transport_instance(
                VirtioMmioState::descriptor(),
                net_mmio,
                &total_id.to_string(),
            );
        }

        Ok(())
    }

    pub(crate) fn fill_replaceable_device(
        &mut self,
        id: &str,
        dev_config: Vec<Arc<dyn ConfigCheck>>,
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
                .update_config(dev_config.clone())
                .with_context(|| MachineError::UpdCfgErr(id.to_string()))?;
        }

        self.add_replaceable_config(id, dev_config[0].clone())
    }

    fn add_replaceable_config(&self, id: &str, back_config: Arc<dyn ConfigCheck>) -> Result<()> {
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
            back_config,
        };

        trace::mmio_replaceable_config(&config);
        configs_lock.push(config);
        Ok(())
    }

    fn add_replaceable_device(
        &self,
        args: Box<qmp_schema::DeviceAddArgument>,
        slot: usize,
    ) -> Result<()> {
        let id = args.id;
        let driver = args.driver;

        // Find the configuration by id.
        let configs_lock = self.replaceable_info.configs.lock().unwrap();
        let mut configs = Vec::new();
        for config in configs_lock.iter() {
            if config.id == id {
                configs.push(config.back_config.clone());
            }
        }
        if configs.is_empty() {
            bail!("Failed to find device configuration.");
        }

        // Sanity check for config, driver and slot.
        let cfg_any = configs[0].as_any();
        let index = if driver.contains("net") {
            if slot >= MMIO_REPLACEABLE_NET_NR {
                return Err(anyhow!(MachineError::RplDevLmtErr(
                    "net".to_string(),
                    MMIO_REPLACEABLE_NET_NR
                )));
            }
            if cfg_any.downcast_ref::<NetDevcfg>().is_none() {
                return Err(anyhow!(MachineError::DevTypeErr("net".to_string())));
            }
            let mut net_config = NetworkInterfaceConfig {
                classtype: driver,
                id: id.clone(),
                netdev: args.chardev.with_context(|| "No chardev set")?,
                mac: args.mac,
                iothread: args.iothread,
                ..Default::default()
            };
            net_config.auto_iothread();
            configs.push(Arc::new(net_config));
            slot + MMIO_REPLACEABLE_BLK_NR
        } else if driver.contains("blk") {
            if slot >= MMIO_REPLACEABLE_BLK_NR {
                return Err(anyhow!(MachineError::RplDevLmtErr(
                    "block".to_string(),
                    MMIO_REPLACEABLE_BLK_NR
                )));
            }
            if cfg_any.downcast_ref::<DriveConfig>().is_none() {
                return Err(anyhow!(MachineError::DevTypeErr("blk".to_string())));
            }
            let dev_config = VirtioBlkDevConfig {
                classtype: driver,
                id: id.clone(),
                drive: args.drive.with_context(|| "No drive set")?,
                bootindex: args.boot_index,
                iothread: args.iothread,
                serial: args.serial_num,
                ..Default::default()
            };
            configs.push(Arc::new(dev_config));
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
                .update_config(configs)
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
                if let Some(drive_config) =
                    config.back_config.as_any().downcast_ref::<DriveConfig>()
                {
                    self.unregister_drive_file(&drive_config.path_on_host)?;
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
                    .update_config(Vec::new())
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
        let mut net_cfg =
            NetworkInterfaceConfig::try_parse_from(str_slip_to_clap(cfg_args, true, false))?;
        net_cfg.auto_iothread();
        check_arg_nonexist!(
            ("bus", net_cfg.bus),
            ("addr", net_cfg.addr),
            ("multifunction", net_cfg.multifunction)
        );
        let netdev_cfg = vm_config
            .netdevs
            .remove(&net_cfg.netdev)
            .with_context(|| format!("Netdev: {:?} not found for net device", &net_cfg.netdev))?;
        if netdev_cfg.vhost_type().is_some() {
            if netdev_cfg.vhost_type().unwrap() == "vhost-kernel" {
                #[cfg(not(feature = "vhost_net"))]
                bail!("Unsupported Vhost_Net");

                #[cfg(feature = "vhost_net")]
                {
                    let net = Arc::new(Mutex::new(VhostKern::Net::new(
                        &net_cfg,
                        netdev_cfg,
                        &self.base.sys_mem,
                    )));
                    self.add_virtio_mmio_device(net_cfg.id.clone(), net)?;
                }
            } else {
                #[cfg(not(feature = "vhostuser_net"))]
                bail!("Unsupported Vhostuser_Net");

                #[cfg(feature = "vhostuser_net")]
                {
                    let chardev = netdev_cfg.chardev.clone().with_context(|| {
                        format!("Chardev not configured for netdev {:?}", netdev_cfg.id)
                    })?;
                    let chardev_cfg = vm_config
                        .chardev
                        .remove(&chardev)
                        .with_context(|| format!("Chardev: {:?} not found for netdev", chardev))?;
                    let sock_path = get_chardev_socket_path(chardev_cfg)?;
                    let net = Arc::new(Mutex::new(VhostUser::Net::new(
                        &net_cfg,
                        netdev_cfg,
                        sock_path,
                        &self.base.sys_mem,
                    )));
                    self.add_virtio_mmio_device(net_cfg.id.clone(), net)?;
                }
            };
        } else {
            let index = MMIO_REPLACEABLE_BLK_NR + self.replaceable_info.net_count;
            if index >= MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR {
                bail!(
                    "A maximum of {} net replaceable devices are supported.",
                    MMIO_REPLACEABLE_NET_NR
                );
            }
            let configs: Vec<Arc<dyn ConfigCheck>> =
                vec![Arc::new(netdev_cfg), Arc::new(net_cfg.clone())];
            self.fill_replaceable_device(&net_cfg.id, configs, index)?;
            self.replaceable_info.net_count += 1;
        }
        Ok(())
    }

    pub(crate) fn add_virtio_mmio_block(
        &mut self,
        vm_config: &mut VmConfig,
        cfg_args: &str,
    ) -> Result<()> {
        let device_cfg =
            VirtioBlkDevConfig::try_parse_from(str_slip_to_clap(cfg_args, true, false))?;
        check_arg_nonexist!(
            ("bus", device_cfg.bus),
            ("addr", device_cfg.addr),
            ("multifunction", device_cfg.multifunction)
        );
        let drive_cfg = vm_config
            .drives
            .remove(&device_cfg.drive)
            .with_context(|| "No drive configured matched for blk device")?;
        if self.replaceable_info.block_count >= MMIO_REPLACEABLE_BLK_NR {
            bail!(
                "A maximum of {} block replaceable devices are supported.",
                MMIO_REPLACEABLE_BLK_NR
            );
        }
        let index = self.replaceable_info.block_count;
        let configs: Vec<Arc<dyn ConfigCheck>> =
            vec![Arc::new(drive_cfg), Arc::new(device_cfg.clone())];
        self.fill_replaceable_device(&device_cfg.id, configs, index)?;
        self.replaceable_info.block_count += 1;
        Ok(())
    }

    pub(crate) fn add_virtio_mmio_device(
        &mut self,
        name: String,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<Arc<Mutex<VirtioMmioDevice>>> {
        let sys_mem = self.get_sys_mem().clone();
        let region_base = self.base.sysbus.lock().unwrap().min_free_base;
        let region_size = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;
        let dev = VirtioMmioDevice::new(
            &sys_mem,
            name,
            device,
            &self.base.sysbus,
            region_base,
            region_size,
        )?;
        let mmio_device = dev
            .realize()
            .with_context(|| MachineError::RlzVirtioMmioErr)?;
        #[cfg(target_arch = "x86_64")]
        {
            let res = mmio_device.lock().unwrap().get_sys_resource().clone();
            let mut bs = self.base.boot_source.lock().unwrap();
            bs.kernel_cmdline.push(Param {
                param_type: "virtio_mmio.device".to_string(),
                value: format!("{}@0x{:08x}:{}", res.region_size, res.region_base, res.irq),
            });
        }
        self.base.sysbus.lock().unwrap().min_free_base += region_size;
        Ok(mmio_device)
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
        if self.shutdown_req.write(1).is_err() {
            error!("Failed to send shutdown request.");
            return false;
        }

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
        use address_space::AddressAttr;
        use address_space::GuestAddress;

        let count = data.len() as u64;
        self.base
            .sys_io
            .write(&mut data, GuestAddress(addr), count, AddressAttr::MMIO)
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
                let cpu_instance = cpu_topo.get_topo_instance_for_qmp(cpu_index);
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
                let cpu_instance = self.base.cpu_topo.get_topo_instance_for_qmp(cpu_index);
                let hotpluggable_cpu = qmp_schema::HotpluggableCPU {
                    type_: cpu_type.clone(),
                    vcpus_count: 1,
                    props: cpu_instance,
                    qom_path: None,
                };
                hotplug_vec.push(serde_json::to_value(hotpluggable_cpu).unwrap());
            } else {
                let cpu_instance = self.base.cpu_topo.get_topo_instance_for_qmp(cpu_index);
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
        let mut slot = 0_usize;
        if let Some(addr) = args.addr.clone() {
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

        match self.add_replaceable_device(args.clone(), slot) {
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
        let readonly = args.read_only.unwrap_or(false);
        let mut direct = true;
        if args.cache.is_some() && !args.cache.unwrap().direct.unwrap_or(true) {
            direct = false;
        }

        let config = DriveConfig {
            id: args.node_name.clone(),
            drive_type: "none".to_string(),
            path_on_host: args.file.filename.clone(),
            readonly,
            direct,
            aio: args.file.aio,
            ..Default::default()
        };

        if let Err(e) = config.check() {
            error!("{:?}", e);
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            );
        }
        // Register drive backend file for hotplugged drive.
        if let Err(e) = self.register_drive_file(&config.id, &args.file.filename, readonly, direct)
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
        let mut netdev_cfg = NetDevcfg {
            id: args.id.clone(),
            ..Default::default()
        };

        if let Some(fds) = args.fds {
            let netdev_fd = if fds.contains(':') {
                let col: Vec<_> = fds.split(':').collect();
                String::from(col[col.len() - 1])
            } else {
                String::from(&fds)
            };

            if let Some(fd_num) = QmpChannel::get_fd(&netdev_fd) {
                netdev_cfg.tap_fds = Some(vec![fd_num]);
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
                netdev_cfg.tap_fds = Some(vec![fd_num]);
            }
        } else if let Some(if_name) = args.if_name {
            netdev_cfg.ifname = if_name.clone();
            if create_tap(None, Some(&if_name), 1).is_err() {
                return Response::create_error_response(
                    qmp_schema::QmpErrorClass::GenericError(
                        "Tap device already in use".to_string(),
                    ),
                    None,
                );
            }
        }

        match self.add_replaceable_config(&args.id, Arc::new(netdev_cfg)) {
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
