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

extern crate util;

use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use strum::VariantNames;

use crate::qmp::qmp_schema::{
    CacheOptions, ChardevInfo, Cmd, CmdLine, DeviceProps, Events, FileOptions, GicCap,
    IothreadInfo, KvmInfo, MachineInfo, MigrateCapabilities, PropList, QmpCommand, QmpEvent,
    Target, TypeLists,
};
use crate::qmp::{Response, Version};

#[derive(Clone)]
pub struct PathInfo {
    pub path: String,
    pub label: String,
}

/// State for KVM VM.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum KvmVmState {
    Created = 1,
    Running = 2,
    InMigrating = 3,
    Migrated = 4,
    Paused = 5,
    Shutdown = 6,
}

/// Event over StratoVirt lifetime.
pub enum VmEvent {
    ShutdownCauseGuestReset,
    ShutdownCauseGuestCrash,
    ShutdownCauseFailEntry,
    ShutdownCauseInternalError,
}

unsafe impl Sync for VmEvent {}
unsafe impl Send for VmEvent {}

/// Trait to handle virtual machine lifecycle.
///
/// # Notes
///
/// VM or Device Life State graph:
///
/// `None` --`(new)`--> `Created`
/// `Created` --`(start)`--> `Running`
/// `Running` --`(pause)`--> `Paused`
/// `Paused` --`(resume)`--> `Running`
/// `KVM_VMSTATE_*` --`(destroy)`--> `None`
///
/// **Notice**:
///    1. Migrate state(`Migrated` and `InMigrating`),
///    not include in Life cycle, both migrate state should deal like `PAUSED`
///    state.
///
///    2. Snapshot state deal with `PAUSED` state.
///
///    3. every one concern with VM or Device state need to implement this trait,
///    will be notified when VM state changed through `lifecycle_notify` hook.
pub trait MachineLifecycle {
    /// Start VM or Device, VM or Device enter running state after this call return.
    fn start(&self) -> bool {
        self.notify_lifecycle(KvmVmState::Created, KvmVmState::Paused)
    }

    /// Pause VM or Device, VM or Device will temporarily stored in memory until it resumed
    /// or destroyed.
    fn pause(&self) -> bool {
        self.notify_lifecycle(KvmVmState::Running, KvmVmState::Paused)
    }

    /// Resume VM or Device, resume VM state to running state after this call return.
    fn resume(&self) -> bool {
        self.notify_lifecycle(KvmVmState::Paused, KvmVmState::Running)
    }

    /// Close VM or Device, stop running.
    fn destroy(&self) -> bool {
        self.notify_lifecycle(KvmVmState::Running, KvmVmState::Shutdown)
    }

    /// When VM or Device life state changed, notify concerned entry.
    ///
    /// # Arguments
    ///
    /// * `old` - The current `KvmVmState`.
    /// * `new` - The new `KvmVmState` expected to transform.
    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool;
}

/// `AddressSpace` access interface of `Machine`.
///
/// # Notes
/// RAM and peripheral mapping to the memory address space,
/// the CPU or other device can use the memory address to access the
/// certain RAM range or a certain device.
///
/// Memory-mapped I/O(MMIO) peripheral refers to transfers using an
/// address space inside of normal memory.
///
/// In x86 architecture, there is a special address space outside of
/// normal memory, the peripheral in the address space use port-mapped
/// I/O(PIO) mode.
pub trait MachineAddressInterface {
    #[cfg(target_arch = "x86_64")]
    fn pio_in(&self, port: u64, data: &mut [u8]) -> bool;

    #[cfg(target_arch = "x86_64")]
    fn pio_out(&self, port: u64, data: &[u8]) -> bool;

    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> bool;

    fn mmio_write(&self, addr: u64, data: &[u8]) -> bool;
}

/// Device external api
///
/// # Notes
///
/// Some external api for device, which can be exposed to outer.
/// Including some query, setting and operation.
pub trait DeviceInterface {
    /// Query vm running state.
    fn query_status(&self) -> Response;

    /// Query each cpu's the topology info.
    fn query_cpus(&self) -> Response;

    /// Query each `hotpluggable_cpus`'s topology info and hotplug message.
    fn query_hotpluggable_cpus(&self) -> Response;

    /// Add a device with configuration.
    fn device_add(
        &self,
        device_id: String,
        driver: String,
        addr: Option<String>,
        lun: Option<usize>,
    ) -> Response;

    /// Delete a device with device id.
    fn device_del(&self, device_id: String) -> Response;

    /// Creates a new block device.
    fn blockdev_add(
        &self,
        node_name: String,
        file: FileOptions,
        cache: Option<CacheOptions>,
        read_only: Option<bool>,
    ) -> Response;

    /// Create a new network device.
    fn netdev_add(&self, id: String, if_name: Option<String>, fds: Option<String>) -> Response;

    /// Receive a file descriptor via SCM rights and assign it a name.
    fn getfd(&self, fd_name: String, if_fd: Option<RawFd>) -> Response;

    /// Query balloon's size.
    fn query_balloon(&self) -> Response;

    /// Set balloon's size.
    fn balloon(&self, size: u64) -> Response;

    /// Query the version of StratoVirt.
    fn query_version(&self) -> Response {
        let version = Version::new(0, 1, 4);
        Response::create_response(serde_json::to_value(&version).unwrap(), None)
    }

    /// Query all commands of StratoVirt.
    fn query_commands(&self) -> Response {
        let mut vec_cmd = Vec::new();
        for qmp_cmd in QmpCommand::VARIANTS {
            let cmd = Cmd {
                name: String::from(*qmp_cmd),
            };
            vec_cmd.push(cmd);
        }
        Response::create_response(serde_json::to_value(&vec_cmd).unwrap(), None)
    }

    /// Query the target platform where the StratoVirt is running.
    fn query_target(&self) -> Response {
        #[cfg(target_arch = "x86_64")]
        let target = Target {
            arch: "x86_64".to_string(),
        };
        #[cfg(target_arch = "aarch64")]
        let target = Target {
            arch: "aarch64".to_string(),
        };
        Response::create_response(serde_json::to_value(&target).unwrap(), None)
    }

    /// Query all events of StratoVirt.
    fn query_events(&self) -> Response {
        let mut vec_events = Vec::new();
        for event in QmpEvent::VARIANTS {
            let cmd = Events {
                name: String::from(*event),
            };
            vec_events.push(cmd);
        }
        Response::create_response(serde_json::to_value(&vec_events).unwrap(), None)
    }

    /// Query if kvm is used.
    fn query_kvm(&self) -> Response {
        let kvm = KvmInfo {
            enabled: true,
            present: true,
        };
        Response::create_response(serde_json::to_value(&kvm).unwrap(), None)
    }

    /// Query machine types supported by StratoVirt.
    fn query_machines(&self) -> Response {
        let mut vec_machine = Vec::new();
        let machine_info = MachineInfo {
            hotplug: false,
            name: "none".to_string(),
            numa_mem_support: false,
            cpu_max: 255,
            deprecated: false,
        };
        vec_machine.push(machine_info);
        let machine_info = MachineInfo {
            hotplug: false,
            name: "microvm".to_string(),
            numa_mem_support: false,
            cpu_max: 255,
            deprecated: false,
        };
        vec_machine.push(machine_info);
        let machine_info = MachineInfo {
            hotplug: false,
            name: "standard_vm".to_string(),
            numa_mem_support: false,
            cpu_max: 255,
            deprecated: false,
        };
        vec_machine.push(machine_info);
        Response::create_response(serde_json::to_value(&vec_machine).unwrap(), None)
    }

    /// Get the list type
    fn list_type(&self) -> Response {
        let mut vec_types = Vec::new();
        // These devices are used to interconnect with libvirt, but not been implemented yet.
        let list_types: Vec<(&str, &str)> = vec![
            ("ioh3420", "pcie-root-port-base"),
            ("pcie-root-port", "pcie-root-port-base"),
            ("pcie-pci-bridge", "base-pci-bridge"),
            ("pci-bridge", "base-pci-bridge"),
            ("virtio-blk-pci-transitional", "virtio-blk-pci-base"),
            ("memory-backend-file", "memory-backend"),
            ("virtio-rng-device", "virtio-device"),
            ("rng-random", "rng-backend"),
            ("vfio-pci", "pci-device"),
            ("vhost-vsock-device", "virtio-device"),
            ("iothread", "object"),
        ];
        for list in list_types {
            let re = TypeLists::new(String::from(list.0), String::from(list.1));
            vec_types.push(re);
        }
        Response::create_response(serde_json::to_value(&vec_types).unwrap(), None)
    }

    fn device_list_properties(&self) -> Response {
        let vec_props = Vec::<DeviceProps>::new();
        Response::create_response(serde_json::to_value(&vec_props).unwrap(), None)
    }

    fn query_tpm_models(&self) -> Response {
        let tpm_models = Vec::<String>::new();
        Response::create_response(serde_json::to_value(&tpm_models).unwrap(), None)
    }

    fn query_tpm_types(&self) -> Response {
        let tpm_types = Vec::<String>::new();
        Response::create_response(serde_json::to_value(&tpm_types).unwrap(), None)
    }

    fn query_command_line_options(&self) -> Response {
        let cmd_lines = Vec::<CmdLine>::new();
        Response::create_response(serde_json::to_value(&cmd_lines).unwrap(), None)
    }

    fn query_migrate_capabilities(&self) -> Response {
        let caps = Vec::<MigrateCapabilities>::new();
        Response::create_response(serde_json::to_value(&caps).unwrap(), None)
    }

    fn query_qmp_schema(&self) -> Response {
        Response::create_empty_response()
    }

    fn query_sev_capabilities(&self) -> Response {
        Response::create_empty_response()
    }

    fn query_chardev(&self) -> Response {
        let mut vec_chardev_info: Vec<ChardevInfo> = Vec::new();
        let locked_paths = PTY_PATH.lock().unwrap().clone();
        for path in locked_paths.iter() {
            let chardev_path = &path.path;
            let chardev_label = &path.label;
            let info = ChardevInfo {
                open: true,
                filename: chardev_path.to_string().replace("\"", ""),
                label: chardev_label.to_string().replace("\"", ""),
            };
            vec_chardev_info.push(info);
        }
        Response::create_response(serde_json::to_value(&vec_chardev_info).unwrap(), None)
    }

    fn qom_list(&self) -> Response {
        let vec_cmd: Vec<PropList> = Vec::new();
        Response::create_response(serde_json::to_value(&vec_cmd).unwrap(), None)
    }

    fn qom_get(&self) -> Response {
        let vec_cmd: Vec<ChardevInfo> = Vec::new();
        Response::create_response(serde_json::to_value(&vec_cmd).unwrap(), None)
    }

    fn query_block(&self) -> Response {
        let vec_cmd: Vec<ChardevInfo> = Vec::new();
        Response::create_response(serde_json::to_value(&vec_cmd).unwrap(), None)
    }

    fn query_named_block_nodes(&self) -> Response {
        let vec_cmd: Vec<ChardevInfo> = Vec::new();
        Response::create_response(serde_json::to_value(&vec_cmd).unwrap(), None)
    }

    fn query_blockstats(&self) -> Response {
        let vec_cmd: Vec<ChardevInfo> = Vec::new();
        Response::create_response(serde_json::to_value(&vec_cmd).unwrap(), None)
    }

    fn query_gic_capabilities(&self) -> Response {
        let vec_gic: Vec<GicCap> = Vec::new();
        Response::create_response(serde_json::to_value(&vec_gic).unwrap(), None)
    }

    fn query_iothreads(&self) -> Response {
        let mut vec_iothreads: Vec<IothreadInfo> = Vec::new();
        let locked_threads = IOTHREADS.lock().unwrap();
        for thread in locked_threads.iter() {
            vec_iothreads.push(thread.clone());
        }
        Response::create_response(serde_json::to_value(&vec_iothreads).unwrap(), None)
    }
}

/// Migrate external api
///
/// # Notes
///
/// Some external api for migration.
pub trait MigrateInterface {
    /// Migrates the current running guest to another VM or file.
    fn migrate(&self, _uri: String) -> Response {
        Response::create_empty_response()
    }

    /// Returns information about current migration.
    fn query_migrate(&self) -> Response {
        Response::create_empty_response()
    }
}

/// Machine interface which is exposed to inner hypervisor.
pub trait MachineInterface: MachineLifecycle + MachineAddressInterface {}

/// Machine interface which is exposed to outer hypervisor.
pub trait MachineExternalInterface: MachineLifecycle + DeviceInterface + MigrateInterface {}

lazy_static! {
    pub static ref PTY_PATH: Arc<Mutex<Vec<PathInfo>>> = Arc::new(Mutex::new(Vec::new()));
    pub static ref IOTHREADS: Arc<Mutex<Vec<IothreadInfo>>> = Arc::new(Mutex::new(Vec::new()));
}
