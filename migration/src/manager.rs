// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
use std::fs::File;
use std::hash::Hash;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use log::info;
use once_cell::sync::Lazy;

use crate::general::translate_id;
use crate::migration::DirtyBitmap;
use crate::protocol::{DeviceStateDesc, MemBlock, MigrationStatus, StateTransfer};
use crate::MigrateOps;
use machine_manager::config::VmConfig;
use machine_manager::machine::MachineLifecycle;
use util::byte_code::ByteCode;

/// Global MigrationManager to manage all migration combined interface.
pub(crate) static MIGRATION_MANAGER: Lazy<MigrationManager> = Lazy::new(|| MigrationManager {
    vmm: Arc::new(RwLock::new(Vmm::default())),
    desc_db: Arc::new(RwLock::new(HashMap::<String, DeviceStateDesc>::new())),
    status: Arc::new(RwLock::new(MigrationStatus::None)),
    vmm_bitmaps: Arc::new(RwLock::new(HashMap::new())),
    limit: Arc::new(RwLock::new(MigrationLimit::default())),
});

/// A hook for `Device` to save device state to `Write` object and load device
/// from `[u8]` slice.
///
/// # Notes
///
/// This trait is a symbol of device's migration capabilities. All
/// migratable device must implement this trait.
pub trait MigrationHook: StateTransfer {
    /// Save device state as `[u8]` with device's `InstanceId` to a `Write`
    /// trait object.
    ///
    /// # Arguments
    ///
    /// * `id` - This unique id to represent a single device. It can be treated as `object_id` in
    ///   `InstanceId`.
    /// * `fd` - The `Write` trait object to save device data.
    fn save_device(&self, id: u64, fd: &mut dyn Write) -> Result<()> {
        let state_data = self
            .get_state_vec()
            .with_context(|| "Failed to get device state")?;

        fd.write_all(
            Instance {
                name: id,
                object: self.get_device_alias(),
            }
            .as_bytes(),
        )
        .with_context(|| "Failed to write instance id.")?;
        fd.write_all(&state_data)
            .with_context(|| "Failed to write device state")?;

        Ok(())
    }

    /// Restore device state from `[u8]` to `Device`.
    ///
    /// # Arguments
    ///
    /// * `state` - The raw data which can be recovered to `DeviceState`.
    fn restore_device(&self, state: &[u8]) -> Result<()> {
        self.set_state(state)
    }

    /// Restore device state from `[u8]` to mutable `Device`.
    ///
    /// # Arguments
    ///
    /// * `state` - The raw data which can be recovered to `DeviceState`.
    fn restore_mut_device(&mut self, state: &[u8]) -> Result<()> {
        self.set_state_mut(state)
    }

    /// Save memory state to `Write` trait.
    ///
    /// # Arguments
    ///
    /// * _fd - The `Write` trait object to save memory data.
    fn save_memory(&self, _fd: &mut dyn Write) -> Result<()> {
        Ok(())
    }

    /// Restore memory state from memory.
    ///
    /// # Arguments
    ///
    /// * _memory - The file of memory data, this parameter is optional.
    /// * _state - device state from memory.
    fn restore_memory(&self, _memory: Option<&File>, _state: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Send memory data to `Write` trait.
    ///
    /// # Arguments
    ///
    /// * _fd - The `Write` trait object to send memory data.
    /// * _range - the memory block range needs to send.
    fn send_memory(&self, _fd: &mut dyn Write, _range: MemBlock) -> Result<()> {
        Ok(())
    }

    /// Receive memory data from `Read`.
    ///
    /// # Arguments
    ///
    /// * _fd - The `Read` trait object to receive memory data.
    /// * _range - the memory block range needs to send.
    fn recv_memory(&self, _fd: &mut dyn Read, _range: MemBlock) -> Result<()> {
        Ok(())
    }

    /// Resume the recover device.
    ///
    /// # Notes
    ///
    /// For some device, such as virtio-device or vhost-device, after restore
    /// device state, it need a step to wake up device to run.
    fn resume(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The instance represents a single object in VM.
///
/// # Notes
///
/// Instance contains two parts: One part is name for every object.
/// another is the type of a object.
#[derive(Ord, PartialOrd, Eq, PartialEq, Hash, Copy, Clone, Debug, Default)]
pub struct Instance {
    /// The name reflects the unique device or ram_region instance in a VM.
    pub name: u64,
    /// The object is the type which is registered to `desc_db`.
    pub object: u64,
}

impl ByteCode for Instance {}

/// Including all components of a Vmm.
#[derive(Default)]
pub struct Vmm {
    /// Vm config
    pub config: Arc<Mutex<VmConfig>>,
    /// Trait to represent a Vm.
    pub vm: Option<Arc<Mutex<dyn MachineLifecycle + Send + Sync>>>,
    /// Trait to represent CPU devices.
    pub cpus: HashMap<u64, Arc<dyn MigrationHook + Send + Sync>>,
    /// Trait to represent memory devices.
    pub memory: Option<Arc<dyn MigrationHook + Send + Sync>>,
    /// Trait to represent transports.
    pub transports: HashMap<u64, Arc<Mutex<dyn MigrationHook + Send + Sync>>>,
    /// Trait to represent devices.
    pub devices: HashMap<u64, Arc<Mutex<dyn MigrationHook + Send + Sync>>>,
    #[cfg(target_arch = "aarch64")]
    /// Trait to represent GIC devices(GICv3, GICv3 ITS).
    pub gic_group: HashMap<u64, Arc<dyn MigrationHook + Send + Sync>>,
    #[cfg(target_arch = "x86_64")]
    /// Trait to represent kvm device.
    pub kvm: Option<Arc<dyn MigrationHook + Send + Sync>>,
    /// The vector of the object implementing MigrateOps trait.
    pub mgt_object: Option<Arc<Mutex<dyn MigrateOps>>>,
}

/// Limit of migration.
pub struct MigrationLimit {
    /// Start time of each iteration.
    pub iteration_start_time: Instant,
    /// Virtual machine downtime.
    pub limit_downtime: u64,
    /// Max number of iterations during iteratively sending dirty memory.
    pub max_dirty_iterations: u16,
}

impl Default for MigrationLimit {
    fn default() -> Self {
        Self {
            iteration_start_time: Instant::now(),
            limit_downtime: 50,
            max_dirty_iterations: 30,
        }
    }
}

/// This structure is to manage all resource during migration.
/// It is also the only way to call on `MIGRATION_MANAGER`.
pub struct MigrationManager {
    /// The vmm can manage all VM related components
    pub vmm: Arc<RwLock<Vmm>>,
    /// The map offers the device type and its device state describe structure.
    pub desc_db: Arc<RwLock<HashMap<String, DeviceStateDesc>>>,
    /// The status of migration work.
    pub status: Arc<RwLock<MigrationStatus>>,
    /// vmm dirty bitmaps.
    pub vmm_bitmaps: Arc<RwLock<HashMap<u32, DirtyBitmap>>>,
    /// Limiting elements of migration.
    pub limit: Arc<RwLock<MigrationLimit>>,
}

impl MigrationManager {
    /// Register `DeviceStateDesc` to `desc_db`'s hashmap with `device_type`.
    ///
    /// # Argument
    ///
    /// * `desc` - The descriptor of `DeviceState`.
    fn register_device_desc(desc: DeviceStateDesc) {
        let mut desc_db = MIGRATION_MANAGER.desc_db.write().unwrap();
        if !desc_db.contains_key(&desc.name) {
            info!("Register device name: {}, desc: {:?}", desc.name, desc);
            desc_db.insert(desc.name.clone(), desc);
        }
    }

    /// Register vm config to vmm.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration from virtual machine.
    pub fn register_vm_config(config: Arc<Mutex<VmConfig>>) {
        MIGRATION_MANAGER.vmm.write().unwrap().config = config;
    }

    /// Register vm instance to vmm.
    ///
    /// # Arguments
    ///
    /// * `vm` - vm instance with MachineLifecycle trait.
    pub fn register_vm_instance<T>(vm: Arc<Mutex<T>>)
    where
        T: MachineLifecycle + Sync + Send + 'static,
    {
        MIGRATION_MANAGER.vmm.write().unwrap().vm = Some(vm);
    }

    /// Register CPU instance to vmm.
    ///
    /// # Arguments
    ///
    /// * `cpu_desc` - The `DeviceStateDesc` of CPU instance.
    /// * `cpu` - CPU device instance with MigrationHook trait.
    /// * `id` - The unique id for CPU device.
    pub fn register_cpu_instance<T>(cpu_desc: DeviceStateDesc, cpu: Arc<T>, id: u8)
    where
        T: MigrationHook + Sync + Send + 'static,
    {
        let name = cpu_desc.name.clone() + "/" + &id.to_string();
        let mut copied_cpu_desc = cpu_desc.clone();
        copied_cpu_desc.name = name.clone();
        copied_cpu_desc.alias = cpu_desc.alias + id as u64;
        Self::register_device_desc(copied_cpu_desc);

        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.cpus.insert(translate_id(&name), cpu);
    }

    /// Register memory instance to vmm.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory instance with MigrationHook trait.
    pub fn register_memory_instance<T>(memory: Arc<T>)
    where
        T: MigrationHook + Sync + Send + 'static,
    {
        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.memory = Some(memory);
    }

    /// Register transport instance to vmm.
    ///
    /// # Arguments
    ///
    /// * `device_desc` - The `DeviceStateDesc` of device instance.
    /// * `device` - The transport instance with MigrationHook trait.
    /// * `id` - The unique id for device.
    pub fn register_transport_instance<T>(
        device_desc: DeviceStateDesc,
        device: Arc<Mutex<T>>,
        id: &str,
    ) where
        T: MigrationHook + Sync + Send + 'static,
    {
        let name = device_desc.name.clone() + "/" + id;
        Self::register_device_desc(device_desc);

        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.transports.insert(translate_id(&name), device);
    }

    /// Register device instance to vmm.
    ///
    /// # Arguments
    ///
    /// * `device_desc` - The `DeviceStateDesc` of device instance.
    /// * `device` - The device instance with MigrationHook trait.
    /// * `id` - The unique id for device.
    pub fn register_device_instance<T>(
        device_desc: DeviceStateDesc,
        device: Arc<Mutex<T>>,
        id: &str,
    ) where
        T: MigrationHook + Sync + Send + 'static,
    {
        let name = device_desc.name.clone() + "/" + id;
        Self::register_device_desc(device_desc);

        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.devices.insert(translate_id(&name), device);
    }

    /// Register kvm instance to vmm.
    ///
    /// # Arguments
    ///
    /// * `kvm_desc` - The `DeviceStateDesc` of kvm instance.
    /// * `kvm` - The kvm device instance with MigrationHook trait.
    #[cfg(target_arch = "x86_64")]
    pub fn register_kvm_instance<T>(kvm_desc: DeviceStateDesc, kvm: Arc<T>)
    where
        T: MigrationHook + Sync + Send + 'static,
    {
        Self::register_device_desc(kvm_desc);

        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.kvm = Some(kvm);
    }

    /// Register GIC device instance to vmm.
    ///
    /// # Arguments
    ///
    /// * `gic_desc` - The `DeviceStateDesc` of GIC instance.
    /// * `gic` - The GIC device instance with MigrationHook trait.
    #[cfg(target_arch = "aarch64")]
    pub fn register_gic_instance<T>(gic_desc: DeviceStateDesc, gic: Arc<T>, id: &str)
    where
        T: MigrationHook + Sync + Send + 'static,
    {
        Self::register_device_desc(gic_desc);

        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.gic_group.insert(translate_id(id), gic);
    }

    /// Register migration instance to vmm.
    ///
    /// # Arguments
    ///
    /// * `mgt_object` - object with MigrateOps trait.
    pub fn register_migration_instance(mgt_object: Arc<Mutex<dyn MigrateOps + 'static>>) {
        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.mgt_object = Some(mgt_object);
    }

    /// Unregister transport instance from vmm.
    ///
    /// # Arguments
    ///
    /// * `device_desc` - The `DeviceStateDesc` of device instance.
    /// * `id` - The unique id for device.
    pub fn unregister_transport_instance(device_desc: DeviceStateDesc, id: &str) {
        let name = device_desc.name + "/" + id;
        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.transports.remove(&translate_id(&name));
    }

    /// Unregister device instance from vmm.
    ///
    /// # Arguments
    ///
    /// * `device_desc` - The `DeviceStateDesc` of device instance.
    /// * `id` - The unique id for device.
    pub fn unregister_device_instance(device_desc: DeviceStateDesc, id: &str) {
        let name = device_desc.name + "/" + id;
        let mut locked_vmm = MIGRATION_MANAGER.vmm.write().unwrap();
        locked_vmm.devices.remove(&translate_id(&name));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::protocol::tests::{DeviceV1, DeviceV1State, DeviceV2, DeviceV2State};

    impl MigrationHook for DeviceV1 {}
    impl MigrationHook for DeviceV2 {}

    #[test]
    fn test_register_device() {
        let device_v1_mutex = Arc::new(Mutex::new(DeviceV1::default()));
        let device_v2_arc = Arc::new(DeviceV2::default());
        let device_v2_mutex = Arc::new(Mutex::new(DeviceV2::default()));

        MigrationManager::register_device_instance(
            DeviceV1State::descriptor(),
            device_v1_mutex,
            "device_v1",
        );
        MigrationManager::register_memory_instance(device_v2_arc);
        MigrationManager::register_device_instance(
            DeviceV2State::descriptor(),
            device_v2_mutex,
            "device_v2",
        );

        assert!(MigrationManager::get_desc_alias("DeviceV1State").is_some());
        assert_eq!(
            MigrationManager::get_desc_alias("DeviceV1State").unwrap(),
            translate_id("DeviceV1State")
        );
        assert!(MigrationManager::get_desc_alias("DeviceV2State").is_some());
        assert_eq!(
            MigrationManager::get_desc_alias("DeviceV2State").unwrap(),
            translate_id("DeviceV2State")
        );
    }
}
