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

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex, RwLock};

use super::device_state::{DeviceStateDesc, StateTransfer};
use super::errors::{Result, ResultExt};
use super::status::MigrationStatus;
use util::byte_code::ByteCode;

lazy_static! {
    /// Glocal MigrationMananger to manage all migration combined interface.
    pub(crate) static ref MIGRATION_MANAGER: Arc<MigrationManager> = Arc::new(MigrationManager {
        entry: Arc::new(RwLock::new(BTreeMap::<u64, MigrationEntry>::new())),
        desc_db: Arc::new(RwLock::new(HashMap::<String, DeviceStateDesc>::new())),
        status: Arc::new(RwLock::new(MigrationStatus::None)),
    });
}

/// A hook for `Device` to save device state to `Write` object and load device
/// from `[u8]` slice.
///
/// # Notes
///
/// This trait is a symbol of device's migration capabilities. All
/// migratable device must implement this trait.
pub trait MigrationHook: StateTransfer {
    /// Pre save device state as `[u8]` with device's `InstanceId` to a `Write`
    /// trait object.
    ///
    /// # Arguments
    ///
    /// * `id` - This unique id to represent a single device. It can be treated
    ///          as `object_id` in `InstanceId`.
    /// * `writer` - The `Write` trait object to store or receive data.
    fn pre_save(&self, id: u64, writer: &mut dyn Write) -> Result<()> {
        let state_data = self
            .get_state_vec()
            .chain_err(|| "Failed to get device state")?;

        let device_alias = self.get_device_alias();
        let instance_id = InstanceId {
            object_type: device_alias,
            object_id: id,
        };

        writer
            .write_all(&instance_id.as_bytes())
            .chain_err(|| "Failed to write instance id.")?;
        writer
            .write_all(&state_data)
            .chain_err(|| "Failed to write device state")?;

        Ok(())
    }

    /// Pre load device state from `[u8]` to `Device`.
    ///
    /// # Arguments
    ///
    /// * `state` - The raw data which can be recovered to `DeviceState`.
    /// * `memory` - The file of memory data, this parameter is optional.
    fn pre_load(&self, state: &[u8], _memory: Option<&File>) -> Result<()> {
        self.set_state(state)
    }

    /// Pre load device state from `[u8]` to mutable `Device`.
    ///
    /// # Arguments
    ///
    /// * `state` - The raw data which can be recovered to `DeviceState`.
    /// * `memory` - The file of memory data, this parameter is optional.
    fn pre_load_mut(&mut self, state: &[u8], _memory: Option<&File>) -> Result<()> {
        self.set_state_mut(state)
    }

    /// Resume the recover device.
    ///
    /// # Notes
    ///
    /// For some device, such as virtio-device or vhost-device, after recover
    /// device state, it need a step to wake up device to running.
    fn resume(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The instance id to represent a single object in VM.
///
/// # Notes
///
/// Instance_id contains two parts: One part is device type to describe the
/// type of a object, another is unique id for every object.
///
/// ## object_type
/// The object_type for a object is the order which type is registered to
/// `desc_db`. It's associated with object name.
///
/// ## object_id
///
/// The object id should reflect the unique device or ram_region instance in
/// a VM. Is will be set delying on device create order.
#[derive(Ord, PartialOrd, Eq, PartialEq, Hash, Copy, Clone, Debug, Default)]
struct InstanceId {
    /// The type of object.
    object_type: u64,
    /// The unique id of object.
    object_id: u64,
}

impl ByteCode for InstanceId {}

/// A entry to every migratable device to call on migration interface.
enum MigrationEntry {
    /// Safe device instance with migration interface.
    Safe(Arc<dyn MigrationHook + Send + Sync>),
    /// Mutex device instance with migration interface.
    Mutex(Arc<Mutex<dyn MigrationHook + Send + Sync>>),
    /// Safe memory instance with migration interface.
    Memory(Arc<dyn MigrationHook + Send + Sync>),
}

/// This structure is to manage all resource during migration.
/// It is also the only way to call on `MIGRATION_MANAGER`.
pub struct MigrationManager {
    /// The map offers the deivce_id and combined migratable device entry.
    entry: Arc<RwLock<BTreeMap<u64, MigrationEntry>>>,
    /// The map offers the device type and its device state describe structure.
    desc_db: Arc<RwLock<HashMap<String, DeviceStateDesc>>>,
    /// The status of migration work.
    status: Arc<RwLock<MigrationStatus>>,
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
            desc_db.insert(desc.name.clone(), desc);
        }
    }

    /// Register safe device instance to entry hashmap with instance id.
    ///
    /// # Arguments
    ///
    /// * `device_desc` - The `DeviceStateDesc` of device instance.
    /// * `entry` - Device instance with migratable interface.
    pub fn register_device_instance<T>(device_desc: DeviceStateDesc, device_entry: Arc<T>)
    where
        T: MigrationHook + Sync + Send + 'static,
    {
        Self::register_device_desc(device_desc);

        let entry = MigrationEntry::Safe(device_entry);
        let nr_entry = Self::entry_db_len();

        MIGRATION_MANAGER
            .entry
            .write()
            .unwrap()
            .insert(nr_entry, entry);
    }

    /// Register mutex device instance to entry hashmap with instance_id.
    ///
    /// # Arguments
    ///
    /// * `device_desc` - The `DeviceStateDesc` of device instance.
    /// * `entry` - Device instance with migratable interface.
    pub fn register_device_instance_mutex<T>(
        device_desc: DeviceStateDesc,
        device_entry: Arc<Mutex<T>>,
    ) where
        T: MigrationHook + Sync + Send + 'static,
    {
        Self::register_device_desc(device_desc);

        let entry = MigrationEntry::Mutex(device_entry);
        let nr_entry = Self::entry_db_len();

        MIGRATION_MANAGER
            .entry
            .write()
            .unwrap()
            .insert(nr_entry, entry);
    }

    /// Register memory instance.
    ///
    /// # Arguments
    ///
    /// * `entry` - Memory instance with migratable interface.
    pub fn register_memory_instance<T>(entry: Arc<T>)
    where
        T: MigrationHook + Sync + Send + 'static,
    {
        let entry = MigrationEntry::Memory(entry);
        let nr_entry = Self::entry_db_len();

        MIGRATION_MANAGER
            .entry
            .write()
            .unwrap()
            .insert(nr_entry, entry);
    }

    /// Get entry_db's length.
    pub fn entry_db_len() -> u64 {
        MIGRATION_MANAGER.entry.read().unwrap().len() as u64
    }

    /// Get desc_db's length.
    pub fn desc_db_len() -> u64 {
        MIGRATION_MANAGER.desc_db.read().unwrap().len() as u64
    }

    /// Get `Device`'s alias from device type string.
    ///
    /// # Argument
    ///
    /// * `device_type` - The type string of device instance.
    pub fn get_desc_alias(device_type: &str) -> Option<u64> {
        if let Some(desc) = MIGRATION_MANAGER.desc_db.read().unwrap().get(device_type) {
            Some(desc.alias)
        } else {
            None
        }
    }

    /// Set a new migration status for migration manager.
    ///
    /// # Arguments
    ///
    /// * `new_status`: new migration status, the transform must be illegal.
    pub fn set_status(new_status: MigrationStatus) -> Result<()> {
        let mut status = MIGRATION_MANAGER.status.write().unwrap();
        *status = status.transfer(new_status)?;

        Ok(())
    }

    /// Get current migration status for migration manager.
    pub fn migration_get_status() -> MigrationStatus {
        *MIGRATION_MANAGER.status.read().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_state::tests::{DeviceV1, DeviceV1State, DeviceV2, DeviceV2State};
    use std::sync::{Arc, Mutex};

    impl MigrationHook for DeviceV1 {}
    impl MigrationHook for DeviceV2 {}

    #[test]
    fn test_register_device() {
        let device_v1 = Arc::new(DeviceV1::default());
        let device_v2 = Arc::new(DeviceV2::default());
        let device_v2_mutex = Arc::new(Mutex::new(DeviceV2::default()));

        MigrationManager::register_device_instance(DeviceV1State::descriptor(), device_v1);
        MigrationManager::register_memory_instance(device_v2);
        MigrationManager::register_device_instance_mutex(
            DeviceV2State::descriptor(),
            device_v2_mutex,
        );

        assert_eq!(MigrationManager::desc_db_len(), 1);
        assert!(MigrationManager::get_desc_alias("Device").is_some());
        assert_eq!(MigrationManager::get_desc_alias("Device").unwrap(), 1);
    }
}
