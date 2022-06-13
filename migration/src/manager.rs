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

use std::cmp;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, RwLock};

use super::device_state::{DeviceStateDesc, StateTransfer};
use super::errors::{Result, ResultExt};
use super::status::MigrationStatus;
use once_cell::sync::Lazy;
use util::byte_code::ByteCode;

/// Glocal MigrationManager to manage all migration combined interface.
pub(crate) static MIGRATION_MANAGER: Lazy<MigrationManager> = Lazy::new(|| MigrationManager {
    entry: Arc::new(RwLock::new([
        Vec::<(String, MigrationEntry)>::new(),
        Vec::<(String, MigrationEntry)>::new(),
        Vec::<(String, MigrationEntry)>::new(),
    ])),
    desc_db: Arc::new(RwLock::new(HashMap::<String, DeviceStateDesc>::new())),
    status: Arc::new(RwLock::new(MigrationStatus::None)),
});

/// Used to map Device id from String to u64 only.
/// Because instance_id in InstanceId can't be String for it has no Copy trait.
///
/// # Arguments
///
/// * `dev_id` - The device id.
pub fn id_remap(dev_id: &str) -> u64 {
    let mut hash = DefaultHasher::new();
    dev_id.hash(&mut hash);
    hash.finish()
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
    fn pre_save(&self, id: &str, writer: &mut dyn Write) -> Result<()> {
        let state_data = self
            .get_state_vec()
            .chain_err(|| "Failed to get device state")?;

        let device_alias = self.get_device_alias();
        let instance_id = InstanceId {
            object_type: device_alias,
            object_id: id_remap(id),
        };

        writer
            .write_all(instance_id.as_bytes())
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
pub struct InstanceId {
    /// The type of object.
    pub object_type: u64,
    /// The unique id of object.
    pub object_id: u64,
}

impl ByteCode for InstanceId {}

/// A entry to every migratable device to call on migration interface.
pub enum MigrationEntry {
    /// Safe device instance with migration interface.
    Safe(Arc<dyn MigrationHook + Send + Sync>),
    /// Mutex device instance with migration interface.
    Mutex(Arc<Mutex<dyn MigrationHook + Send + Sync>>),
    /// Safe memory instance with migration interface.
    Memory(Arc<dyn MigrationHook + Send + Sync>),
}

/// Ensure the recovery sequence of different devices based on priorities.
/// At present, we need to ensure that the state recovery of the gic device
/// must be after the cpu, so different priorities are defined.
#[derive(Debug)]
pub enum MigrationRestoreOrder {
    Default = 0,
    Gicv3 = 1,
    Gicv3Its = 2,
    Max = 3,
}

impl From<MigrationRestoreOrder> for u16 {
    fn from(order: MigrationRestoreOrder) -> u16 {
        match order {
            MigrationRestoreOrder::Default => 0,
            MigrationRestoreOrder::Gicv3 => 1,
            MigrationRestoreOrder::Gicv3Its => 2,
            _ => 3,
        }
    }
}

/// The entry list size is the same as the MigrationRestoreOrder number
type MigrationEntryList = [Vec<(String, MigrationEntry)>; 3];

/// This structure is to manage all resource during migration.
/// It is also the only way to call on `MIGRATION_MANAGER`.
pub struct MigrationManager {
    /// The map offers the device_id and combined migratable device entry.
    pub(crate) entry: Arc<RwLock<MigrationEntryList>>,
    /// The map offers the device type and its device state describe structure.
    pub(crate) desc_db: Arc<RwLock<HashMap<String, DeviceStateDesc>>>,
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
    /// * `restore_order` - device restore order.
    pub fn register_device_instance<T>(
        device_desc: DeviceStateDesc,
        device_entry: Arc<T>,
        restore_order: MigrationRestoreOrder,
    ) where
        T: MigrationHook + Sync + Send + 'static,
    {
        let name = device_desc.name.clone();
        Self::register_device_desc(device_desc);

        let entry = MigrationEntry::Safe(device_entry);
        info!(
            "Register device instance: id {} order {:?}",
            &name, &restore_order
        );
        MigrationManager::insert_entry(name, restore_order.into(), entry, true);
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
        let name = device_desc.name.clone();
        let order = MigrationRestoreOrder::Default.into();
        Self::register_device_desc(device_desc);

        let entry = MigrationEntry::Mutex(device_entry);
        info!("Register device instance mutex: id {}", &name);
        MigrationManager::insert_entry(name, order, entry, true);
    }

    pub fn register_device_instance_mutex_with_id<T>(
        device_desc: DeviceStateDesc,
        device_entry: Arc<Mutex<T>>,
        id: &str,
    ) where
        T: MigrationHook + Sync + Send + 'static,
    {
        let name = device_desc.name.clone() + "/" + id;
        let order = MigrationRestoreOrder::Default.into();
        Self::register_device_desc(device_desc);
        let entry = MigrationEntry::Mutex(device_entry);
        info!("Register device instance with id: id {}", &name);
        MigrationManager::insert_entry(name, order, entry, false);
    }

    pub fn unregister_device_instance_mutex_by_id(device_desc: DeviceStateDesc, id: &str) {
        let name = device_desc.name + "/" + id;
        info!("Unregister device instance: id {}", &name);
        MigrationManager::remove_entry(&name);
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
        info!("Register memory instance");
        MigrationManager::insert_entry(String::from("MemoryState/Memory"), 0, entry, true);
    }

    /// Insert entry. If the name is duplicated, you should set gen_instance_id to true to
    /// generated instance id to ensure that the id is unique.
    ///
    /// # Arguments
    ///
    /// * `name` - Entry name.
    /// * `order` - Restore order.
    /// * `entry` - Instance with migratable interface.
    /// * `gen_instance_id` - If auto-generated instance id.
    fn insert_entry(name: String, order: u16, entry: MigrationEntry, gen_instance_id: bool) {
        let mut entrys = MIGRATION_MANAGER.entry.write().unwrap();
        let mut index = 0;
        if gen_instance_id {
            for (key, _) in &entrys[order as usize] {
                if let Some(pos) = key.rfind(':') {
                    let (tmp_id, num_id) = key.split_at(pos);
                    if tmp_id == name {
                        let num = num_id.strip_prefix(':').unwrap();
                        index = cmp::max(index, num.parse::<u16>().unwrap() + 1);
                    }
                }
            }
        }
        // ID is format as "{name}:{instance_id}"
        let id = format!("{}:{}", name, index);
        debug!("Insert entry: id {}", &id);
        entrys[order as usize].push((id, entry));
    }

    /// Remove entry by the unique name. Not support to remove the entry with instance id.
    ///
    /// # Arguments
    ///
    /// * `name` - Entry name.
    fn remove_entry(name: &str) {
        let eid = format!("{}:0", name);
        let mut entrys = MIGRATION_MANAGER.entry.write().unwrap();
        for (i, item) in entrys.iter().enumerate() {
            let pos = item.iter().position(|(key, _)| key == &eid);
            if let Some(index) = pos {
                debug!("Remove entry: eid {}", &eid);
                entrys[i].remove(index);
                return;
            }
        }
    }

    /// Get `Device`'s alias from device type string.
    ///
    /// # Argument
    ///
    /// * `device_type` - The type string of device instance.
    pub fn get_desc_alias(device_type: &str) -> Option<u64> {
        Some(id_remap(device_type))
    }

    /// Return `desc_db` value len(0 restored as `serde_json`)
    pub fn get_desc_db_len() -> Result<usize> {
        let mut db_data_len = 0;
        let desc_db = MIGRATION_MANAGER.desc_db.read().unwrap();
        for (_, desc) in desc_db.iter() {
            let desc_str = serde_json::to_string(desc)?;
            db_data_len += desc_str.as_bytes().len();
        }

        Ok(db_data_len)
    }

    /// Write all `DeviceStateDesc` in `desc_db` hashmap to `Write` trait object.
    pub fn save_descriptor_db(writer: &mut dyn Write) -> Result<()> {
        let desc_length = Self::get_desc_db_len()?;
        let mut desc_buffer = Vec::new();
        desc_buffer.resize(desc_length, 0);
        let mut start = 0;

        let desc_db = MIGRATION_MANAGER.desc_db.read().unwrap();
        for (_, desc) in desc_db.iter() {
            let desc_str = serde_json::to_string(desc)?;
            let desc_bytes = desc_str.as_bytes();
            desc_buffer[start..start + desc_bytes.len()].copy_from_slice(desc_bytes);
            start += desc_bytes.len();
        }
        writer
            .write_all(&desc_buffer)
            .chain_err(|| "Failed to write descriptor message.")?;

        Ok(())
    }

    /// Load and parse device state descriptor from `Read` trait object. Save as a Hashmap.
    pub fn load_descriptor_db(
        reader: &mut dyn Read,
        desc_length: usize,
    ) -> Result<HashMap<u64, DeviceStateDesc>> {
        let mut desc_buffer = Vec::new();
        desc_buffer.resize(desc_length, 0);
        reader.read_exact(&mut desc_buffer)?;
        let mut snapshot_desc_db = HashMap::<u64, DeviceStateDesc>::new();

        let deserializer = serde_json::Deserializer::from_slice(&desc_buffer);
        for desc in deserializer.into_iter::<DeviceStateDesc>() {
            let device_desc: DeviceStateDesc = match desc {
                Ok(desc) => desc,
                Err(_) => break,
            };
            snapshot_desc_db.insert(device_desc.alias, device_desc);
        }

        Ok(snapshot_desc_db)
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

        MigrationManager::register_device_instance(
            DeviceV1State::descriptor(),
            device_v1,
            MigrationRestoreOrder::Default,
        );
        MigrationManager::register_memory_instance(device_v2);
        MigrationManager::register_device_instance_mutex(
            DeviceV2State::descriptor(),
            device_v2_mutex,
        );

        assert!(MigrationManager::get_desc_alias("DeviceV1State").is_some());
        assert_eq!(
            MigrationManager::get_desc_alias("DeviceV1State").unwrap(),
            id_remap("DeviceV1State")
        );
        assert!(MigrationManager::get_desc_alias("DeviceV2State").is_some());
        assert_eq!(
            MigrationManager::get_desc_alias("DeviceV2State").unwrap(),
            id_remap("DeviceV2State")
        );
    }
}
