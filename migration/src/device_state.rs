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

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use super::errors::Result;

/// Version check result enum.
#[derive(PartialEq, Debug)]
pub enum VersionCheck {
    /// Version is completely same.
    Same,
    /// Version is not same but compat.
    Compat,
    /// Version is not compatible.
    Mismatch,
}

/// Trait to acquire `DeviceState` bytes slice from `Device` and recover
/// `Device`'s state from `DeviceState` bytes slice.
///
/// # Notes
/// `DeviceState` structure is to save some device state such as register data
/// and switch flag value. `DeviceState` must implement the `ByteCode` trait.
/// So it can be transferred to bytes slice directly.
pub trait StateTransfer {
    /// Get `Device`'s state to `DeviceState` structure as bytes vector.
    fn get_state_vec(&self) -> Result<Vec<u8>>;

    /// Set a `Device`'s state from bytes slice as `DeviceState` structure.
    fn set_state(&self, _state: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Set a `Device`'s state in mutable `Device` structure from bytes slice
    /// as `DeviceState` structure.
    fn set_state_mut(&mut self, _state: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Upgrade some high-version information.
    fn upgrade_version(&mut self) {}

    /// Downcast some high-version information.
    fn downcast_version(&mut self) {}

    /// Get `DeviceState` alias used for `InstanceId`.
    fn get_device_alias(&self) -> u64;
}

/// The structure to describe `DeviceState` structure with version messege.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStateDesc {
    /// Device type identfy.
    pub name: String,
    /// Alias for device type.
    pub alias: u64,
    /// Size of `DeviceState` structure.
    pub size: u32,
    /// Device current migration version.
    pub current_version: u32,
    /// The minimum required device migration version.
    pub compat_version: u32,
    /// Field descriptor of `DeviceState` structure.
    pub fields: Vec<FieldDesc>,
}

/// The structure to describe struct field in `DeviceState` structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldDesc {
    /// Field var name.
    pub var_name: String,
    /// Field type name.
    pub type_name: String,
    /// Alias for field.
    pub alias: String,
    /// Offset for this field in bytes slice.
    pub offset: u32,
    /// Size of this field.
    pub size: u32,
}

impl DeviceStateDesc {
    /// Check the field is exist in `DeviceState` with a field alias.
    fn contains(&self, alias_name: &str) -> bool {
        for field in &self.fields {
            if alias_name == field.alias {
                return true;
            }
        }

        false
    }

    /// Get a slice index: (start, end) for given field alias.
    fn get_slice_index(&self, alias_name: &str) -> Result<(usize, usize)> {
        for field in &self.fields {
            if alias_name == field.alias {
                let start = field.offset as usize;
                let end = start + field.size as usize;
                if end > self.size as usize {
                    bail!("Data slice index out of range");
                }
                return Ok((start, end));
            }
        }

        bail!("Don't have this alias name: {}", alias_name)
    }

    /// Check padding from a device state descriptor to another version device state
    /// descriptor. The padding will be added tinto current_slice for `DeviceState`.
    ///
    /// # Arguments
    ///
    /// * `desc` - device state descriptor for old version `DeviceState`.
    /// * `current_slice` - current slice for `DeviceState`.
    pub fn add_padding(&self, desc: &DeviceStateDesc, current_slice: &mut Vec<u8>) -> Result<()> {
        let tmp_slice = current_slice.clone();
        current_slice.clear();
        current_slice.resize(self.size as usize, 0);
        for field in self.clone().fields {
            if desc.contains(&field.alias) {
                let (new_start, new_end) = desc.get_slice_index(&field.alias)?;
                let (start, mut end) = self.get_slice_index(&field.alias)?;

                // Make snap_desc field data length fit with current field data length.
                if new_end - new_start > end - start {
                    end += (new_end - new_start) - (end - start);
                } else {
                    end -= (end - start) - (new_end - new_start);
                }

                current_slice[start..end].clone_from_slice(&tmp_slice[new_start..new_end]);
            }
        }

        Ok(())
    }

    /// Check device state version descriptor version messege.
    /// If version is same, return enum `Same`.
    /// If version is not same but fit, return enum `Compat`.
    /// if version is not fit, return enum `Mismatch`.
    ///
    /// # Arguments
    ///
    /// * `desc`: device state descriptor for old version `DeviceState`.
    pub fn check_version(&self, desc: &DeviceStateDesc) -> VersionCheck {
        match self.current_version.cmp(&desc.current_version) {
            Ordering::Equal => VersionCheck::Same,
            Ordering::Greater => VersionCheck::Compat,
            Ordering::Less => VersionCheck::Mismatch,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::{DeviceStateDesc, FieldDesc, StateTransfer, VersionCheck};
    use util::byte_code::ByteCode;

    struct MigrationManager {}
    impl MigrationManager {
        fn desc_db_len() -> u64 {
            0
        }
    }

    #[derive(Default)]
    // A simple device version 1.
    pub struct DeviceV1 {
        state: DeviceV1State,
    }

    #[derive(Default)]
    // A simple device version 2.
    pub struct DeviceV2 {
        state: DeviceV2State,
    }

    #[derive(Copy, Clone, Desc, ByteCode)]
    #[desc_version(current_version = "1.0.0", compat_version = "0.1.0")]
    // Statement for DeviceV1.
    pub struct DeviceV1State {
        ier: u8,
        iir: u8,
        lcr: u8,
    }

    #[derive(Copy, Clone, Desc, ByteCode)]
    #[desc_version(current_version = "2.0.0", compat_version = "0.1.0")]
    // Statement for DeviceV2.
    pub struct DeviceV2State {
        ier: u8,
        iir: u8,
        lcr: u8,
        mcr: u8,
    }

    impl StateTransfer for DeviceV1 {
        fn get_state_vec(&self) -> super::Result<Vec<u8>> {
            Ok(self.state.as_bytes().to_vec())
        }

        fn set_state_mut(&mut self, state: &[u8]) -> super::Result<()> {
            self.state = *DeviceV1State::from_bytes(state).unwrap();
            Ok(())
        }

        fn get_device_alias(&self) -> u64 {
            0
        }
    }

    impl StateTransfer for DeviceV2 {
        fn get_state_vec(&self) -> super::Result<Vec<u8>> {
            Ok(self.state.as_bytes().to_vec())
        }

        fn set_state_mut(&mut self, state: &[u8]) -> super::Result<()> {
            self.state = *DeviceV2State::from_bytes(state).unwrap();
            Ok(())
        }

        fn upgrade_version(&mut self) {
            self.state.mcr = 255_u8;
        }

        fn get_device_alias(&self) -> u64 {
            0
        }
    }

    #[test]
    fn test_desc_padding() {
        /*
         * This test makes two version of a device.
         * Those devices's difference is appending a new field `mcr` in
         * device state.
         * Add_padding can solve this change in descriptor of device state.
         * Test can verify this function works.
         */

        let mut device_v1 = DeviceV1 {
            state: DeviceV1State::default(),
        };

        device_v1.state.ier = 1;
        device_v1.state.iir = 2;
        device_v1.state.lcr = 3;

        let state_1_desc = DeviceV1State::descriptor();
        let state_2_desc = DeviceV2State::descriptor();

        assert_eq!(
            state_2_desc.check_version(&state_1_desc),
            VersionCheck::Compat
        );

        let mut current_slice = device_v1.get_state_vec().unwrap();
        assert_eq!(
            state_2_desc
                .add_padding(&state_1_desc, &mut current_slice)
                .is_ok(),
            true
        );

        let mut device_v2 = DeviceV2 {
            state: DeviceV2State::default(),
        };
        device_v2.set_state_mut(&current_slice).unwrap();
        assert!(state_2_desc.current_version > state_1_desc.current_version);
        device_v2.upgrade_version();

        assert_eq!(device_v2.state.ier, device_v1.state.ier);
        assert_eq!(device_v2.state.iir, device_v1.state.iir);
        assert_eq!(device_v2.state.lcr, device_v1.state.lcr);
        assert_eq!(device_v2.state.mcr, 255_u8);
    }
}
