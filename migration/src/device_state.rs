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
