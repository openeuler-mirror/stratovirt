// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

/// BaseDevice is a simplest demo-pci-device. Its function is to
/// multiply data writed by two and return it when reading.
use crate::demo_dev::DeviceTypeOperation;
use address_space::GuestAddress;
pub use anyhow::{bail, Result};
use std::collections::HashMap;

#[derive(Default)]
pub struct BaseDevice {
    result: HashMap<u64, u8>,
}

impl BaseDevice {
    pub fn new() -> Self {
        Self {
            result: HashMap::new(),
        }
    }
}

impl DeviceTypeOperation for BaseDevice {
    // The base device can multiply the value with 2 when writing to mmio.
    fn write(&mut self, data: &[u8], addr: GuestAddress, _offset: u64) -> Result<()> {
        let value = data[0].checked_mul(2).unwrap_or(0);
        self.result.insert(addr.raw_value(), value);
        Ok(())
    }

    // Rm the data after reading, as we assume that the data becomes useless after the test
    // process checked the addr.
    fn read(&mut self, data: &mut [u8], addr: GuestAddress, _offset: u64) -> Result<()> {
        data[0] = *self.result.get(&addr.raw_value()).unwrap_or(&0);
        self.result.remove(&addr.raw_value());
        Ok(())
    }

    fn realize(&mut self) -> Result<()> {
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }
}
