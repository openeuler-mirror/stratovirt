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

use std::{
    sync::{Arc, Mutex, Weak},
    thread,
};

use address_space::{GuestAddress, HostMemMapping, Region};
use anyhow::{Context, Result};
use core::time;

use super::ivshmem::Ivshmem;
use pci::{PciBus, PciDevOps};

/// Scream sound card device structure.
pub struct Scream {
    hva: u64,
    size: u64,
}

impl Scream {
    pub fn new(size: u64) -> Self {
        Self { hva: 0, size }
    }

    fn start(&self) -> Result<()> {
        thread::Builder::new()
            .name("scream audio worker".to_string())
            .spawn(move || loop {
                thread::sleep(time::Duration::from_millis(50));
            })
            .with_context(|| "Failed to create thread scream")?;
        Ok(())
    }

    pub fn realize(mut self, devfn: u8, parent_bus: Weak<Mutex<PciBus>>) -> Result<()> {
        let host_mmap = Arc::new(HostMemMapping::new(
            GuestAddress(0),
            None,
            self.size,
            None,
            false,
            true,
            false,
        )?);
        self.hva = host_mmap.host_address();

        let mem_region = Region::init_ram_region(host_mmap);

        let ivshmem = Ivshmem::new("ivshmem".to_string(), devfn, parent_bus, mem_region);
        ivshmem.realize()?;

        self.start()
    }
}
