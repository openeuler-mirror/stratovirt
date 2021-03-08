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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

pub mod errors {
    error_chain! {
        errors {
            AddPciCap(id: u8, size: usize) {
                display("Failed to add PCI capability: id 0x{:x}, size: 0x{:x}.", id, size)
            }
            AddPcieExtCap(id: u8, size: usize) {
                display("Failed to add PCIe extended capability: id 0x{:x}, size: 0x{:x}.", id, size)
            }
            UnregMemBar(id: usize) {
                display("Failed to unmap BAR {} in memory space.", id)
            }
        }
    }
}

mod bus;
#[allow(dead_code)]
mod config;
mod msix;

use std::mem::size_of;
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use kvm_ioctls::VmFd;

use errors::Result;

const BDF_FUNC_SHIFT: u8 = 3;

macro_rules! le_write {
    ($name: ident, $func: ident, $type: tt) => {
        pub fn $name(buf: &mut [u8], offset: usize, data: $type) -> Result<()> {
            let data_len: usize = size_of::<$type>();
            let buf_len: usize = buf.len();
            if offset + data_len > buf_len {
                bail!(
                    "Out-of-bounds write access: buf_len = {}, offset = {}, data_len = {}",
                    buf_len,
                    offset,
                    data_len
                );
            }
            LittleEndian::$func(&mut buf[offset..(offset + data_len)], data);
            Ok(())
        }
    };
}

le_write!(le_write_u16, write_u16, u16);
le_write!(le_write_u32, write_u32, u32);
le_write!(le_write_u64, write_u64, u64);

macro_rules! le_read {
    ($name: ident, $func: ident, $type: tt) => {
        pub fn $name(buf: &[u8], offset: usize) -> Result<$type> {
            let data_len: usize = size_of::<$type>();
            let buf_len: usize = buf.len();
            if offset + data_len > buf_len {
                bail!(
                    "Out-of-bounds read access: buf_len = {}, offset = {}, data_len = {}",
                    buf_len,
                    offset,
                    data_len
                );
            }
            Ok(LittleEndian::$func(&buf[offset..(offset + data_len)]))
        }
    };
}

le_read!(le_read_u16, read_u16, u16);
le_read!(le_read_u32, read_u32, u32);
le_read!(le_read_u64, read_u64, u64);

pub trait PciDevOps: Send {
    /// Init writable bit mask.
    fn init_write_mask(&mut self) -> Result<()>;

    /// Init write-and-clear bit mask.
    fn init_write_clear_mask(&mut self) -> Result<()>;

    /// Realize PCI/PCIe device.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - File descriptor of VM.
    fn realize(&mut self, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Configuration space read.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in configuration space.
    /// * `data` - Data buffer for reading.
    fn read_config(&self, offset: usize, data: &mut [u8]);

    /// Configuration space write.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in configuration space.
    /// * `data` - Data to write.
    fn write_config(&mut self, offset: usize, data: &mut [u8]);

    /// Set device id to send MSI/MSI-X.
    ///
    /// # Arguments
    ///
    /// * `bus_num` - Bus number.
    /// * `devfn` - Slot number << 8 | Function number.
    ///
    /// # Returns
    ///
    /// Device id to send MSI/MSI-X.
    fn set_dev_id(&self, bus_num: u8, devfn: u8) -> u16 {
        let bus_shift: u16 = 8;
        ((bus_num as u16) << bus_shift) | (devfn as u16)
    }

    /// Get device name.
    fn name(&self) -> String;
}
