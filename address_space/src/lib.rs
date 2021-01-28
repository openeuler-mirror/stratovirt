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

#![allow(missing_docs)]
//! Manages address resources that used by Vm's memory and emulated devices.
//!
//! # Examples
//!
//! ```rust
//! use std::sync::{Arc, Mutex};
//! extern crate address_space;
//! use address_space::{AddressSpace, Region, GuestAddress, HostMemMapping, RegionOps, FileBackend};
//!
//! struct DummyDevice;
//! impl DummyDevice {
//!     fn read(&mut self, data: &mut [u8], base: GuestAddress, offset: u64) -> bool {
//!         // read operation omitted
//!         true
//!     }
//!     fn write(&mut self, data: &[u8], base: GuestAddress, offset: u64) -> bool {
//!         // write operation omitted
//!         true
//!     }
//! }
//!
//! fn main() {
//!     // 1. create address_space
//!     let space = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
//!
//!     // 2. create an Ram-type Region, and set it's priority
//!     let mem_mapping = Arc::new(HostMemMapping::new(GuestAddress(0), 0x1000, None, false, false).unwrap());
//!     let ram_region = Region::init_ram_region(mem_mapping.clone());
//!     ram_region.set_priority(10);
//!
//!     // 3. create a IO-type Region
//!     let dev = Arc::new(Mutex::new(DummyDevice));
//!     let dev_clone = dev.clone();
//!     let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
//!         let mut dev_locked = dev_clone.lock().unwrap();
//!         dev_locked.read(data, addr, offset)
//!     };
//!     let dev_clone = dev.clone();
//!     let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
//!         let mut dev_locked = dev_clone.lock().unwrap();
//!         dev_locked.write(data, addr, offset)
//!     };
//!     let dev_ops = RegionOps {
//!         read: Arc::new(read_ops),
//!         write: Arc::new(write_ops),
//!     };
//!
//!     let io_region = Region::init_io_region(0x1000, dev_ops);
//!
//!     // 4. add sub_region to address_space's root region
//!     space.root().add_subregion(ram_region, mem_mapping.start_address().raw_value());
//!     space.root().add_subregion(io_region, 0x2000);
//!
//!     // 5. access address_space
//!     space.write_object(&0x11u64, GuestAddress(0));
//! }
//! ```

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

mod address;
mod address_space;
mod host_mmap;
mod listener;
mod region;

pub use crate::address_space::AddressSpace;
pub use address::{AddressRange, GuestAddress};
pub use host_mmap::{create_host_mmaps, FileBackend, HostMemMapping};
#[cfg(target_arch = "x86_64")]
pub use listener::KvmIoListener;
pub use listener::KvmMemoryListener;
pub use listener::{Listener, ListenerReqType};
pub use region::{FlatRange, Region, RegionIoEventFd, RegionType};

pub mod errors {
    error_chain! {
        foreign_links {
            Io(std::io::Error);
        }
        errors {
            ListenerRequest(req_type: crate::listener::ListenerReqType) {
                display("Failed to call listener, request type is {:#?}", req_type)
            }
            UpdateTopology(base: u64, size: u64, reg_ty: crate::RegionType) {
                display("Failed to update topology, base 0x{:X}, size 0x{:X}, region type is {:#?}", base, size, reg_ty)
            }
            IoEventFd {
                display("Failed to clone EventFd")
            }
            AddrAlignUp(addr: u64, align: u64) {
                display("Failed to align-up address, overflows: addr 0x{:X}, align 0x{:X}", addr, align)
            }
            RegionNotFound(addr: u64) {
                display("Failed to find matched region, addr 0x{:X}", addr)
            }
            Overflow(addr: u64) {
                display("Address overflows, addr is 0x{:X}", addr)
            }
            Mmap {
                display("Failed to mmap")
            }
            IoAccess(offset: u64) {
                display("Access io region failed, offset is 0x{:X}", offset)
            }
            RegionType(t: crate::RegionType) {
                display("Wrong region type, {:#?}", t)
            }
            NoAvailKvmSlot(cnt: usize) {
                display("No available kvm_mem_slot, total count is {}", cnt)
            }
            NoMatchedKvmSlot(addr: u64, sz: u64) {
                display("Failed to find matched kvm_mem_slot, addr 0x{:X}, size 0x{:X}", addr, sz)
            }
            KvmSlotOverlap(add: (u64, u64), exist: (u64, u64)) {
                display("Added KVM mem range (0x{:X}, 0x{:X}) overlaps with exist one (0x{:X}, 0x{:X})", add.0, add.1, exist.0, exist.1)
            }
        }
    }
}

/// Provide Some operations of `Region`, mainly used by Vm's devices.
#[derive(Clone)]
pub struct RegionOps {
    /// Read data from Region to argument `data`,
    /// return `true` if read successfully, or return `false`.
    ///
    /// # Arguments
    ///
    /// * `data` - A u8-type array.
    /// * `base` - Base address.
    /// * `offset` - Offset from base address.
    pub read: std::sync::Arc<dyn Fn(&mut [u8], GuestAddress, u64) -> bool + Send + Sync>,
    /// Write `data` to memory,
    /// return `true` if write successfully, or return `false`.
    ///
    /// # Arguments
    ///
    /// * `data` - A u8-type array.
    /// * `base` - Base address.
    /// * `offset` - Offset from base address.
    pub write: std::sync::Arc<dyn Fn(&[u8], GuestAddress, u64) -> bool + Send + Sync>,
}

/// Gets the page size of system.
#[inline]
pub fn page_size() -> u64 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}
