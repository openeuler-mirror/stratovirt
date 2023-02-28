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

use std::mem;

use devices::legacy::FwCfgEntryType;

use super::malloc::GuestAllocator;
use crate::libtest::TestState;
use crate::utils::{swap_u16, swap_u32, swap_u64};
use machine::standard_vm::aarch64::{LayoutEntryType, MEM_LAYOUT};

#[cfg(target_arch = "aarch64")]
pub const FW_CFG_BASE: u64 = MEM_LAYOUT[LayoutEntryType::FwCfg as usize].0;
#[cfg(target_arch = "x86_64")]
pub const FW_CFG_BASE: u64 = 0x510;

const FW_CFG_FNAME_SIZE: usize = 56;

#[repr(C)]
pub struct FwCfgDmaAccess {
    control: u32,
    length: u32,
    address: u64,
}

pub fn bios_args(base_args: &mut Vec<&str>) {
    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    base_args.append(&mut args);
    args = "-drive file=/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw,if=pflash,unit=0,readonly=true"
        .split(' ')
        .collect();
    base_args.append(&mut args);
}

impl TestState {
    pub fn fw_cfg_read_bytes(&self, key: u16, data: &mut Vec<u8>, len: u32) {
        self.writew(FW_CFG_BASE + 0x8, swap_u16(key));
        for _i in 0..len {
            data.push(self.readb(FW_CFG_BASE))
        }
    }

    pub fn fw_cfg_read_u16(&self, key: u16) -> u16 {
        self.writew(FW_CFG_BASE + 0x8, swap_u16(key));
        self.readw(FW_CFG_BASE)
    }

    pub fn fw_cfg_read_u32(&self, key: u16) -> u32 {
        self.writew(FW_CFG_BASE + 0x8, swap_u16(key));
        self.readl(FW_CFG_BASE)
    }

    pub fn dma_transfer_bytes(&self, access: u64, buff: u64, size: u32, ctrl: u32) {
        self.writel(access, swap_u32(ctrl));
        self.writel(access + 4, swap_u32(size));
        self.writeq(access + 8, swap_u64(buff));

        self.writeq(FW_CFG_BASE + 0x10, swap_u64(access));
    }

    pub fn fw_cfg_read_file(
        &self,
        allocator: &mut GuestAllocator,
        file_name: &str,
        data: &mut Vec<u8>,
        data_len: u32,
    ) -> u32 {
        let file_name_len = file_name.to_string().len();
        let mut file_size = 0;
        let mut name: [u8; FW_CFG_FNAME_SIZE] = [0; FW_CFG_FNAME_SIZE];
        let buff = allocator.alloc(FW_CFG_FNAME_SIZE as u64);
        let access = allocator.alloc(mem::size_of::<FwCfgDmaAccess>() as u64);

        self.writew(FW_CFG_BASE + 0x8, swap_u16(FwCfgEntryType::FileDir as u16));
        let count = swap_u32(self.readl(FW_CFG_BASE));
        for _i in 0..count {
            let mut size = swap_u32(self.readl(FW_CFG_BASE));
            let select = swap_u16(self.readw(FW_CFG_BASE));
            let _reserved = swap_u16(self.readw(FW_CFG_BASE));
            // Read file name by DMA.
            self.dma_transfer_bytes(access, buff, FW_CFG_FNAME_SIZE as u32, 2);
            for i in 0..FW_CFG_FNAME_SIZE {
                name[i] = self.readb(buff + i as u64);
            }
            if String::from_utf8_lossy(&name[0..file_name_len]).eq(file_name) {
                file_size = size;
                if size > data_len {
                    size = data_len;
                }
                self.fw_cfg_read_bytes(select, data, size);
                break;
            }
        }
        file_size
    }

    pub fn fw_cfg_write_file(
        &self,
        allocator: &mut GuestAllocator,
        file_name: &str,
        data_access: u64,
        data_addr: u64,
        data_len: u32,
    ) {
        let file_name_len = file_name.to_string().len();
        let mut name: [u8; FW_CFG_FNAME_SIZE] = [0; FW_CFG_FNAME_SIZE];
        let buff = allocator.alloc(FW_CFG_FNAME_SIZE as u64);
        let access = allocator.alloc(mem::size_of::<FwCfgDmaAccess>() as u64);

        self.writew(FW_CFG_BASE + 0x8, swap_u16(FwCfgEntryType::FileDir as u16));
        let count = swap_u32(self.readl(FW_CFG_BASE));
        for _i in 0..count {
            let _size = swap_u32(self.readl(FW_CFG_BASE));
            let select = swap_u16(self.readw(FW_CFG_BASE));
            let _reserved = swap_u16(self.readw(FW_CFG_BASE));
            // Read file name by DMA.
            self.dma_transfer_bytes(access, buff, FW_CFG_FNAME_SIZE as u32, 2);
            for i in 0..FW_CFG_FNAME_SIZE {
                name[i] = self.readb(buff + i as u64);
            }
            if String::from_utf8_lossy(&name[0..file_name_len]).eq(file_name) {
                self.writew(FW_CFG_BASE + 0x8, swap_u16(select));
                self.dma_transfer_bytes(data_access, data_addr, data_len, 16);
                break;
            }
        }
    }
}
