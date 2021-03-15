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

// FwCfg Signature
const FW_CFG_DMA_SIGNATURE: u128 = 0x51454d5520434647;
/// FwCfg version bits
const FW_CFG_VERSION: u16 = 0x01;
const FW_CFG_VERSION_DMA: u16 = 0x02;
// FwCfg related constants
const FW_CFG_FILE_SLOTS_DFLT: u16 = 0x20;
const FW_CFG_FILE_FIRST: u16 = 0x20;
const FW_CFG_WRITE_CHANNEL: u16 = 0x4000;
const FW_CFG_ARCH_LOCAL: u16 = 0x8000;
const FW_CFG_ENTRY_MASK: u16 = !(FW_CFG_WRITE_CHANNEL | FW_CFG_ARCH_LOCAL);
const FW_CFG_INVALID: u16 = 0xffff;

/// Define the Firmware Configuration Entry Type
#[repr(u16)]
pub enum FwCfgEntryType {
    Signature = 0x00,
    Id,
    Uuid,
    RamSize,
    NoGraphic,
    NbCpus,
    MachineId,
    KernelAddr,
    KernelSize,
    KernelCmdline,
    InitrdAddr,
    InitrdSize,
    BootDevice,
    Numa,
    BootMenu,
    MaxCpus,
    KernelEntry,
    KernelData,
    InitrdData,
    CmdlineAddr,
    CmdlineSize,
    CmdlineData,
    SetupAddr,
    SetupSize,
    SetupData,
    FileDir,
    #[cfg(target_arch = "x86_64")]
    Irq0Override = 0x8002,
    #[cfg(target_arch = "x86_64")]
    E820Table = 0x8003,
}
/// Get the FwCfg entry name of a given key
fn get_key_name(key: usize) -> &'static str {
    static FW_CFG_KEYS: [&str; 26] = [
        "signature",
        "id",
        "uuid",
        "ram_size",
        "nographic",
        "nb_cpus",
        "machine_id",
        "kernel_addr",
        "kernel_size",
        "kernel_cmdline",
        "initrd_addr",
        "initrd_size",
        "boot_device",
        "numa",
        "boot_menu",
        "max_cpus",
        "kernel_entry",
        "kernel_data",
        "initrd_data",
        "cmdline_addr",
        "cmdline_size",
        "cmdline_data",
        "setup_addr",
        "setup_size",
        "setup_data",
        "file_dir",
    ];

    if key < FW_CFG_FILE_FIRST as usize {
        FW_CFG_KEYS[key]
    } else {
        "unknown"
    }
}
