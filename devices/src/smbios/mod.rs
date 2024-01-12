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

pub mod smbios_table;

// The name of corresponding file-entry in FwCfg device that represents smbios table data.
pub const SMBIOS_TABLE_FILE: &str = "etc/smbios/smbios-tables";
// The name of corresponding file-entry in FwCfg device that represents smbios table anchor.
pub const SMBIOS_ANCHOR_FILE: &str = "etc/smbios/smbios-anchor";
