// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OzonecErr {
    #[error("Failed to access /proc/{0}")]
    ReadProcPid(i32),
    #[error("Failed to access /proc/{0}/status")]
    ReadProcStat(i32),
    #[error("Failed to open {0}")]
    OpenFile(String),
    #[error("Failed to create directory {0}")]
    CreateDir(String),
    #[error("Failed to mount {0}")]
    Mount(String),
    #[error("Failed to access /proc/self")]
    AccessProcSelf,
    #[error("Failed to get mountinfo")]
    GetMntInfo,
    #[error("Dup2 {0} error")]
    Dup2(String),
    #[error("Failed to get all capabilities of {0} set")]
    GetAllCaps(String),
    #[error("Failed to set the capability set {0}")]
    SetCaps(String),
    #[error("Failed to add architecture to seccomp filter")]
    AddScmpArch,
}
