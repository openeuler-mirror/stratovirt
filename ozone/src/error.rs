// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

#[allow(clippy::upper_case_acronyms)]
#[derive(Error, Debug)]
pub enum OzoneError {
    #[error("Util error")]
    Util {
        #[from]
        source: util::error::UtilError,
    },
    #[error("Io")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("Failed to run binary file in ozone environment: {0}")]
    ExecError(std::io::Error),
    #[error("Failed to parse {0} to {1}")]
    DigitalParseError(&'static str, String),
    #[error("Failed to execute {0}")]
    CapsError(&'static str),
    #[error("Failed to write {0} to {1}")]
    WriteError(String, String),
}
