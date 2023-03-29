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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("UtilError")]
    UtilError {
        #[from]
        source: util::error::UtilError,
    },
    #[error("JsonSerde")]
    JsonSerde {
        #[from]
        source: serde_json::Error,
    },
    #[error("Invalid json field \'{0}\'")]
    InvalidJsonField(String),
    #[error("Invalid parameter \'{0}\' for \'{1}\'")]
    InvalidParam(String, String),
    #[error("Unable to parse \'{0}\' for \'{1}\'")]
    ConvertValueFailed(String, String),
    #[error("Input {0} string's length must be no more than {1}.")]
    StringLengthTooLong(String, usize),
    #[error("Input field \'{0}\' in {1} is offered more than once.")]
    FieldRepeat(String, String),
    #[error("Input id \'{0}\' for {1} repeat.")]
    IdRepeat(String, String),
    #[error("Integer overflow occurred during parse {0}!")]
    IntegerOverflow(String),
    #[error("Unknown device type: {0}!")]
    UnknownDeviceType(String),
    #[error("\'{0}\' is missing for \'{1}\' device.")]
    FieldIsMissing(String, String),
    #[error("{0} must >{} {1} and <{} {3}.", if *.2 {"="} else {""}, if *.4 {"="} else {""})]
    IllegalValue(String, u64, bool, u64, bool),
    #[error("{0} must {}{} {3}.", if *.1 {">"} else {"<"}, if *.2 {"="} else {""})]
    IllegalValueUnilateral(String, bool, bool, u64),
    #[error("Mac address is illegal.")]
    MacFormatError,
    #[error("Unknown vhost type.")]
    UnknownVhostType,
    #[error("{0} is not a regular File.")]
    UnRegularFile(String),
    #[error("{0} is not a regular file or block device.")]
    UnRegularFileOrBlk(String),
    #[error("Failed to get metadata of file {0}: {1}.")]
    NoMetadata(String, String),
    #[error("Input value {0} is unaligned with {1} for {2}.")]
    Unaligned(String, u64, u64),
    #[error("{0} given {1} should not be more than {2}")]
    UnitIdError(String, usize, usize),
    #[error("Directory {0} does not exist")]
    DirNotExist(String),
    #[error("File {0} does not exist")]
    FileNotExist(String),
}
