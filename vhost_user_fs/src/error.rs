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

#[derive(Error, Debug)]
pub enum VhostUserFsError {
    #[error("Util")]
    Util {
        #[from]
        source: util::error::UtilError,
    },
    #[error("Virtio")]
    Virtio {
        #[from]
        source: virtio::error::VirtioError,
    },
    #[error("AddressSpace")]
    AddressSpace {
        #[from]
        source: address_space::error::AddressSpaceError,
    },
}
