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

use super::errors::{ErrorKind, Result};
use crate::VncClient;

/// Authentication type
#[derive(Clone, Copy)]
pub enum AuthState {
    Invalid = 0,
    No = 1,
    Vnc = 2,
    Vencrypt = 19,
    Sasl = 20,
}

/// Authentication and encryption method
#[derive(Clone, Copy)]
pub enum SubAuthState {
    VncAuthVencryptPlain = 256,
    VncAuthVencryptX509None = 260,
    VncAuthVencryptX509Sasl = 263,
    VncAuthVencryptTlssasl = 264,
}

impl VncClient {
    /// Send auth version
    pub fn protocol_client_vencrypt_init(&mut self) -> Result<()> {
        Ok(())
    }
}
