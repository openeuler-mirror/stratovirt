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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
//#[macro_use]
extern crate sscanf;
//#[macro_use]
extern crate vmm_sys_util;

pub mod errors {
    error_chain! {
        links {
            Util(util::errors::Error, util::errors::ErrorKind);
        }
        errors {
            UnsupportRFBProtocolVersion {
                display("Unsupported RFB Protocol Version!")
            }
            InvalidImageSize {
                display("Invalid Image Size!")
            }
            TcpBindFailed(reason: String) {
                display("Tcp bind failed: {}", reason)
            }
            MakeTlsConnectionFailed(reason: String) {
                display("Make tls connection failed: {}", reason)
            }
            ProtocolMessageFailed(reason: String) {
                display("ProtocolMessage failed: {}", reason)
            }
            ReadMessageFailed(reason: String) {
                display("Read buf form tcpstream failed: {}", reason)
            }
            AuthFailed(reason: String){
                display("Authentication failed: {}", reason)
            }
            ParseKeyBoardFailed(reason: String) {
                display("ParseKeyBoardFailed: {}", reason)
            }
        }
    }
}

pub mod auth;
pub mod client;
mod data;
pub mod input;
pub mod pixman;
pub mod server;
pub mod utils;
pub mod vnc;

pub const fn round_up_div(n: u64, d: u64) -> u64 {
    (n + d - 1) / d
}

pub const fn round_up(n: u64, d: u64) -> u64 {
    round_up_div(n, d) * d
}
