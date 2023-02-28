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

pub mod error;
pub use error::VncError;

pub mod auth;
pub mod client;
pub mod console;
mod data;
pub mod encoding;
pub mod input;
pub mod pixman;
pub mod server;
pub mod utils;
pub mod vencrypt;
pub mod vnc;

pub const fn round_up_div(n: u64, d: u64) -> u64 {
    (n + d - 1) / d
}

pub const fn round_up(n: u64, d: u64) -> u64 {
    round_up_div(n, d) * d
}
