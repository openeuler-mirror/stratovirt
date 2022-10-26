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
extern crate log;

pub mod error;
pub use anyhow::Result;
pub use error::UsbError;

pub mod bus;
pub mod config;
mod descriptor;
pub mod hid;
pub mod keyboard;
pub mod tablet;
pub mod usb;
pub mod xhci;

use crate::keyboard::UsbKeyboard;
use crate::tablet::UsbTablet;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};

pub struct Input {
    pub keyboard: Option<Arc<Mutex<UsbKeyboard>>>,
    pub tablet: Option<Arc<Mutex<UsbTablet>>>,
}
pub static INPUT: Lazy<Arc<Mutex<Input>>> = Lazy::new(|| {
    Arc::new(Mutex::new(Input {
        keyboard: None,
        tablet: None,
    }))
});
