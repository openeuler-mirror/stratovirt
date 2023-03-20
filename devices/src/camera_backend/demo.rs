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

//! Demo backend for vCamera device, that helps for testing.

use super::CamFmt;

#[allow(dead_code)]
pub struct DemoHostDev {
    buffer: Vec<u8>, // buffer that stores video frame

    hostfmt: CamFmt, // the combination of video formats that the hardware supports
    pub cur_fmt: CamFmt, // the combination of video formats that we negotiated with the hardware
}
