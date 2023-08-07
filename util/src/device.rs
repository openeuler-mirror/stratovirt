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

#[derive(Clone, Default)]
pub struct DeviceBase {
    /// Name of this device.
    pub id: String,
    /// Whether it supports hot-plug/hot-unplug.
    pub hotpluggable: bool,
}

impl DeviceBase {
    pub fn new(id: String, hotpluggable: bool) -> Self {
        DeviceBase { id, hotpluggable }
    }
}

pub trait Device {
    fn device_base(&self) -> &DeviceBase;

    fn device_base_mut(&mut self) -> &mut DeviceBase;

    /// Get device name.
    fn name(&self) -> String {
        self.device_base().id.clone()
    }

    /// Query whether it supports hot-plug/hot-unplug.
    fn hotpluggable(&self) -> bool {
        self.device_base().hotpluggable
    }
}
