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

use address_space::Listener;

#[derive(Default, Clone)]
pub struct TestMemoryListener {
    enabled: bool,
}

impl Listener for TestMemoryListener {
    /// Get default priority.
    fn priority(&self) -> i32 {
        10_i32
    }

    /// Is this listener enabled to call.
    fn enabled(&self) -> bool {
        self.enabled
    }

    /// Enable listener for address space.
    fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable listener for address space.
    fn disable(&mut self) {
        self.enabled = false;
    }
}
