// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::HashMap;
use std::sync::OnceLock;

use bitflags::bitflags;

bitflags! {
    pub struct UsbQuirk: u32 {
        const ALWAYS_SET_CONFIG = 1 << 0;
        const IGNORE_SET_CONFIG = 1 << 1;
    }
}

impl UsbQuirk {
    #[inline]
    pub fn always_set_config(&self) -> bool {
        self.contains(UsbQuirk::ALWAYS_SET_CONFIG)
    }

    #[inline]
    pub fn ignore_set_config(&self) -> bool {
        self.contains(UsbQuirk::IGNORE_SET_CONFIG)
    }
}

static USB_QUIRKS_TABLE: OnceLock<HashMap<(u16, u16), UsbQuirk>> = OnceLock::new();

fn quirks_table() -> &'static HashMap<(u16, u16), UsbQuirk> {
    USB_QUIRKS_TABLE.get_or_init(|| {
        let mut m = HashMap::new();
        // -----------------------------------------------------------------------------
        // Scanner (VID: 0x2010, PID: 0x7638)
        // -----------------------------------------------------------------------------
        // Symptom: The device has a flaw in its firmware state machine despite
        //          having only a single configuration.
        // Cause:   During passthrough, even if the Host OS has already set it to Config 1,
        //          the Guest driver still expects a real `set_config(1)` action during
        //          initialization. Without issuing the actual ioctl, the device's internal
        //          state machine fails to activate properly, causing subsequent control or
        //          bulk transfers to fail (the device refuses to work).
        // Fix:     Apply ALWAYS_SET_CONFIG to force issuing the ioctl to the host.
        m.insert((0x2010, 0x7638), UsbQuirk::ALWAYS_SET_CONFIG);

        // -----------------------------------------------------------------------------
        // Headset (VID: 0x1395, PID: 0x002e)
        // -----------------------------------------------------------------------------
        // Symptom: The headset has a critical bug when handling redundant configuration
        //          requests.
        // Cause:   Upon insertion, the Host OS automatically selects the active configuration.
        //          When the Guest boots and attempts to issue a `set_config(1)` request
        //          for the exact same configuration, the headset firmware crashes, communication
        //          pipes stall, or audio functionality breaks completely.
        // Fix:     Apply IGNORE_SET_CONFIG. If the active configuration already matches the
        //          target, intercept and drop the real ioctl request, faking a 'Success'
        //          response to the Guest.
        m.insert((0x1395, 0x002e), UsbQuirk::IGNORE_SET_CONFIG);

        m
    })
}

pub fn get_device_quirks(vid: u16, pid: u16) -> UsbQuirk {
    quirks_table()
        .get(&(vid, pid))
        .copied()
        .unwrap_or(UsbQuirk::empty())
}
