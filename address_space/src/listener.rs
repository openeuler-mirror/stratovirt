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

use anyhow::Result;

use crate::{FlatRange, RegionIoEventFd};

/// Request type of listener.
#[derive(Debug, Copy, Clone)]
pub enum ListenerReqType {
    /// Add a region.
    AddRegion,
    /// Delete a region.
    DeleteRegion,
    /// Add a io event file descriptor.
    AddIoeventfd,
    /// Delete a io event file descriptor.
    DeleteIoeventfd,
}

pub trait Listener: Send + Sync {
    /// Get priority.
    fn priority(&self) -> i32;

    /// Is this listener enabled to call.
    fn enabled(&self) -> bool;

    /// Enable listener for address space.
    fn enable(&mut self);

    /// Disable listener for address space.
    fn disable(&mut self);

    /// Function that handle request according to request-type.
    ///
    /// # Arguments
    ///
    /// * `_range` - FlatRange would be used to find the region.
    /// * `_evtfd` - RegionIoEventFd of Region.
    /// * `_type` - Request type.
    fn handle_request(
        &self,
        _range: Option<&FlatRange>,
        _evtfd: Option<&RegionIoEventFd>,
        _type: ListenerReqType,
    ) -> Result<()> {
        Ok(())
    }
}

/// Records information that manage the slot resource and current usage.
#[derive(Default, Copy, Clone)]
pub struct MemSlot {
    /// Index of a memory slot.
    pub index: u32,
    /// Guest address.
    pub guest_addr: u64,
    /// Size of memory.
    /// size = 0 represents no-region use this slot.
    pub size: u64,
    /// Host address.
    pub host_addr: u64,
}
