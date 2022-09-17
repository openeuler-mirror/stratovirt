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

use std::sync::{Arc, Mutex, Weak};

use anyhow::Result;

use crate::ScsiCntlr::ScsiCntlr;

pub struct ScsiBus {
    /// Bus name.
    pub name: String,
    /// Scsi Controller which the bus orignates from.
    pub parent_cntlr: Weak<Mutex<ScsiCntlr>>,
}

impl ScsiBus {
    pub fn new(bus_name: String, parent_cntlr: Weak<Mutex<ScsiCntlr>>) -> ScsiBus {
        ScsiBus {
            name: bus_name,
            parent_cntlr,
        }
    }
}

pub fn create_scsi_bus(bus_name: &str, scsi_cntlr: &Arc<Mutex<ScsiCntlr>>) -> Result<()> {
    let mut locked_scsi_cntlr = scsi_cntlr.lock().unwrap();
    let bus = ScsiBus::new(bus_name.to_string(), Arc::downgrade(scsi_cntlr));
    locked_scsi_cntlr.bus = Some(Arc::new(Mutex::new(bus)));
    Ok(())
}
