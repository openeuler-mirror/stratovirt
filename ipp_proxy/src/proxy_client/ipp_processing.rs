// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::{HashMap, HashSet};

use log::warn;
use uuid::Uuid;

use crate::proxy_client::{
    ipp_printer::Printer,
    print_api::{PrintApi, PrintOps, PrinterId},
    VMGT_UUID_PREFIX,
};

pub fn ipp_make_uuid(printer_id: &str) -> String {
    let uuid_in = Uuid::new_v5(&Uuid::NAMESPACE_URL, printer_id.as_bytes());
    let mut uuid_bin = uuid_in.into_bytes();
    let vmgt_magic = VMGT_UUID_PREFIX.as_bytes();
    uuid_bin[0..8].copy_from_slice(vmgt_magic);
    Uuid::from_bytes(uuid_bin).to_string()
}

pub struct IppProcessing {
    printer_uuid_num: HashMap<String, u32>,
    printers_list: HashMap<u32, Printer>,
}

impl Default for IppProcessing {
    fn default() -> Self {
        Self {
            printer_uuid_num: HashMap::new(),
            printers_list: HashMap::new(),
        }
    }
}

impl IppProcessing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn refresh_printers(&mut self) -> bool {
        let mut added_printers: HashSet<u32> = HashSet::new();
        let mut removed_printers: HashSet<u32> = HashSet::new();

        let sysid_list = match PrintApi::create_printers_list(&mut self.printer_uuid_num) {
            Ok(list) => list,
            Err(e) => {
                warn!("Failed to create printers list: {:?}", e);
                Vec::new()
            }
        };
        // Create hash-map of printers, based on id
        let mut id_map: HashMap<u32, PrinterId> = HashMap::new();
        for printer in &sysid_list {
            id_map.insert(printer.printer_num, printer.clone());
        }

        // List of new printers
        for sysid in &sysid_list {
            if self.printers_list.get(&sysid.printer_num).is_none() {
                added_printers.insert(sysid.printer_num);
            }
        }
        // List of removed printers
        for (printer_id, _) in self.printers_list.iter() {
            if id_map.get(printer_id).is_none() {
                removed_printers.insert(printer_id.clone());
            }
        }

        let changed = !added_printers.is_empty() || !removed_printers.is_empty();

        for printer_id in added_printers {
            let sysid = id_map.get(&printer_id).unwrap(); // guaranteed to be valid
            self.printers_list.insert(printer_id, Printer::new(sysid));
        }

        for printer_id in removed_printers {
            self.printers_list.remove(&printer_id);
        }

        changed
    }

    pub fn get_printers_list(&self) -> Vec<PrinterId> {
        let mut list: Vec<PrinterId> = Vec::new();
        for (_, ipp_printer) in self.printers_list.iter() {
            list.push(ipp_printer.get_sys_id());
        }
        list
    }
}
