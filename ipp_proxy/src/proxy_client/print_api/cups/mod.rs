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

use std::{collections::HashMap, process::Command};

use anyhow::Result;
use core::time::Duration;
use log::{error, trace};
use std::thread;
use vmm_sys_util::eventfd::EventFd;

use crate::proxy_client::{
    ipp_printer::{ipp_create_default_printer_attrs, PageSizesIds, PrinterAttrs},
    ipp_processing::ipp_make_uuid,
    print_api::{PrintOps, PrinterId},
};

pub struct CupsPrintApi {}

// CUPS printers refresh interval
const PRINTER_REFRESH_INTERVAL_SECS: u64 = 30;

impl PrintOps for CupsPrintApi {
    fn init_printers() -> Result<()> {
        Ok(())
    }

    fn create_printers_list(printer_uuid_num: &mut HashMap<String, u32>) -> Result<Vec<PrinterId>> {
        trace!("Creating printers list");

        let command = Command::new("lpstat")
            .arg("-a")
            .output()
            .unwrap_or_else(|e| {
                error!("Error at lpstat -a: {e}");
                std::process::exit(1);
            });

        let mut printers_list: Vec<PrinterId> = Vec::new();
        let output = String::from_utf8(command.stdout)?;

        for line in output.lines() {
            if let Some(name) = line.split_whitespace().next() {
                let converted_printer_id = ipp_make_uuid(name);
                let printer_num = if printer_uuid_num.contains_key(&converted_printer_id) {
                    printer_uuid_num
                        .get(&converted_printer_id)
                        .copied()
                        .unwrap()
                } else {
                    let printer_num = printer_uuid_num.len() as u32;
                    printer_uuid_num.insert(converted_printer_id.clone(), printer_num);
                    printer_num
                };

                printers_list.push(PrinterId::new(
                    printer_num,
                    &converted_printer_id,
                    name,
                    &format!("CUPS {name}"),
                ));
            }
        }

        trace!("Printers list created");

        Ok(printers_list)
    }

    fn subscribe_printers_changes(update_evt: EventFd) -> Result<()> {
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(PRINTER_REFRESH_INTERVAL_SECS));
            let _ = update_evt.write(1);
        });
        Ok(())
    }

    fn fill_printer_attributes(
        sys_id: &PrinterId,
        _pagesize_ids: &mut PageSizesIds,
    ) -> Result<PrinterAttrs> {
        Ok(ipp_create_default_printer_attrs(sys_id))
    }
}
