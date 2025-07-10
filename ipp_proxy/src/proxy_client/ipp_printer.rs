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

use ipp::value::IppValue;
use std::collections::HashMap;

use crate::proxy_client::print_api::{PrintApi, PrintOps, PrinterId};

pub struct Printer {
    _printer_id: String,
    sys_id: PrinterId,
    _printer_attributes: PrinterAttrs,
    _pagesize_ids: PageSizesIds,
}

pub type PageSizesIds = Vec<(String, String)>; // Vector of mappings of OhosPageId -> IppPageId
pub type PrinterAttrs = HashMap<&'static str, IppValue>;

pub fn ipp_create_default_printer_attrs(_sys_id: &PrinterId) -> PrinterAttrs {
    PrinterAttrs::new()
}

impl Printer {
    pub fn new(sys_id: &PrinterId) -> Self {
        let mut pagesize_ids = PageSizesIds::new();
        let pa = match PrintApi::fill_printer_attributes(sys_id, &mut pagesize_ids) {
            Ok(a) => a,
            _ => ipp_create_default_printer_attrs(sys_id),
        };

        Self {
            _printer_id: sys_id.printer_id.clone(),
            sys_id: sys_id.clone(),
            _printer_attributes: pa,
            _pagesize_ids: pagesize_ids,
        }
    }

    pub fn get_sys_id(&self) -> PrinterId {
        self.sys_id.clone()
    }
}
