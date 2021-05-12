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

use quote::{format_ident, quote};

use crate::field_parser::parse_fields;

/// Parse `DeviceState` structure to `DeviceStateDesc`.
pub fn parse_struct(input: &syn::DataStruct, ident: &syn::Ident) -> proc_macro2::TokenStream {
    let struct_ident = format_ident!("DeviceStateDesc");
    let name = format!("{}", ident);

    let fields = parse_fields(&input.fields, ident);

    quote! {
        #struct_ident {
            name: #name.to_string(),
            alias: MigrationManager::desc_db_len(),
            size: std::mem::size_of::<#ident>() as u32,
            current_version: 0_u32,
            compat_version: 0_u32,
            fields: vec![#(#fields), *],
        }
    }
}
