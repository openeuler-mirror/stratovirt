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

//! # migration_derive
//!
//! Exports a derive for migration flow:
//! The `Desc` derive pro macro to generate the DeviceStateDesc structure for
//! DeviceState struct.

#[macro_use]
extern crate syn;
extern crate quote;

use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

mod attr_parser;
mod field_parser;
mod struct_parser;

use attr_parser::{parse_struct_attributes, validate_version};
use struct_parser::parse_struct;

/// Define a macro derive `Desc`.
#[proc_macro_derive(Desc, attributes(desc_version, alias))]
pub fn derive_desc(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();

    // Get attr info
    let (mut current_version, mut compat_version) = parse_struct_attributes(&input.attrs);
    validate_version(&mut current_version, &mut compat_version);

    let desc = match &input.data {
        syn::Data::Struct(data_struct) => {
            parse_struct(data_struct, &ident, current_version, compat_version)
        }
        _ => panic!("Only support struct."),
    };

    (quote! {
        impl #ident {
            pub fn descriptor() -> DeviceStateDesc {
                #desc
            }
        }
    })
    .into()
}
