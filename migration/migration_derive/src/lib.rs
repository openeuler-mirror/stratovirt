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
//! Exports two derives for migration flow:
//! The `Desc` derive pro macro to generate the DeviceStateDesc structure for
//! DeviceState struct.It also offers two attributes: one to describe version
//! and compat version for structure, the other to give struct field an `alias`
//! name.
//!
//! ```no_run
//! #[macro_use]
//! extern crate migration_derive;
//! extern crate migration;
//! extern crate util;
//!
//! use migration::{DeviceStateDesc, FieldDesc, MigrationManager};
//!
//! #[derive(Desc)]
//! #[desc_version(compat_version = "0.1.0")]
//! struct DeviceState {
//!     #[alias(activated)]
//!     device_activated: bool,
//!     #[alias(select)]
//!     features_select: u32,
//!     #[alias(acked_select)]
//!     acked_features_select: u32,
//!     #[alias(status)]
//!     device_status: u32,
//! }
//!
//! fn main() {
//!     println!(
//!         "Description of DeviceState is {:?}",
//!         DeviceState::descriptor()
//!     );
//! }
//! ```
//!
//! 2. The `ByteCode` derive to auto add `ByteCode` trait and its relying trait for
//! struct, such as `Default`, `Sync`, `Send`.

mod attr_parser;
mod field_parser;
mod struct_parser;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Define a macro derive `Desc`.
#[proc_macro_derive(Desc, attributes(desc_version, alias))]
pub fn derive_desc(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();

    // Get attr info
    let (mut current_version, mut compat_version) =
        attr_parser::parse_struct_attributes(&input.attrs);
    attr_parser::validate_version(&mut current_version, &mut compat_version);

    let desc = match &input.data {
        syn::Data::Struct(data_struct) => {
            struct_parser::parse_struct(data_struct, &ident, current_version, compat_version)
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

#[proc_macro_derive(ByteCode)]
pub fn derive_bytecode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();

    let struct_default = match &input.data {
        syn::Data::Struct(data_struct) => struct_parser::parse_struct_default(data_struct, &ident),
        _ => panic!("Only support struct."),
    };

    (quote! {
        impl Default for #ident {
            fn default() -> #ident {
                #struct_default
            }
        }
        impl util::byte_code::ByteCode for #ident {}
    })
    .into()
}
