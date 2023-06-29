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

use super::attr_parser::parse_field_attributes;

/// Parse fields in `DeviceState` structure to `TokenStream`.
pub fn parse_fields(input: &syn::Fields, ident: &syn::Ident) -> Vec<proc_macro2::TokenStream> {
    let mut fields = Vec::new();

    match input {
        syn::Fields::Named(ref name_fields) => {
            let pairs = name_fields.named.pairs();
            for field in pairs {
                fields.push(parse_field(field, ident));
            }
        }
        _ => panic!("Only named fields are supported!"),
    }

    fields
}

/// Parse field in `DeviceState` structure to `TokenStream`.
fn parse_field(
    input: syn::punctuated::Pair<&syn::Field, &syn::token::Comma>,
    ident: &syn::Ident,
) -> proc_macro2::TokenStream {
    let struct_ident = format_ident!("FieldDesc");

    // parse var of field
    let var_ident = input.value().ident.as_ref().unwrap();
    let var_name = var_ident.to_string();
    let alias_name =
        parse_field_attributes(&input.value().attrs).unwrap_or_else(|| var_name.clone());

    // parse type of field
    let ty = input.value().ty.clone();
    let (ty_ident, len, is_array) = parse_ty(ty);
    let type_name = if is_array {
        format!("[{};{}]", ty_ident.path.get_ident().unwrap(), len)
    } else {
        ty_ident.path.get_ident().unwrap().to_string()
    };

    quote! {
        #struct_ident {
            var_name: #var_name.to_string(),
            type_name: #type_name.to_string(),
            alias: #alias_name.to_string(),
            offset: util::offset_of!(#ident, #var_ident) as u32,
            size: (std::mem::size_of::<#ty_ident>() * #len) as u32,
        }
    }
}

// Parse syn::Type to TypePath and length of array.
// Type parser only support path_type and array[path_type] now.
//
// # Output
//
// (path_type, length of array(if not an array, len will be 1), is_array)
fn parse_ty(input: syn::Type) -> (syn::TypePath, usize, bool) {
    match input {
        syn::Type::Array(array) => {
            let array_type_token = match *array.elem.clone() {
                syn::Type::Path(token) => token,
                _ => panic!("Unsupported array type."),
            };

            match &array.len {
                syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
                    syn::Lit::Int(lit_int) => {
                        let array_len: usize = lit_int.base10_parse().unwrap();
                        (array_type_token, array_len, true)
                    }
                    _ => panic!("Unsupported array len literal."),
                },
                _ => panic!("Unsupported array len."),
            }
        }
        syn::Type::Path(token) => (token, 1, false),
        _ => panic!("Unsupported field type {:?}", input),
    }
}

/// Parse fields default with a vector.
/// Every element is a expression with: `Var: type::default()`.
pub fn parse_fields_default(input: &syn::Fields) -> Vec<proc_macro2::TokenStream> {
    let mut fields = Vec::new();

    match input {
        syn::Fields::Named(ref name_fields) => {
            let pairs = name_fields.named.pairs();
            for field in pairs {
                fields.push(parse_field_default(field));
            }
        }
        _ => panic!("Only named fields are supported!"),
    }

    fields
}

fn parse_field_default(
    input: syn::punctuated::Pair<&syn::Field, &syn::token::Comma>,
) -> proc_macro2::TokenStream {
    // parse var of field
    let var_ident = input.value().ident.as_ref().unwrap();

    // parse type of field
    let ty = input.value().ty.clone();
    let (ty_ident, len, is_array) = parse_ty(ty);

    if is_array {
        quote! {
            #var_ident: [#ty_ident::default(); #len]
        }
    } else {
        quote! {
            #var_ident: #ty_ident::default()
        }
    }
}
