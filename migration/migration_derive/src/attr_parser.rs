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

use syn::Lit;

// Read the program version in `Cargo.toml`.
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// Attribute in this derive should be used as:
/// for example: `#[desc_version(current_version=1, compat_version=1)]`
/// or `#[desc_version(current_version="0.1.0", compat_version="0.0.1")]`
/// This attribute need to be put above `struct` declaration.
const ATTRIBUTE_NAME: &str = "desc_version";
const CURRENT_VERSION: &str = "current_version";
const COMPAT_VERSION: &str = "compat_version";

/// Attribute `alias` is used above `field` declaration.
/// It can set a field name with a alias. If alias is not set, the default
/// value of alias will be set by field name. The alias is the unique
/// identification of field in a structure.
const FIELD_ATTRIBUTE_NAME: &str = "alias";

/// Parse attribute above a struct.
/// Version attribute with `current_version` or `compat_version` will be parsed to
/// two `u32` number.
///
/// # Output
///
/// (current_version, compat_version)
pub fn parse_struct_attributes(attributes: &[syn::Attribute]) -> (u32, u32) {
    let (mut current_version, mut compat_version) = (0, 0);
    for attribute in attributes {
        if attribute.path().is_ident(ATTRIBUTE_NAME) {
            let _ = attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident(CURRENT_VERSION) {
                    let value = meta.value()?;
                    let lit = value.parse::<Lit>()?;
                    current_version = match lit {
                        syn::Lit::Int(lit_int) => lit_int.base10_parse().unwrap(),
                        syn::Lit::Str(lit_str) => version_to_u32(&lit_str.value()),
                        _ => panic!("Unsupported version number."),
                    };

                    return Ok(());
                }

                if meta.path.is_ident(COMPAT_VERSION) {
                    let value = meta.value()?;
                    let lit = value.parse::<Lit>()?;
                    compat_version = match lit {
                        syn::Lit::Int(lit_int) => lit_int.base10_parse().unwrap(),
                        syn::Lit::Str(lit_str) => version_to_u32(&lit_str.value()),
                        _ => panic!("Unsupported version number."),
                    };

                    return Ok(());
                }

                Err(meta.error("unrecognized repr"))
            });
        }
    }

    (current_version, compat_version)
}

/// Parse attribute above fields.
/// Alias attribute with `alias` will be parse to a alias string.
pub fn parse_field_attributes(attributes: &[syn::Attribute]) -> Option<String> {
    let mut field_alias = None;

    for attribute in attributes {
        if attribute.path().is_ident(FIELD_ATTRIBUTE_NAME) {
            let content: proc_macro2::TokenStream = attribute.parse_args().unwrap();
            field_alias = Some(content.to_string());
        }
    }

    field_alias
}

/// Check current version and compat version.
///
/// # Check rules
///
/// 1. If version in `Cargo.toml` exists, current_version should equal to it.
/// 2. Compat_version can't greater than current_version.
/// 3. If current_version not set, it will be equal to compat_version.
/// 4. Compat_version should be given with attribute.
pub fn validate_version(current_version: &mut u32, compat_version: &mut u32) {
    if *compat_version == 0 {
        panic!("compat_version should be given.");
    }

    if let Some(version_str) = VERSION {
        let version = version_to_u32(version_str);
        if *current_version == 0 {
            *current_version = version;
        }
    } else if *current_version == 0 {
        *current_version = *compat_version;
    }

    if *current_version < *compat_version {
        panic!("version check error, compat version can't greater than current_version.")
    }
}

// Version in `Cargo.toml` will be shown as "x.x.x".
// This function will separate it to three bytes, and padding to [u8;4] after
// three as u32.
// Version in `attribute` can also be shown as this format.
fn version_to_u32(version_str: &str) -> u32 {
    let version_vec: Vec<u8> = version_str
        .split('.')
        .map(|x| x.parse::<u8>().unwrap())
        .collect();

    if version_vec.len() != 3 {
        panic!("Version str is illegal.");
    }

    (version_vec[2] as u32) + ((version_vec[1] as u32) << 8) + ((version_vec[0] as u32) << 16)
}

#[cfg(test)]
mod test {
    use syn::{parse_quote, ItemStruct};

    use super::*;

    #[test]
    fn test_version_to_u32() {
        let version_str_01 = "0.1.0";
        assert_eq!(version_to_u32(version_str_01), 256);

        let version_str_02 = "1.18.0";
        assert_eq!(version_to_u32(version_str_02), 70_144);

        let version_str_03 = "255.255.255";
        assert_eq!(version_to_u32(version_str_03), 16_777_215);
    }

    #[test]
    fn test_parse_attribute() {
        let input: ItemStruct = parse_quote! {
            #[desc_version(current_version = 1, compat_version = "0.1.0")]
            pub struct MyStruct(u16, u32);
        };

        let (current_version, compat_version) = parse_struct_attributes(input.attrs.as_slice());

        assert_eq!(current_version, 1);
        assert_eq!(compat_version, 256);
    }
}
