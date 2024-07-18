// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::{fs, io::Read};

use proc_macro::TokenStream;
use quote::quote;
use regex::Regex;
use serde::Deserialize;
use syn::{parse_str, Expr, Ident, Type};

const EVENT_DIR_NAME: &str = "event_info";

#[derive(Debug, Deserialize)]
struct EventDesc {
    name: String,
    event_type: String,
    args: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct HiSysEventConf {
    events: Option<Vec<EventDesc>>,
}

fn get_event_desc() -> HiSysEventConf {
    let event_dir_path = format!(
        "{}/{}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        EVENT_DIR_NAME
    );
    let paths = fs::read_dir(event_dir_path).unwrap();
    let mut desc = String::new();

    for path in paths {
        let file_path = path.unwrap().path();
        let file_name = file_path.to_str().unwrap();
        if file_name.ends_with(".toml") {
            let mut file = fs::File::open(file_path).unwrap();
            file.read_to_string(&mut desc).unwrap();
        }
    }
    match toml::from_str::<HiSysEventConf>(&desc) {
        Ok(ret) => ret,
        Err(e) => panic!("Failed to parse event info : {}", e),
    }
}

fn is_slice(arg_type: &str) -> bool {
    let regex = Regex::new(r"\[([^\[\]]*)\]").unwrap();
    let match_texts = regex
        .captures_iter(arg_type)
        .map(|mat| mat.get(1).map_or("", |m| m.as_str()));
    match match_texts.count() {
        0 => false,
        1 => true,
        _ => panic!("The format of parameter type: {} is wrong!", arg_type),
    }
}

fn capitalize(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }

    let mut chars = s.chars().collect::<Vec<char>>();
    if chars[0].is_alphabetic() {
        chars[0] = chars[0]
            .to_uppercase()
            .collect::<String>()
            .chars()
            .next()
            .unwrap();
    }
    chars.iter().collect()
}

fn parse_param_type(arg_type: &str) -> String {
    if is_slice(arg_type) {
        let regex = Regex::new(r"\[([^\[\]]*)\]").unwrap();
        let match_texts: Vec<&str> = regex
            .captures_iter(arg_type)
            .map(|mat| mat.get(1).map_or("", |m| m.as_str()))
            .collect();
        format!("Array{}", capitalize(match_texts[0]))
    } else {
        format!("Type{}", capitalize(arg_type))
    }
}

fn generate_param_value(arg_type: &str, arg_value: &str) -> (Ident, Expr) {
    let param_type: Ident;
    let param_value: Expr;
    if is_slice(arg_type) {
        let trans_token = ".as_ptr() as *const std::ffi::c_int as *const ()";
        param_type = parse_str::<Ident>("void_ptr_value").unwrap();
        param_value = parse_str::<Expr>(format!("{}{}", arg_value, trans_token).as_str()).unwrap();
    } else if arg_type.contains("String") {
        let cstr_arg = format!("std::ffi::CString::new({}).unwrap()", arg_value);
        let trans_token = ".into_raw() as *const std::ffi::c_char";
        param_type = parse_str::<Ident>("char_ptr_value").unwrap();
        param_value = parse_str::<Expr>(format!("{}{}", cstr_arg, trans_token).as_str()).unwrap();
    } else {
        param_type = parse_str::<Ident>(format!("{}_value", arg_type).as_str()).unwrap();
        param_value = parse_str::<Expr>(format!("{} as {}", arg_value, arg_type).as_str()).unwrap();
    }
    (param_type, param_value)
}

#[proc_macro]
pub fn gen_hisysevent_func(_input: TokenStream) -> TokenStream {
    let events = match get_event_desc().events {
        Some(events) => events,
        None => return TokenStream::from(quote!()),
    };
    let hisysevent_func = events.iter().map(|desc| {
        if desc.name.trim().is_empty() {
            panic!("Empty event name is unsupported!");
        }
        let desc_name = desc.name.trim();
        let func_name = parse_str::<Ident>(desc_name).unwrap();
        let event_name = desc_name;
        let event_type =
            parse_str::<Expr>(format!("HiSysEventType::_{}", desc.event_type.trim()).as_str())
                .unwrap();

        let func_args = match desc.args.is_empty() {
            true => quote!(),
            false => {
                let split_args: Vec<&str> = desc.args.split(',').collect();
                let _args = split_args.iter().map(|arg| {
                    let (v, t) = arg.split_once(':').unwrap();
                    let arg_name = parse_str::<Ident>(v.trim()).unwrap();
                    let arg_type = parse_str::<Type>(t.trim()).unwrap();
                    quote!(
                        #arg_name: #arg_type,
                    )
                });
                quote! { #( #_args )* }
            }
        };

        let param_body = {
            let split_args: Vec<&str> = desc.args.split(',').collect();
            let _args = split_args.iter().map(|arg| {
                let (v, t) = arg.split_once(':').unwrap();
                let param_name = v.trim();
                let param_type_str: String = parse_param_type(t.trim());
                let param_type_token = format!("EventParamType::_{}", param_type_str);
                let param_type = parse_str::<Expr>(param_type_token.as_str()).unwrap();
                let (elem_type, elem_value) = generate_param_value(t.trim(), v.trim());
                let param_size = if param_type_str.contains("Array") {
                    parse_str::<Expr>(format!("{}.len()", v.trim()).as_str()).unwrap()
                } else {
                    parse_str::<Expr>("0").unwrap()
                };

                quote!(
                    EventParam {
                        param_name: #param_name,
                        param_type: #param_type,
                        param_value: EventParamValue{#elem_type: #elem_value},
                        array_size: #param_size},
                )
            });
            quote! { #( #_args )* }
        };

        let func_body = match desc.enabled {
            true => {
                quote!(
                    #[cfg(all(target_env = "ohos", feature = "hisysevent"))]
                    {
                        let func = function!();
                        let params: &[EventParam] = &[#param_body];
                        write_to_hisysevent(func, #event_name, #event_type as std::ffi::c_int, params);
                    }
                )
            }
            false => quote!(),
        };

        quote!(
            #[inline(always)]
            pub fn #func_name(#func_args) {
                #func_body
            }
        )
    });

    TokenStream::from(quote! { #( #hisysevent_func )* })
}
