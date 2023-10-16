// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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
use serde::Deserialize;
use syn::{parse_macro_input, parse_str, Ident, Type};

const TRACE_DIR_NAME: &str = "trace_event";

#[derive(Debug, Deserialize)]
struct TraceEventDesc {
    name: String,
    args: String,
    message: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct TraceConf {
    events: Vec<TraceEventDesc>,
}

fn get_trace_event_desc() -> TraceConf {
    let trace_dir_path = format!(
        "{}/{}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        TRACE_DIR_NAME
    );
    let paths = fs::read_dir(trace_dir_path).unwrap();
    let mut desc = String::new();

    for path in paths {
        let file_path = path.unwrap().path();
        let file_name = file_path.to_str().unwrap();
        if file_name.ends_with(".toml") {
            let mut file = fs::File::open(file_path).unwrap();
            file.read_to_string(&mut desc).unwrap();
        }
    }
    toml::from_str::<TraceConf>(&desc).unwrap()
}

#[proc_macro]
pub fn add_trace_event_to(input: TokenStream) -> TokenStream {
    let set = parse_macro_input!(input as Ident);
    let events = get_trace_event_desc().events;
    let init_code = events.iter().map(|desc| match &desc.enabled {
        true => {
            let event_name = desc.name.trim();
            let get_func = parse_str::<Ident>(format!("get_{}_state", event_name).as_str()).unwrap();
            let set_func = parse_str::<Ident>(format!("set_{}_state", event_name).as_str()).unwrap();
            quote!(
                #set.add_trace_event(TraceEvent::new(#event_name.to_string(), #get_func, #set_func));
            )
        }
        false => quote!(),
    });
    TokenStream::from(quote! { #( #init_code )* })
}

#[proc_macro]
pub fn gen_trace_state(_input: TokenStream) -> TokenStream {
    let events = get_trace_event_desc().events;
    let trace_state = events.iter().map(|desc| {
        let event_name = parse_str::<Ident>(desc.name.trim()).unwrap();
        let state_name =
            parse_str::<Ident>(format!("{}_state", event_name).to_uppercase().as_str()).unwrap();
        let get_func = parse_str::<Ident>(format!("get_{}_state", event_name).as_str()).unwrap();
        let set_func = parse_str::<Ident>(format!("set_{}_state", event_name).as_str()).unwrap();
        quote!(
            static mut #state_name: AtomicBool = AtomicBool::new(false);
            fn #get_func() -> bool {
                // SAFETY: AtomicBool can be safely shared between threads.
                unsafe { #state_name.load(Ordering::SeqCst) }
            }
            fn #set_func(val: bool) {
                // SAFETY: AtomicBool can be safely shared between threads.
                unsafe { #state_name.store(val, Ordering::SeqCst) }
            }
        )
    });

    TokenStream::from(quote! { #( #trace_state )* })
}

#[proc_macro]
pub fn gen_trace_func(_input: TokenStream) -> TokenStream {
    let events = get_trace_event_desc().events;
    let trace_func = events.iter().map(|desc| {
        let func_name = parse_str::<Ident>(desc.name.trim()).unwrap();

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

        let message_args = match desc.args.is_empty() {
            true => quote!(),
            false => {
                let split_args: Vec<&str> = desc.args.split(',').collect();
                let _args = split_args.iter().map(|arg| {
                    let (v, _) = arg.split_once(':').unwrap();
                    let arg_name = parse_str::<Ident>(v.trim()).unwrap();
                    quote!(
                        , #arg_name
                    )
                });
                quote! { #( #_args )* }
            }
        };

        let func_body = match desc.enabled {
            true => {
                let mut _body = quote!();
                let message = format!("[{{}}] {}", desc.message.trim());
                let event_name = desc.name.trim();
                let state_name = parse_str::<Ident>(format!("{}_state", event_name).to_uppercase().as_str()).unwrap();
                _body = quote!(
                    #_body
                    #[cfg(any(feature = "trace_to_logger", feature = "trace_to_ftrace"))]
                    // SAFETY: AtomicBool can be safely shared between threads.
                    if unsafe { #state_name.load(Ordering::SeqCst) } {
                        #[cfg(feature = "trace_to_logger")]
                        {
                            log::trace!(#message, #event_name.to_string() #message_args);
                        }
                        #[cfg(feature = "trace_to_ftrace")]
                        {
                            let trace_info = format!(#message, #event_name.to_string() #message_args);
                            let _result = TRACE_MARKER_FD.lock().unwrap().write_all(trace_info.as_bytes());
                        }
                    }
                );
                _body
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

    TokenStream::from(quote! { #( #trace_func )* })
}
