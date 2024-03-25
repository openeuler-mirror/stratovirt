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

const TRACE_DIR_NAME: &str = "trace_info";

#[derive(Debug, Deserialize)]
struct TraceDesc {
    name: String,
    args: String,
    message: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct TraceConf {
    events: Option<Vec<TraceDesc>>,
    scopes: Option<Vec<TraceDesc>>,
}

fn get_trace_desc() -> TraceConf {
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
pub fn add_trace_state_to(input: TokenStream) -> TokenStream {
    let trace_conf = get_trace_desc();
    let mut state_name = Vec::new();
    for desc in trace_conf.events.unwrap_or_default() {
        if desc.enabled {
            state_name.push(desc.name.trim().to_string());
        }
    }
    for desc in trace_conf.scopes.unwrap_or_default() {
        if desc.enabled {
            state_name.push(desc.name.trim().to_string());
        }
    }

    let set = parse_macro_input!(input as Ident);
    let init_code = state_name.iter().map(|name| {
        let get_func = parse_str::<Ident>(format!("get_{}_state", name).as_str()).unwrap();
        let set_func = parse_str::<Ident>(format!("set_{}_state", name).as_str()).unwrap();
        quote!(
            #set.add_trace_state(TraceState::new(#name.to_string(), #get_func, #set_func));
        )
    });
    TokenStream::from(quote! { #( #init_code )* })
}

#[proc_macro]
pub fn gen_trace_state(_input: TokenStream) -> TokenStream {
    let trace_conf = get_trace_desc();
    let mut state_name = Vec::new();
    for desc in trace_conf.events.unwrap_or_default() {
        if desc.enabled {
            state_name.push(desc.name.trim().to_string());
        }
    }
    for desc in trace_conf.scopes.unwrap_or_default() {
        if desc.enabled {
            state_name.push(desc.name.trim().to_string());
        }
    }

    let trace_state = state_name.iter().map(|name| {
        let state_name =
            parse_str::<Ident>(format!("{}_state", name).to_uppercase().as_str()).unwrap();
        let get_func = parse_str::<Ident>(format!("get_{}_state", name).as_str()).unwrap();
        let set_func = parse_str::<Ident>(format!("set_{}_state", name).as_str()).unwrap();
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
pub fn gen_trace_event_func(_input: TokenStream) -> TokenStream {
    let events = match get_trace_desc().events {
        Some(events) => events,
        None => return TokenStream::from(quote!()),
    };
    let trace_func = events.iter().map(|desc| {
        let event_name = desc.name.trim();
        let func_name = parse_str::<Ident>(event_name).unwrap();

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
                let message = format!("[{{}}] {}", desc.message.trim());
                let state_name = parse_str::<Ident>(format!("{}_state", event_name).to_uppercase().as_str()).unwrap();
                quote!(
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
                            let _result = ftrace::write_trace_marker(&trace_info);
                        }
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

    TokenStream::from(quote! { #( #trace_func )* })
}

#[proc_macro]
pub fn gen_trace_scope_func(_input: TokenStream) -> TokenStream {
    let scopes = match get_trace_desc().scopes {
        Some(scopes) => scopes,
        None => return TokenStream::from(quote!()),
    };
    let trace_func =scopes.iter().map(|desc| {
        let scope_name = desc.name.trim();
        let func_name = parse_str::<Ident>(scope_name).unwrap();

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

        let func_decl = match desc.enabled {
            true => quote!(pub fn #func_name(asyn: bool, #func_args) -> trace_scope::Scope),
            false => quote!(pub fn #func_name(asyn: bool, #func_args)),
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
                let message = format!("[{{}}] {}", desc.message.trim());
                let state_name = parse_str::<Ident>(format!("{}_state", scope_name).to_uppercase().as_str()).unwrap();
                quote!(
                    #[cfg(any(feature = "trace_to_logger", feature = "trace_to_ftrace", all(target_env = "ohos", feature = "trace_to_hitrace")))]
                    // SAFETY: AtomicBool can be safely shared between threads.
                    if unsafe { #state_name.load(Ordering::SeqCst) } {
                        let trace_info = format!(#message, #scope_name.to_string() #message_args);
                        if asyn {
                            return trace_scope::Scope::Asyn(trace_scope::TraceScopeAsyn::new(trace_info))
                        }
                        return trace_scope::Scope::Common(trace_scope::TraceScope::new(trace_info))
                    }
                    return trace_scope::Scope::None
                )
            }
            false => quote!(),
        };

        quote!(
            #[cfg(any(
                feature = "trace_to_logger",
                feature = "trace_to_ftrace",
                all(target_env = "ohos", feature = "trace_to_hitrace")
            ))]
            #[inline(always)]
            #func_decl {
                #func_body
            }

            #[cfg(not(any(
                feature = "trace_to_logger",
                feature = "trace_to_ftrace", 
                all(target_env = "ohos", feature = "trace_to_hitrace")
            )))]
            #[inline(always)]
            pub fn #func_name(asyn: bool, #func_args) {
            }
        )
    });

    TokenStream::from(quote! { #( #trace_func )* })
}
