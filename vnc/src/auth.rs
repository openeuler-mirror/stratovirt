// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use crate::{
    client::{vnc_flush, vnc_write, ClientIoHandler, APP_NAME},
    VncError,
};
use anyhow::{anyhow, Result};
use libc::{c_char, c_int, c_uint, c_void};
use log::{error, info};
use sasl2_sys::prelude::{
    sasl_conn_t, sasl_dispose, sasl_getprop, sasl_listmech, sasl_security_properties_t,
    sasl_server_init, sasl_server_new, sasl_server_start, sasl_server_step, sasl_setprop,
    sasl_ssf_t, SASL_CONTINUE, SASL_OK, SASL_SEC_PROPS, SASL_SSF, SASL_SSF_EXTERNAL,
    SASL_SUCCESS_DATA,
};
use sasl2_sys::sasl::SASL_USERNAME;
use std::ffi::{CStr, CString};
use std::ptr;
use util::byte_code::ByteCode;

/// Vnc Service.
const SERVICE: &str = "vnc";
const MECHNAME_MAX_LEN: u32 = 100;
const MECHNAME_MIN_LEN: u32 = 1;
const SASL_DATA_MAX_LEN: u32 = 1024 * 1024;
/// Minimum supported encryption length of ssf layer in sasl.
const MIN_SSF_LENGTH: usize = 56;

/// Authentication type
#[derive(Clone, Copy)]
pub enum AuthState {
    Invalid = 0,
    No = 1,
    Vnc = 2,
    Vencrypt = 19,
    Sasl = 20,
}

/// Authentication and encryption method.
#[derive(Clone, Copy)]
pub enum SubAuthState {
    /// Send plain Message + no auth.
    VncAuthVencryptPlain = 256,
    /// Tls vencry with anon + no auth.
    VncAuthVencryptTlNone = 257,
    /// Tls vencrypt with x509 + no auth.
    VncAuthVencryptX509None = 260,
    /// Tls vencrypt with x509 + sasl.
    VncAuthVencryptX509Sasl = 263,
    /// Tls vencrypt + sasl.
    VncAuthVencryptTlssasl = 264,
}

/// Configuration for authentication.
/// Identity: authentication user.
#[derive(Debug, Clone)]
pub struct SaslAuth {
    pub identity: String,
}

impl SaslAuth {
    pub fn new(identity: String) -> Self {
        SaslAuth { identity }
    }
}

/// Struct of sasl authentiation.
#[derive(Debug, Clone)]
pub struct SaslConfig {
    /// State of sasl connection .
    pub sasl_conn: *mut sasl_conn_t,
    /// Mech list server support.
    pub mech_list: String,
    /// Authentication mechanism currently in use.
    pub mech_name: String,
    /// State of auth.
    pub sasl_stage: SaslStage,
    /// Security layer in sasl.
    pub want_ssf: bool,
    /// Strength of ssf.
    pub run_ssf: u32,
}

impl Default for SaslConfig {
    fn default() -> Self {
        SaslConfig {
            sasl_conn: ptr::null_mut() as *mut sasl_conn_t,
            mech_list: String::new(),
            mech_name: String::new(),
            sasl_stage: SaslStage::SaslServerStart,
            want_ssf: false,
            run_ssf: 0,
        }
    }
}

/// Authentication stage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SaslStage {
    SaslServerStart,
    SaslServerStep,
}

impl ClientIoHandler {
    /// Get length of mechname send form client.
    pub fn get_mechname_length(&mut self) -> Result<()> {
        let buf = self.read_incoming_msg();
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if !(MECHNAME_MIN_LEN..MECHNAME_MAX_LEN).contains(&len) {
            return Err(anyhow!(VncError::AuthFailed(String::from(
                "SASL mechname too short or too long"
            ))));
        }

        self.update_event_handler(len as usize, ClientIoHandler::get_sasl_mechname);
        Ok(())
    }

    /// Start sasl authentication.
    /// 1. Sals server init.
    /// 2. Get the mechlist support by Sasl server.
    /// 3. Send the mechlist to client.
    pub fn start_sasl_auth(&mut self) -> Result<()> {
        self.sasl_server_init()?;

        self.set_ssf_for_sasl()?;

        self.send_mech_list()?;

        Ok(())
    }

    /// Get authentication mechanism supported by client.
    pub fn get_sasl_mechname(&mut self) -> Result<()> {
        let buf = self.read_incoming_msg();
        let mech_name = String::from_utf8_lossy(&buf).to_string();

        let mut security = self.server.security_type.borrow_mut();
        let mech_list: Vec<&str> = security.saslconfig.mech_list.split(',').collect();
        for mech in mech_list {
            if mech_name == *mech {
                security.saslconfig.mech_name = mech_name;
                break;
            }
        }
        // Unsupported mechanism.
        if security.saslconfig.mech_name.is_empty() {
            return Err(anyhow!(VncError::AuthFailed(
                "Unsupported mechanism".to_string()
            )));
        }
        drop(security);

        self.update_event_handler(4, ClientIoHandler::get_authmessage_length);
        Ok(())
    }

    /// Length of client authentication message.
    pub fn get_authmessage_length(&mut self) -> Result<()> {
        let buf = self.read_incoming_msg();
        let buf = [buf[0], buf[1], buf[2], buf[3]];
        let len = u32::from_be_bytes(buf);

        if len > SASL_DATA_MAX_LEN {
            error!("SASL start len too large");
            return Err(anyhow!(VncError::AuthFailed(
                "SASL start len too large".to_string()
            )));
        }

        if len == 0 {
            return self.client_sasl_auth();
        }
        self.update_event_handler(len as usize, ClientIoHandler::client_sasl_auth);
        Ok(())
    }

    /// Receive the authentication information from client and return the result.
    pub fn client_sasl_auth(&mut self) -> Result<()> {
        info!("Sasl Authentication");
        let buf = self.read_incoming_msg();

        let mut client_data = buf.to_vec();
        let mut client_len: c_uint = 0;
        if self.expect > 0 {
            client_len = (self.expect - 1) as c_uint;
            client_data[self.expect - 1] = 0_u8;
        }

        let server = self.server.clone();
        let client = self.client.clone();
        let mut security = server.security_type.borrow_mut();
        let mut serverout: *const c_char = ptr::null_mut();
        let mut serverout_len: c_uint = 0;
        let mech_name = CString::new(security.saslconfig.mech_name.as_str())?;

        // Start authentication.
        let err: c_int = match security.saslconfig.sasl_stage {
            // SAFETY: sasl_server_start() and sasl_server_step() is C function. All parameters passed of the
            // function have been checked. Memory will be allocated for the incoming pointer inside the function.
            SaslStage::SaslServerStart => unsafe {
                sasl_server_start(
                    security.saslconfig.sasl_conn,
                    mech_name.as_ptr(),
                    client_data.as_ptr() as *const c_char,
                    client_len,
                    &mut serverout,
                    &mut serverout_len,
                )
            },
            SaslStage::SaslServerStep => unsafe {
                sasl_server_step(
                    security.saslconfig.sasl_conn,
                    client_data.as_ptr() as *const c_char,
                    client_len,
                    &mut serverout,
                    &mut serverout_len,
                )
            },
        };

        if err != SASL_OK && err != SASL_CONTINUE {
            // SAFETY: sasl_dispose() is C function. All parameters passed of the
            // function have been checked.
            unsafe { sasl_dispose(&mut security.saslconfig.sasl_conn) }
            error!("Auth failed!");
            return Err(anyhow!(VncError::AuthFailed("Auth failed!".to_string())));
        }
        if serverout_len > SASL_DATA_MAX_LEN {
            unsafe { sasl_dispose(&mut security.saslconfig.sasl_conn) }
            error!("SASL data too long");
            return Err(anyhow!(VncError::AuthFailed(
                "SASL data too long".to_string()
            )));
        }

        let mut buf = Vec::new();
        if serverout_len > 0 {
            // Authentication related information.
            let serverout = unsafe { CStr::from_ptr(serverout as *const c_char) };
            let auth_message = String::from(serverout.to_str().unwrap_or(""));
            buf.append(&mut (serverout_len + 1).to_be_bytes().to_vec());
            buf.append(&mut auth_message.as_bytes().to_vec());
        } else {
            buf.append(&mut (0_u32).to_be_bytes().to_vec());
        }

        if err == SASL_OK {
            buf.append(&mut (1_u8).as_bytes().to_vec());
        } else if err == SASL_CONTINUE {
            buf.append(&mut (0_u8).as_bytes().to_vec());
        }
        drop(security);

        if err == SASL_CONTINUE {
            // Authentication continue.
            let mut security = server.security_type.borrow_mut();
            security.saslconfig.sasl_stage = SaslStage::SaslServerStep;
            self.update_event_handler(4, ClientIoHandler::get_authmessage_length);
            drop(security);
            return Ok(());
        } else {
            if let Err(err) = self.sasl_check_ssf() {
                // Reject auth: the strength of ssf is too weak.
                auth_reject(&mut buf);
                vnc_write(&client, buf);
                vnc_flush(&client);
                return Err(err);
            }

            if let Err(err) = self.sasl_check_authz() {
                // Reject auth: wrong sasl username.
                auth_reject(&mut buf);
                vnc_write(&client, buf);
                vnc_flush(&client);
                return Err(err);
            }
            // Accpet auth.
            buf.append(&mut (0_u32).as_bytes().to_vec());
        }

        vnc_write(&client, buf);
        vnc_flush(&client);
        self.update_event_handler(1, ClientIoHandler::handle_client_init);
        Ok(())
    }

    /// Sasl server init.
    fn sasl_server_init(&mut self) -> Result<()> {
        let mut err: c_int;
        let service = CString::new(SERVICE)?;
        let appname = CString::new(APP_NAME)?;
        let local_addr = self.stream.local_addr()?.to_string().replace(':', ";");
        let remote_addr = self.stream.peer_addr()?.to_string().replace(':', ";");
        info!("local_addr: {} remote_addr: {}", local_addr, remote_addr);
        let local_addr = CString::new(local_addr)?;
        let remote_addr = CString::new(remote_addr)?;
        // SAFETY: sasl_server_init() and sasl_server_new() is C function. All parameters passed of the
        // function have been checked. Memory will be allocated for the incoming pointer inside the function.
        // Sasl server init.
        unsafe {
            err = sasl_server_init(ptr::null_mut(), appname.as_ptr());
        }
        if err != SASL_OK {
            error!("SASL_FAIL error code {}", err);
            return Err(anyhow!(VncError::AuthFailed(format!(
                "SASL_FAIL error code {}",
                err
            ))));
        }
        let mut saslconfig = SaslConfig::default();
        unsafe {
            err = sasl_server_new(
                service.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                local_addr.as_ptr(),
                remote_addr.as_ptr(),
                ptr::null_mut(),
                SASL_SUCCESS_DATA,
                &mut saslconfig.sasl_conn,
            );
        }
        if err != SASL_OK {
            error!("SASL_FAIL error code {}", err);
            return Err(anyhow!(VncError::AuthFailed(format!(
                "SASL_FAIL error code {}",
                err
            ))));
        }
        self.server.security_type.borrow_mut().saslconfig = saslconfig;

        Ok(())
    }

    /// Set properties for sasl.
    fn set_ssf_for_sasl(&mut self) -> Result<()> {
        // Set the relevant properties of sasl.
        let mut err: c_int;
        let ssf: sasl_ssf_t = 256;
        let ssf = &ssf as *const sasl_ssf_t;
        let security = self.server.security_type.borrow_mut();
        // SAFETY: sasl_setprop() and sasl_server_new() is C function. It can be ensure
        // that security.saslconfig.sasl_conn is not null.
        unsafe {
            err = sasl_setprop(
                security.saslconfig.sasl_conn,
                SASL_SSF_EXTERNAL as i32,
                ssf as *const c_void,
            );
        }
        if err != SASL_OK {
            error!("SASL_FAIL error code {}", err);
            return Err(anyhow!(VncError::AuthFailed(format!(
                "SASL_FAIL error code {}",
                err
            ))));
        }

        // Already using tls, disable ssf in sasl.
        let props_name = ptr::null_mut() as *mut *const c_char;
        let props_value = ptr::null_mut() as *mut *const c_char;
        let saslprops = sasl_security_properties_t {
            min_ssf: 0,
            max_ssf: 0,
            maxbufsize: 8192,
            security_flags: 0,
            property_names: props_name,
            property_values: props_value,
        };

        let props = &saslprops as *const sasl_security_properties_t;
        // SAFETY: sasl_setprop() and sasl_server_new() is C function. It can be ensure
        // that security.saslconfig.sasl_conn is not null.
        unsafe {
            err = sasl_setprop(
                security.saslconfig.sasl_conn,
                SASL_SEC_PROPS.try_into()?,
                props as *const c_void,
            );
        }
        if err != SASL_OK {
            error!("SASL_FAIL error code {}", err);
            return Err(anyhow!(VncError::AuthFailed(format!(
                "SASL_FAIL error code {}",
                err
            ))));
        }

        Ok(())
    }

    /// Get the mechlist support by Sasl server.
    /// Send the mechlist to client.
    fn send_mech_list(&mut self) -> Result<()> {
        let err: c_int;
        let prefix = CString::new("")?;
        let sep = CString::new(",")?;
        let suffix = CString::new("")?;
        let mut mechlist: *const c_char = ptr::null_mut();
        let mut security = self.server.security_type.borrow_mut();
        let client = self.client.clone();
        // SAFETY: sasl_listmech() is C function. It can be ensure
        // that security.saslconfig.sasl_conn is not null.
        unsafe {
            err = sasl_listmech(
                security.saslconfig.sasl_conn,
                ptr::null_mut(),
                prefix.as_ptr(),
                sep.as_ptr(),
                suffix.as_ptr(),
                &mut mechlist,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
        if err != SASL_OK || mechlist.is_null() {
            error!("SASL_FAIL: no support sasl mechlist");
            return Err(anyhow!(VncError::AuthFailed(
                "SASL_FAIL: no support sasl mechlist".to_string()
            )));
        }
        // SAFETY: It can be ensure that the pointer of mechlist is not null.
        let mech_list = unsafe { CStr::from_ptr(mechlist as *const c_char) };
        security.saslconfig.mech_list = String::from(mech_list.to_str()?);
        let mut buf = Vec::new();
        let len = security.saslconfig.mech_list.len();
        buf.append(&mut (len as u32).to_be_bytes().to_vec());
        buf.append(&mut security.saslconfig.mech_list.as_bytes().to_vec());
        drop(security);
        vnc_write(&client, buf);
        vnc_flush(&client);

        Ok(())
    }

    /// Check whether the ssf layer of sasl meets the strength requirements.
    fn sasl_check_ssf(&mut self) -> Result<()> {
        let server = self.server.clone();
        let mut security = server.security_type.borrow_mut();
        if !security.saslconfig.want_ssf {
            return Ok(());
        }
        let err: c_int;
        let mut val: *const c_void = ptr::null_mut();
        // SAFETY: sasl_getprop() is C function. It can be ensure
        // that security.saslconfig.sasl_conn is not null.
        unsafe { err = sasl_getprop(security.saslconfig.sasl_conn, SASL_SSF as c_int, &mut val) }
        if err != SASL_OK {
            error!("sasl_getprop: internal error");
            return Err(anyhow!(VncError::AuthFailed(String::from(
                "sasl_getprop: internal error"
            ))));
        }

        // SAFETY: It can be ensure that the ptr of val is not null.
        let ssf: usize = unsafe { *(val as *const usize) };
        if ssf < MIN_SSF_LENGTH {
            error!("SASL SSF too weak");
            return Err(anyhow!(VncError::AuthFailed(String::from(
                "SASL SSF too weak"
            ))));
        }

        security.saslconfig.run_ssf = 1;
        drop(security);
        Ok(())
    }

    /// Check username.
    fn sasl_check_authz(&mut self) -> Result<()> {
        let security = self.server.security_type.borrow_mut();
        let mut val: *const c_void = ptr::null_mut();
        // SAFETY: sasl_getprop() is C function. It can be ensure
        // that security.saslconfig.sasl_conn is not null.
        let err = unsafe {
            sasl_getprop(
                security.saslconfig.sasl_conn,
                SASL_USERNAME as c_int,
                &mut val,
            )
        };
        drop(security);
        if err != SASL_OK {
            return Err(anyhow!(VncError::AuthFailed(String::from(
                "Cannot fetch SASL username"
            ))));
        }
        if val.is_null() {
            return Err(anyhow!(VncError::AuthFailed(String::from(
                "No SASL username set"
            ))));
        }
        // SAFETY: It can ensure that the pointer val is not null.
        let username = unsafe { CStr::from_ptr(val as *const c_char) };
        let username = String::from(username.to_str()?);

        let server = self.server.clone();
        let security = server.security_type.borrow_mut();
        if let Some(saslauth) = &security.saslauth {
            if saslauth.identity != username {
                return Err(anyhow!(VncError::AuthFailed(String::from(
                    "No SASL username set"
                ))));
            }
        } else {
            return Err(anyhow!(VncError::AuthFailed(String::from(
                "No SASL username set"
            ))));
        }
        drop(security);

        Ok(())
    }
}

/// Auth reject.
fn auth_reject(buf: &mut Vec<u8>) {
    let reason = String::from("Authentication failed");
    buf.append(&mut (1_u32).to_be_bytes().to_vec());
    buf.append(&mut (reason.len() as u32).to_be_bytes().to_vec());
    buf.append(&mut reason.as_bytes().to_vec());
}
