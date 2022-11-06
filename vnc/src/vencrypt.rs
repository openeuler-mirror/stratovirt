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

use crate::{auth::SubAuthState, client::VncClient, VncError};
use anyhow::{anyhow, Result};
use log::{error, info};
use rustls::{
    self,
    cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    },
    kx_group::{SECP256R1, SECP384R1, X25519},
    server::{AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth},
    version::{TLS12, TLS13},
    RootCertStore, SupportedCipherSuite, SupportedKxGroup, SupportedProtocolVersion,
};
use std::{fs::File, io::BufReader, sync::Arc};
use util::loop_context::NotifierOperation;

const TLS_CREDS_SERVER_CACERT: &str = "cacert.pem";
const TLS_CREDS_SERVERCERT: &str = "servercert.pem";
const TLS_CREDS_SERVERKEY: &str = "serverkey.pem";
pub const X509_CERT: &str = "x509";
pub const ANON_CERT: &str = "anon";
const CLIENT_REQUIRE_AUTH: bool = true;
/// Number of stored sessions.
const MAXIMUM_SESSION_STORAGE: usize = 256;

/// Cipher suites supported by server.
pub static TLS_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
];
/// Tls version supported by server.
pub static TLS_VERSIONS: &[&SupportedProtocolVersion] = &[&TLS13, &TLS12];
/// Key exchange groups supported by server.
pub static TLS_KX_GROUPS: [&SupportedKxGroup; 3] = [&X25519, &SECP256R1, &SECP384R1];

/// Configuration for tls.
#[derive(Debug, Clone, Default)]
pub struct TlsCreds {
    /// X509 or anon.
    pub cred_type: String,
    /// Path of cred file.
    pub dir: String,
    /// Server of client.
    pub endpoint: Option<String>,
    /// Verify peer.
    pub verifypeer: bool,
}

impl VncClient {
    /// Exchange auth version with client
    pub fn client_vencrypt_init(&mut self) -> Result<()> {
        let buf = self.buffpool.read_front(self.expect);

        // VeNCrypt version 0.2.
        if buf[0] != 0 || buf[1] != 2 {
            let mut buf = Vec::new();
            // Reject version.
            buf.append(&mut (0_u8).to_be_bytes().to_vec());
            self.write_msg(&buf);
            return Err(anyhow!(VncError::UnsupportRFBProtocolVersion));
        } else {
            let mut buf = Vec::new();
            // Accept version.
            buf.append(&mut (0_u8).to_be_bytes().to_vec());
            // Number of sub-auths.
            buf.append(&mut (1_u8).to_be_bytes().to_vec());
            // The supported auth.
            buf.append(&mut (self.subauth as u32).to_be_bytes().to_vec());
            self.write_msg(&buf);
        }

        self.update_event_handler(4, VncClient::client_vencrypt_auth);
        Ok(())
    }

    /// Encrypted Channel Initialize.
    pub fn client_vencrypt_auth(&mut self) -> Result<()> {
        let buf = self.buffpool.read_front(self.expect);
        let buf = [buf[0], buf[1], buf[2], buf[3]];
        let auth = u32::from_be_bytes(buf);

        if auth != self.subauth as u32 {
            let mut buf = Vec::new();
            // Reject auth.
            buf.append(&mut (0_u8).to_be_bytes().to_vec());
            self.write_msg(&buf);
            error!("Authentication failed");
            return Err(anyhow!(VncError::AuthFailed(String::from(
                "Authentication failed"
            ))));
        }

        let mut buf = Vec::new();
        // Accept auth.
        buf.append(&mut (1_u8).to_be_bytes().to_vec());
        self.write_msg(&buf);

        if let Some(tls_config) = self.server.security_type.lock().unwrap().tls_config.clone() {
            match rustls::ServerConnection::new(tls_config) {
                Ok(tls_conn) => {
                    self.tls_conn = Some(tls_conn);
                }
                Err(e) => {
                    error!("Can't make ServerConnection: {}", e);
                    return Err(anyhow!(VncError::MakeTlsConnectionFailed(String::from(
                        "Can't make ServerConnection",
                    ))));
                }
            }
        } else {
            error!("There is no ventrypt configuration!");
            return Err(anyhow!(VncError::MakeTlsConnectionFailed(String::from(
                "There is no ventrypt configuration!",
            ))));
        }

        self.update_event_handler(1, VncClient::tls_handshake);
        self.modify_event(NotifierOperation::Modify, 1)?;
        Ok(())
    }

    /// Tls handshake.
    pub fn tls_handshake(&mut self) -> Result<()> {
        if let Some(tc) = &mut self.tls_conn {
            info!("tls_handshake");
            match tc.read_tls(&mut self.stream) {
                Err(err) => {
                    error!("{:?}", err);
                    return Err(anyhow!(VncError::AuthFailed(format!("{:?}", err))));
                }
                Ok(0) => {
                    error!("EOF");
                    return Err(anyhow!(VncError::AuthFailed(String::from("EOF"))));
                }
                Ok(_) => {}
            }

            if let Err(err) = tc.process_new_packets() {
                error!("Cannot process packet: {:?}", err);
                let rc = tc.write_tls(&mut self.stream);
                if rc.is_err() {
                    return Err(anyhow!(VncError::AuthFailed(format!("{:?}", rc))));
                }
                return Err(anyhow!(VncError::AuthFailed(format!("{:?}", err))));
            }

            if tc.wants_write() {
                if let Err(err) = tc.write_tls(&mut self.stream) {
                    return Err(anyhow!(VncError::AuthFailed(format!("{:?}", err))));
                }
            }

            if tc.is_handshaking() {
                // Tls handshake continue.
                self.handle_msg = VncClient::tls_handshake;
            } else {
                info!("Finished tls handshaking");
                // Tls handshake finished.
                self.modify_event(NotifierOperation::Modify, 0)?;
                if let Err(e) = self.handle_vencrypt_subauth() {
                    return Err(e);
                }
            }
        } else {
            return Err(anyhow!(VncError::AuthFailed(String::from(
                "Handshake failed"
            ))));
        }
        Ok(())
    }

    fn handle_vencrypt_subauth(&mut self) -> Result<()> {
        match self.subauth {
            SubAuthState::VncAuthVencryptX509Sasl => {
                self.expect = 4;
                self.handle_msg = VncClient::get_mechname_length;
                if let Err(e) = self.start_sasl_auth() {
                    return Err(e);
                }
            }
            SubAuthState::VncAuthVencryptX509None => {
                let buf = [0u8; 4];
                self.write_msg(&buf);
                self.expect = 1;
                self.handle_msg = VncClient::handle_client_init;
            }
            _ => {
                let mut buf: Vec<u8> = Vec::new();
                buf.append(&mut (0_u8).to_be_bytes().to_vec());
                if self.version.minor >= 8 {
                    let err_msg: String = "Unsupported subauth type".to_string();
                    buf.append(&mut (err_msg.len() as u32).to_be_bytes().to_vec());
                    buf.append(&mut err_msg.as_bytes().to_vec());
                    self.write_msg(&buf);
                }
                error!("Unsupported subauth type");
                return Err(anyhow!(VncError::MakeTlsConnectionFailed(String::from(
                    "Unsupported subauth type",
                ))));
            }
        }
        Ok(())
    }
}

/// Config encrypted channel.
///
/// # Arguments
///
/// * `args` - tls configuration.
pub fn make_vencrypt_config(args: &TlsCreds) -> Result<Arc<rustls::ServerConfig>> {
    let server_cacert = args.dir.clone() + "/" + TLS_CREDS_SERVER_CACERT;
    let server_cert = args.dir.clone() + "/" + TLS_CREDS_SERVERCERT;
    let server_key = args.dir.clone() + "/" + TLS_CREDS_SERVERKEY;

    // Load cacert.pem and provide verification for certificate chain
    let client_auth = if args.verifypeer {
        let roots;
        match load_certs(server_cacert.as_str()) {
            Ok(r) => roots = r,
            Err(e) => return Err(e),
        }
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(&root).unwrap();
        }
        if CLIENT_REQUIRE_AUTH {
            AllowAnyAuthenticatedClient::new(client_auth_roots)
        } else {
            AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
        }
    } else {
        NoClientAuth::new()
    };

    // Cipher suiter.
    let suites = TLS_CIPHER_SUITES.to_vec();
    // Tls protocol version supported by server.
    let versions = TLS_VERSIONS.to_vec();
    let certs: Vec<rustls::Certificate>;
    let privkey: rustls::PrivateKey;
    // Server certificate.
    match load_certs(server_cert.as_str()) {
        Ok(c) => certs = c,
        Err(e) => return Err(e),
    };
    // Server private key.
    match load_private_key(server_key.as_str()) {
        Ok(key) => privkey = key,
        Err(e) => return Err(e),
    }

    let mut config = rustls::ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_kx_groups(&TLS_KX_GROUPS)
        .with_protocol_versions(&versions)
        .expect("Unsupported cipher-suite/version")
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .expect("Invalid Certificate format");

    // SSLKEYLOGFILE=path configure key log path.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    // Limit data size in one time.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(MAXIMUM_SESSION_STORAGE);
    // Tickets.
    config.ticketer = rustls::Ticketer::new().unwrap();
    config.alpn_protocols = Vec::new();

    Ok(Arc::new(config))
}

/// load private key
///
/// # Arguments
///
/// * `filepath` - the path private key.
fn load_private_key(filepath: &str) -> Result<rustls::PrivateKey> {
    let keyfile;
    match File::open(filepath) {
        Ok(file) => keyfile = file,
        Err(e) => {
            error!("Private key file is no exit!: {}", e);
            return Err(anyhow!(VncError::MakeTlsConnectionFailed(String::from(
                "Private key file is no exit!",
            ))));
        }
    }

    let mut reader = BufReader::new(keyfile);
    loop {
        match rustls_pemfile::read_one(&mut reader).expect("Cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    error!("Load private key failed!");
    Err(anyhow!(VncError::MakeTlsConnectionFailed(String::from(
        "Load private key failed!"
    ))))
}

/// Load certificate.
///
/// # Arguments
///
/// * `filepath` - the file path of certificate.
fn load_certs(filepath: &str) -> Result<Vec<rustls::Certificate>> {
    let certfile;
    match File::open(filepath) {
        Ok(file) => certfile = file,
        Err(e) => {
            error!("Cannot open certificate file: {}", e);
            return Err(anyhow!(VncError::MakeTlsConnectionFailed(String::from(
                "Cannot open certificate file",
            ))));
        }
    }
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();
    Ok(certs)
}
