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

use std::{
    cell::RefCell,
    fs::File,
    io::{BufReader, ErrorKind, Read, Write},
    net::TcpStream,
    os::unix::prelude::{AsRawFd, RawFd},
    rc::Rc,
    sync::Arc,
};

use anyhow::{anyhow, bail, Result};
use log::error;
use rustls::{
    self,
    cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    },
    kx_group::{SECP256R1, SECP384R1, X25519},
    server::{
        AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
        ServerSessionMemoryCache,
    },
    version::{TLS12, TLS13},
    Certificate, KeyLogFile, PrivateKey, RootCertStore, ServerConfig, ServerConnection,
    SupportedCipherSuite, SupportedKxGroup, SupportedProtocolVersion, Ticketer,
};
use vmm_sys_util::epoll::EventSet;

use super::client_io::vnc_disconnect_start;
use crate::{
    error::VncError,
    vnc::{
        auth_sasl::SubAuthState,
        client_io::{vnc_flush, vnc_write, ClientIoHandler, IoOperations},
    },
};
use machine_manager::event_loop::EventLoop;
use util::loop_context::{EventNotifier, NotifierCallback, NotifierOperation};

const TLS_CREDS_SERVER_CACERT: &str = "cacert.pem";
const TLS_CREDS_SERVERCERT: &str = "servercert.pem";
const TLS_CREDS_SERVERKEY: &str = "serverkey.pem";
pub const X509_CERT: &str = "x509";
pub const ANON_CERT: &str = "anon";
const CLIENT_REQUIRE_AUTH: bool = true;
/// Number of stored sessions.
const MAXIMUM_SESSION_STORAGE: usize = 256;

/// Cipher suites supported by server.
static TLS_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
];
/// Tls version supported by server.
static TLS_VERSIONS: &[&SupportedProtocolVersion] = &[&TLS13, &TLS12];
/// Key exchange groups supported by server.
static TLS_KX_GROUPS: [&SupportedKxGroup; 3] = [&X25519, &SECP256R1, &SECP384R1];

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

impl ClientIoHandler {
    /// Exchange auth version with client
    pub fn client_vencrypt_init(&mut self) -> Result<()> {
        trace::vnc_client_vencrypt_init();

        let buf = self.read_incoming_msg();
        let client = self.client.clone();
        let subauth = self.server.security_type.borrow().subauth;
        // VeNCrypt version 0.2.
        if buf[0] != 0 || buf[1] != 2 {
            let mut buf = Vec::new();
            // Reject version.
            buf.append(&mut (0_u8).to_be_bytes().to_vec());
            vnc_write(&client, buf);
            vnc_flush(&client);
            return Err(anyhow!(VncError::UnsupportedRFBProtocolVersion));
        } else {
            let mut buf = Vec::new();
            // Accept version.
            buf.append(&mut (0_u8).to_be_bytes().to_vec());
            // Number of sub-auths.
            buf.append(&mut (1_u8).to_be_bytes().to_vec());
            // The supported auth.
            buf.append(&mut (subauth as u32).to_be_bytes().to_vec());
            vnc_write(&client, buf);
        }

        vnc_flush(&client);
        self.update_event_handler(4, ClientIoHandler::client_vencrypt_auth);
        Ok(())
    }

    /// Encrypted Channel Initialize.
    pub fn client_vencrypt_auth(&mut self) -> Result<()> {
        let buf = self.read_incoming_msg();
        let buf = [buf[0], buf[1], buf[2], buf[3]];
        let auth = u32::from_be_bytes(buf);
        let client = self.client.clone();
        let subauth = self.server.security_type.borrow().subauth;
        trace::vnc_client_vencrypt_auth(&auth, &subauth);

        if auth != subauth as u32 {
            let mut buf = Vec::new();
            // Reject auth.
            buf.append(&mut (0_u8).to_be_bytes().to_vec());
            vnc_write(&client, buf);
            vnc_flush(&client);
            return Err(anyhow!(VncError::AuthFailed(
                "client_vencrypt_auth".to_string(),
                "sub auth is not supported".to_string()
            )));
        }

        let mut buf = Vec::new();
        // Accept auth.
        buf.append(&mut (1_u8).to_be_bytes().to_vec());
        vnc_write(&client, buf);
        vnc_flush(&client);

        let tls_config = self
            .server
            .security_type
            .borrow()
            .tls_config
            .clone()
            .unwrap();
        let tls_conn = ServerConnection::new(tls_config)?;
        let tls_io_channel = Rc::new(RefCell::new(TlsIoChannel::new(
            self.stream.try_clone().unwrap(),
            tls_conn,
        )));

        let handler: Rc<NotifierCallback> = Rc::new(move |event, _fd: RawFd| {
            let mut dis_conn = false;
            if event & EventSet::READ_HANG_UP == EventSet::READ_HANG_UP {
                dis_conn = true;
            } else if event & EventSet::IN == EventSet::IN {
                if let Err(e) = tls_io_channel.borrow_mut().tls_handshake() {
                    error!("Tls handle shake error: {:?}", e);
                    dis_conn = true;
                }
            }

            if !dis_conn && !tls_io_channel.borrow().tls_conn.is_handshaking() {
                let client_io = client.conn_state.lock().unwrap().client_io.clone();
                let client_io = client_io.and_then(|c| c.upgrade()).unwrap();
                let mut locked_client = client_io.lock().unwrap();
                locked_client.io_channel = tls_io_channel.clone();
                if let Err(_e) = locked_client.tls_handshake_done() {
                    dis_conn = true;
                }
            }
            if dis_conn {
                client.conn_state.lock().unwrap().dis_conn = true;
                vnc_disconnect_start(&client);
            }
            None
        });
        self.handlers
            .insert("vnc_tls_io".to_string(), handler.clone());
        let handlers = vec![handler];
        EventLoop::update_event(
            vec![EventNotifier::new(
                NotifierOperation::Modify,
                self.stream.as_raw_fd(),
                None,
                EventSet::empty(),
                handlers,
            )],
            None,
        )?;

        self.client
            .in_buffer
            .lock()
            .unwrap()
            .remove_front(self.expect);
        self.expect = 0;
        Ok(())
    }

    fn tls_handshake_done(&mut self) -> Result<()> {
        trace::vnc_client_tls_handshake_done();

        let handler = self.handlers.get("vnc_client_io").unwrap().clone();
        let handlers = vec![handler];
        EventLoop::update_event(
            vec![EventNotifier::new(
                NotifierOperation::Modify,
                self.stream.as_raw_fd(),
                None,
                EventSet::empty(),
                handlers,
            )],
            None,
        )?;
        self.handle_vencrypt_subauth()?;
        Ok(())
    }

    fn handle_vencrypt_subauth(&mut self) -> Result<()> {
        let subauth = self.server.security_type.borrow().subauth;
        let client = self.client.clone();
        match subauth {
            SubAuthState::VncAuthVencryptX509Sasl => {
                self.expect = 4;
                self.msg_handler = ClientIoHandler::get_mechname_length;
                self.start_sasl_auth()?;
            }
            SubAuthState::VncAuthVencryptX509None => {
                let buf = [0u8; 4];
                vnc_write(&client, buf.to_vec());
                vnc_flush(&client);
                self.expect = 1;
                self.msg_handler = ClientIoHandler::handle_client_init;
            }
            _ => {
                let mut buf: Vec<u8> = Vec::new();
                buf.append(&mut (0_u8).to_be_bytes().to_vec());
                let version = self.client.conn_state.lock().unwrap().version.clone();
                if version.minor >= 8 {
                    let err_msg: String = "Unsupported subauth type".to_string();
                    buf.append(&mut (err_msg.len() as u32).to_be_bytes().to_vec());
                    buf.append(&mut err_msg.as_bytes().to_vec());
                    vnc_write(&client, buf);
                    vnc_flush(&client);
                }

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
pub fn make_vencrypt_config(args: &TlsCreds) -> Result<Arc<ServerConfig>> {
    let server_cacert = args.dir.clone() + "/" + TLS_CREDS_SERVER_CACERT;
    let server_cert = args.dir.clone() + "/" + TLS_CREDS_SERVERCERT;
    let server_key = args.dir.clone() + "/" + TLS_CREDS_SERVERKEY;

    // Load cacert.pem and provide verification for certificate chain
    let client_auth = if args.verifypeer {
        let roots = load_certs(server_cacert.as_str())?;
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(&root)?;
        }
        if CLIENT_REQUIRE_AUTH {
            AllowAnyAuthenticatedClient::new(client_auth_roots).boxed()
        } else {
            AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots).boxed()
        }
    } else {
        NoClientAuth::boxed()
    };

    // Cipher suiter.
    let suites = TLS_CIPHER_SUITES.to_vec();
    // Tls protocol version supported by server.
    let versions = TLS_VERSIONS.to_vec();
    // Server certificate.
    let certs: Vec<Certificate> = load_certs(server_cert.as_str())?;
    // Server private key.
    let privkey: PrivateKey = load_private_key(server_key.as_str())?;

    let mut config = ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_kx_groups(&TLS_KX_GROUPS)
        .with_protocol_versions(&versions)
        .expect("Unsupported cipher-suite/version")
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .expect("Invalid Certificate format");

    // SSLKEYLOGFILE=path configure key log path.
    config.key_log = Arc::new(KeyLogFile::new());
    // Limit data size in one time.
    config.session_storage = ServerSessionMemoryCache::new(MAXIMUM_SESSION_STORAGE);
    // Tickets.
    config.ticketer = Ticketer::new()?;
    config.alpn_protocols = Vec::new();

    Ok(Arc::new(config))
}

/// load private key
///
/// # Arguments
///
/// * `filepath` - the path private key.
fn load_private_key(filepath: &str) -> Result<PrivateKey> {
    let file = File::open(filepath)?;

    let mut reader = BufReader::new(file);
    loop {
        match rustls_pemfile::read_one(&mut reader).expect("Cannot parse .pem file") {
            Some(rustls_pemfile::Item::RSAKey(ras)) => return Ok(PrivateKey(ras)),
            Some(rustls_pemfile::Item::PKCS8Key(pkcs8)) => return Ok(PrivateKey(pkcs8)),
            Some(rustls_pemfile::Item::ECKey(ec)) => return Ok(PrivateKey(ec)),
            None => break,
            _ => {}
        }
    }

    Err(anyhow!(VncError::MakeTlsConnectionFailed(
        "Load private key failed!".to_string()
    )))
}

/// Load certificate.
///
/// # Arguments
///
/// * `filepath` - the file path of certificate.
fn load_certs(filepath: &str) -> Result<Vec<Certificate>> {
    let certfile = File::open(filepath)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| Certificate(v.clone()))
        .collect();
    Ok(certs)
}

struct TlsIoChannel {
    /// TcpStream connected with client.
    stream: TcpStream,
    /// Tls server connection.
    tls_conn: ServerConnection,
}

impl TlsIoChannel {
    fn new(stream: TcpStream, tls_conn: ServerConnection) -> Self {
        Self { stream, tls_conn }
    }

    fn tls_handshake(&mut self) -> Result<()> {
        if self.tls_conn.read_tls(&mut self.stream)? == 0 {
            bail!("Tls hand shake failed: EOF");
        }
        self.tls_conn.process_new_packets()?;
        if self.tls_conn.wants_write() {
            self.tls_conn.write_tls(&mut self.stream)?;
        }
        Ok(())
    }
}

impl IoOperations for TlsIoChannel {
    fn channel_write(&mut self, buf: &[u8]) -> Result<usize> {
        let buf_size = buf.len();
        let mut offset = 0;
        while offset < buf_size {
            let tmp_buf = &buf[offset..];
            match self.tls_conn.writer().write(tmp_buf) {
                Ok(0) => {
                    bail!("Failed to write tls message!");
                }
                Ok(n) => offset += n,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    bail!("Internal error: {}", e);
                }
            }

            while self.tls_conn.wants_write() {
                match self.tls_conn.write_tls(&mut self.stream) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(e) => {
                        bail!("Unable to write msg on tls socket: {:?}", e);
                    }
                }
            }
        }

        Ok(buf_size)
    }

    fn channel_read(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut len = 0_usize;
        self.tls_conn.read_tls(&mut self.stream)?;

        let io_state = self.tls_conn.process_new_packets()?;
        if io_state.plaintext_bytes_to_read() > 0 {
            len = io_state.plaintext_bytes_to_read();
            // FIXME: Split len to avoid possible OOM.
            buf.resize(len, 0u8);
            self.tls_conn.reader().read_exact(buf)?;
        }
        Ok(len)
    }
}
