// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
// Minimal TCP/IP stack for MMDS at 169.254.169.254:80.
//
// Intercepts VirtIO TX packets (VirtioNetHdr + Ethernet + IPv4 + TCP),
// handles IMDSv2 HTTP, and returns raw packet bytes to inject into the RX queue.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use log::warn;
use util::aio::{get_iov_size, iov_to_buf_direct, Iovec};

use super::MmdsStore;

/// Offset constants (from start of VirtIO packet buffer).
const VNET_HDR_LEN: usize = 12; // VirtioNetHdr size
const ETH_HDR_LEN: usize = 14; // Ethernet header
const IPV4_HDR_MIN: usize = 20; // minimum IPv4 header
const TCP_HDR_MIN: usize = 20; // minimum TCP header

const IP_PROTO_TCP: u8 = 0x06;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;

// ARP operation codes
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
// Minimum ARP packet: VirtioNetHdr + Ethernet + 28-byte ARP payload
const ARP_PKT_LEN: usize = VNET_HDR_LEN + ETH_HDR_LEN + 28;

// Locally-administered unicast MAC used as the MMDS endpoint in ARP replies.
const MMDS_MAC: [u8; 6] = [0xfe, 0x12, 0x34, 0x56, 0x78, 0x9a];

// Maximum number of concurrent half-open or established MMDS connections.
// Prevents unbounded memory growth from guests that open connections without closing them.
const MAX_CONNECTIONS: usize = 128;

// TCP flag bits
const TCP_FIN: u16 = 0x001;
const TCP_SYN: u16 = 0x002;
const TCP_RST: u16 = 0x004;
const TCP_ACK: u16 = 0x010;
const TCP_PSH: u16 = 0x008;

/// TCP connection state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum TcpState {
    Listen,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
}

/// Per-connection state tracked by the MMDS TCP stack.
struct TcpConn {
    state: TcpState,
    /// Our (server) sequence number.
    server_seq: u32,
    /// Client's next expected sequence (our ACK number).
    client_seq: u32,
    /// Accumulated HTTP request bytes.
    rx_buf: Vec<u8>,
    /// Pending response bytes to send.
    tx_buf: Vec<u8>,
    /// Whether we've already queued the FIN.
    fin_sent: bool,
    /// Remote MAC (to swap src/dst in replies).
    remote_mac: [u8; 6],
    /// Local MAC (the MMDS endpoint mac, copied from the incoming dst_mac).
    local_mac: [u8; 6],
    /// Remote IP.
    remote_ip: [u8; 4],
    /// Remote port.
    remote_port: u16,
}

/// Connection key: (src_ip, src_port).
type ConnKey = ([u8; 4], u16);

/// Minimal MMDS TCP stack.
pub struct MmdsTcpStack {
    mmds: Arc<Mutex<MmdsStore>>,
    /// MMDS IPv4 address (usually 169.254.169.254).
    pub local_ip: [u8; 4],
    connections: HashMap<ConnKey, TcpConn>,
}

impl MmdsTcpStack {
    pub fn new(mmds: Arc<Mutex<MmdsStore>>) -> Self {
        let local_ip = mmds.lock().unwrap().get_ipv4_address();
        MmdsTcpStack {
            mmds,
            local_ip,
            connections: HashMap::new(),
        }
    }

    pub fn store(&self) -> &Arc<Mutex<MmdsStore>> {
        &self.mmds
    }

    /// Process one inbound packet (full VirtIO packet: VirtioNetHdr + Ethernet + IP + TCP).
    /// Returns a list of response packets to inject into the guest RX queue.
    pub fn process(&mut self, pkt: &[u8]) -> Vec<Vec<u8>> {
        // Handle ARP requests for the MMDS IP before attempting TCP/IP processing.
        if let Some(arp_reply) = self.handle_arp(pkt) {
            return vec![arp_reply];
        }
        match self.parse_and_handle(pkt) {
            Ok(pkts) => pkts,
            Err(e) => {
                warn!("MMDS TCP stack error: {}", e);
                Vec::new()
            }
        }
    }

    fn parse_and_handle(&mut self, pkt: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        // Minimum size check: VNet + Eth + IP + TCP
        let min_len = VNET_HDR_LEN + ETH_HDR_LEN + IPV4_HDR_MIN + TCP_HDR_MIN;
        if pkt.len() < min_len {
            return Err(format!(
                "packet too short: {} bytes, need at least {}",
                pkt.len(),
                min_len
            ));
        }

        // --- Ethernet ---
        let eth = &pkt[VNET_HDR_LEN..];
        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        if ethertype != ETHERTYPE_IPV4 {
            return Ok(Vec::new());
        }
        let src_mac: [u8; 6] = eth[6..12].try_into().unwrap();
        let dst_mac: [u8; 6] = eth[0..6].try_into().unwrap();

        // --- IPv4 ---
        let ip = &eth[ETH_HDR_LEN..];
        let ihl = (ip[0] & 0x0f) as usize * 4;
        if ihl < IPV4_HDR_MIN {
            return Err(format!("invalid IP header length: {} bytes", ihl));
        }
        if ip.len() < ihl + TCP_HDR_MIN {
            return Err(format!(
                "IP payload too short: {} bytes, need at least {}",
                ip.len(),
                ihl + TCP_HDR_MIN
            ));
        }
        if ip[9] != IP_PROTO_TCP {
            return Ok(Vec::new());
        }
        let ip_total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if ip.len() < ip_total_len {
            return Err(format!(
                "truncated IP packet: buffer {} bytes, ip_total_len field says {}",
                ip.len(),
                ip_total_len
            ));
        }
        let src_ip: [u8; 4] = ip[12..16].try_into().unwrap();
        let dst_ip: [u8; 4] = ip[16..20].try_into().unwrap();

        if dst_ip != self.local_ip {
            return Ok(Vec::new());
        }

        // --- TCP ---
        let tcp = &ip[ihl..ip_total_len];
        if tcp.len() < TCP_HDR_MIN {
            return Err(format!(
                "TCP segment too short: {} bytes, need at least {}",
                tcp.len(),
                TCP_HDR_MIN
            ));
        }
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        if dst_port != 80 {
            return Ok(Vec::new());
        }
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        let flags = ((tcp[12] as u16 & 0x01) << 8) | tcp[13] as u16;
        let payload = if tcp.len() > data_offset {
            &tcp[data_offset..]
        } else {
            &[]
        };

        let key: ConnKey = (src_ip, src_port);
        let mut out = Vec::new();

        if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
            // Reject new connections when the table is full.
            if self.connections.len() >= MAX_CONNECTIONS {
                warn!(
                    "MMDS: connection table full ({} entries), dropping SYN from {:?}:{}",
                    MAX_CONNECTIONS, src_ip, src_port
                );
                return Ok(out);
            }
            // New connection: SYN
            let server_isn: u32 = random_isn(&src_ip, src_port, &self.local_ip, 80);
            let conn = TcpConn {
                state: TcpState::SynReceived,
                server_seq: server_isn.wrapping_add(1),
                client_seq: seq.wrapping_add(1),
                rx_buf: Vec::new(),
                tx_buf: Vec::new(),
                fin_sent: false,
                remote_mac: src_mac,
                local_mac: dst_mac,
                remote_ip: src_ip,
                remote_port: src_port,
            };
            // Build SYN-ACK
            let syn_ack = build_tcp_packet(
                &conn.local_mac,
                &conn.remote_mac,
                &self.local_ip,
                &conn.remote_ip,
                80,
                conn.remote_port,
                server_isn,
                conn.client_seq,
                TCP_SYN | TCP_ACK,
                &[],
            );
            out.push(syn_ack);
            self.connections.insert(key, conn);
        } else if let Some(conn) = self.connections.get_mut(&key) {
            match conn.state.clone() {
                TcpState::SynReceived => {
                    if flags & TCP_ACK != 0 {
                        conn.state = TcpState::Established;
                    }
                }
                TcpState::Established => {
                    if !payload.is_empty() {
                        conn.client_seq = conn.client_seq.wrapping_add(payload.len() as u32);
                        conn.rx_buf.extend_from_slice(payload);
                        // ACK the data
                        let ack_pkt = build_tcp_packet(
                            &conn.local_mac,
                            &conn.remote_mac,
                            &self.local_ip,
                            &conn.remote_ip,
                            80,
                            conn.remote_port,
                            conn.server_seq,
                            conn.client_seq,
                            TCP_ACK,
                            &[],
                        );
                        out.push(ack_pkt);

                        // Try to process HTTP request
                        if let Some(response_bytes) = maybe_handle_http(&conn.rx_buf, &self.mmds) {
                            conn.rx_buf.clear();
                            conn.tx_buf = response_bytes;
                            // Send response + FIN
                            let resp_pkt = build_tcp_packet(
                                &conn.local_mac,
                                &conn.remote_mac,
                                &self.local_ip,
                                &conn.remote_ip,
                                80,
                                conn.remote_port,
                                conn.server_seq,
                                conn.client_seq,
                                TCP_PSH | TCP_ACK,
                                &conn.tx_buf.clone(),
                            );
                            conn.server_seq =
                                conn.server_seq.wrapping_add(conn.tx_buf.len() as u32);
                            out.push(resp_pkt);

                            // FIN
                            let fin_pkt = build_tcp_packet(
                                &conn.local_mac,
                                &conn.remote_mac,
                                &self.local_ip,
                                &conn.remote_ip,
                                80,
                                conn.remote_port,
                                conn.server_seq,
                                conn.client_seq,
                                TCP_FIN | TCP_ACK,
                                &[],
                            );
                            conn.server_seq = conn.server_seq.wrapping_add(1);
                            conn.fin_sent = true;
                            // Server sent FIN — waiting for client's ACK of our FIN.
                            conn.state = TcpState::LastAck;
                            out.push(fin_pkt);
                        }
                    }

                    if flags & TCP_FIN != 0 {
                        conn.client_seq = conn.client_seq.wrapping_add(1);
                        let fin_ack = build_tcp_packet(
                            &conn.local_mac,
                            &conn.remote_mac,
                            &self.local_ip,
                            &conn.remote_ip,
                            80,
                            conn.remote_port,
                            conn.server_seq,
                            conn.client_seq,
                            TCP_FIN | TCP_ACK,
                            &[],
                        );
                        conn.server_seq = conn.server_seq.wrapping_add(1);
                        // Server sent FIN|ACK in response to client FIN — waiting for client's ACK.
                        conn.state = TcpState::LastAck;
                        out.push(fin_ack);
                    }
                }
                TcpState::CloseWait | TcpState::LastAck => {
                    if flags & TCP_ACK != 0 {
                        // Final ACK received, clean up
                        self.connections.remove(&key);
                        return Ok(out);
                    }
                }
                TcpState::Listen => {}
            }
        } else if flags & TCP_RST == 0 {
            // Unknown connection, send RST
            let rst = build_tcp_packet(
                &dst_mac,
                &src_mac,
                &self.local_ip,
                &src_ip,
                80,
                src_port,
                ack,
                seq.wrapping_add(payload.len() as u32),
                TCP_RST | TCP_ACK,
                &[],
            );
            out.push(rst);
        }

        Ok(out)
    }

    /// Returns true if the packet should be intercepted by MMDS:
    /// either an IPv4 packet destined for the MMDS IP, or an ARP request for it.
    pub fn is_mmds_packet(pkt: &[u8], local_ip: &[u8; 4]) -> bool {
        let min = VNET_HDR_LEN + ETH_HDR_LEN + 20;
        if pkt.len() < min {
            return false;
        }
        let eth = &pkt[VNET_HDR_LEN..];
        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        match ethertype {
            ETHERTYPE_IPV4 => {
                let ip = &eth[ETH_HDR_LEN..];
                &ip[16..20] == local_ip
            }
            ETHERTYPE_ARP => {
                // ARP request (opcode 1) whose target IP is the MMDS address.
                pkt.len() >= ARP_PKT_LEN && {
                    let arp = &eth[ETH_HDR_LEN..];
                    u16::from_be_bytes([arp[6], arp[7]]) == ARP_REQUEST && &arp[24..28] == local_ip
                }
            }
            _ => false,
        }
    }

    /// Check if the scatter-gather packet targets the MMDS IP, without copying the full packet.
    /// Reads at most 8 bytes from guest memory into stack-allocated buffers.
    ///
    /// # Safety
    /// Caller must ensure all iov_base addresses are valid HVAs.
    pub unsafe fn is_mmds_packet_iov(iovecs: &[Iovec], local_ip: &[u8; 4]) -> bool {
        let total = get_iov_size(iovecs) as usize;
        if total < VNET_HDR_LEN + ETH_HDR_LEN + 20 {
            return false;
        }

        let mut et = [0u8; 2];
        if iov_to_buf_direct(iovecs, (VNET_HDR_LEN + 12) as u64, &mut et).unwrap_or(0) < 2 {
            return false;
        }
        let ethertype = u16::from_be_bytes(et);

        match ethertype {
            ETHERTYPE_IPV4 => {
                let mut dst = [0u8; 4];
                iov_to_buf_direct(iovecs, (VNET_HDR_LEN + ETH_HDR_LEN + 16) as u64, &mut dst)
                    .unwrap_or(0)
                    == 4
                    && &dst == local_ip
            }
            ETHERTYPE_ARP => {
                if total < ARP_PKT_LEN {
                    return false;
                }
                let mut op = [0u8; 2];
                if iov_to_buf_direct(iovecs, (VNET_HDR_LEN + ETH_HDR_LEN + 6) as u64, &mut op)
                    .unwrap_or(0)
                    < 2
                    || u16::from_be_bytes(op) != ARP_REQUEST
                {
                    return false;
                }
                let mut tip = [0u8; 4];
                iov_to_buf_direct(iovecs, (VNET_HDR_LEN + ETH_HDR_LEN + 24) as u64, &mut tip)
                    .unwrap_or(0)
                    == 4
                    && &tip == local_ip
            }
            _ => false,
        }
    }

    /// If `pkt` is an ARP request for the MMDS IP, return a crafted ARP reply.
    fn handle_arp(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < ARP_PKT_LEN {
            return None;
        }
        let eth = &pkt[VNET_HDR_LEN..];
        if u16::from_be_bytes([eth[12], eth[13]]) != ETHERTYPE_ARP {
            return None;
        }
        let arp = &eth[ETH_HDR_LEN..];
        if u16::from_be_bytes([arp[6], arp[7]]) != ARP_REQUEST {
            return None;
        }
        let target_ip: [u8; 4] = arp[24..28].try_into().ok()?;
        if target_ip != self.local_ip {
            return None;
        }

        let guest_mac: [u8; 6] = eth[6..12].try_into().ok()?;
        let sender_mac: [u8; 6] = arp[8..14].try_into().ok()?;
        let sender_ip: [u8; 4] = arp[14..18].try_into().ok()?;

        let mut reply = vec![0u8; ARP_PKT_LEN];

        // Ethernet header
        let eth_out = &mut reply[VNET_HDR_LEN..];
        eth_out[0..6].copy_from_slice(&guest_mac);
        eth_out[6..12].copy_from_slice(&MMDS_MAC);
        eth_out[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());

        // ARP payload
        let arp_out = &mut eth_out[ETH_HDR_LEN..];
        arp_out[0..2].copy_from_slice(&1u16.to_be_bytes()); // hw_type = Ethernet
        arp_out[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // proto = IPv4
        arp_out[4] = 6; // hw_size
        arp_out[5] = 4; // proto_size
        arp_out[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes());
        arp_out[8..14].copy_from_slice(&MMDS_MAC); // sender = MMDS
        arp_out[14..18].copy_from_slice(&self.local_ip); // sender IP = MMDS IP
        arp_out[18..24].copy_from_slice(&sender_mac); // target = guest
        arp_out[24..28].copy_from_slice(&sender_ip); // target IP = guest IP

        Some(reply)
    }
}

/// Try to parse a complete HTTP/1.x request from the buffer.
/// Returns Some(http_response_bytes) if the request is complete, None otherwise.
fn maybe_handle_http(buf: &[u8], mmds: &Arc<Mutex<MmdsStore>>) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(buf).ok()?;

    // HTTP request is complete when headers end with \r\n\r\n (GET/PUT with no body)
    // or body length matches Content-Length (PUT with body - not used for MMDS).
    let header_end = text.find("\r\n\r\n")?;
    let headers_str = &text[..header_end];

    let mut lines = headers_str.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;

    // Parse headers into a map
    let mut header_map: HashMap<String, String> = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            header_map.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    let token = header_map.get("x-metadata-token").map(String::as_str);
    let store = mmds.lock().unwrap();

    let (status, body) = match method {
        "PUT" if path == "/latest/api/token" => {
            let ttl: u32 = header_map
                .get("x-metadata-token-ttl-seconds")
                .and_then(|v| {
                    v.parse::<u32>()
                        .ok()
                        .or_else(|| v.parse::<f64>().ok().map(|f| f as u32))
                })
                .unwrap_or(21600);
            // IMDSv2 spec: TTL must be in [1, 21600] seconds.
            if ttl == 0 || ttl > 21600 {
                drop(store);
                let err_body = "TTL must be between 1 and 21600\n";
                return Some(
                    format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                        err_body.len(),
                        err_body,
                    )
                    .into_bytes(),
                );
            }
            drop(store);
            let mut store_mut = mmds.lock().unwrap();
            let tok = store_mut.generate_token(ttl);
            (200u16, tok)
        }
        "GET" => match store.handle_get_request(token) {
            Ok(json) => {
                let body = serde_json::to_string(&json).unwrap_or_default();
                drop(store);
                (200u16, body)
            }
            Err(_) => {
                drop(store);
                (401u16, "Unauthorized\r\n".to_string())
            }
        },
        _ => {
            drop(store);
            (405u16, "Method Not Allowed\r\n".to_string())
        }
    };

    let status_text = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };

    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );

    Some(response.into_bytes())
}

/// Generate a pseudo-random Initial Sequence Number.
/// Mixes system time (nanoseconds) with the connection 4-tuple so each
/// connection gets a unique, unpredictable ISN even without a PRNG crate.
fn random_isn(src_ip: &[u8; 4], src_port: u16, dst_ip: &[u8; 4], dst_port: u16) -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let mut h = t;
    h ^= u32::from_be_bytes(*src_ip);
    h ^= u32::from_be_bytes(*dst_ip).rotate_left(7);
    h ^= (src_port as u32) << 16 | dst_port as u32;
    // Fibonacci hashing + avalanche
    h = h.wrapping_mul(0x9e3779b9);
    h ^= h >> 16;
    h
}

/// Build a complete VirtioNetHdr + Ethernet + IPv4 + TCP packet.
#[allow(clippy::too_many_arguments)]
fn build_tcp_packet(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_num: u32,
    flags: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = TCP_HDR_MIN + payload.len();
    let ip_total = IPV4_HDR_MIN + tcp_len;
    let total = VNET_HDR_LEN + ETH_HDR_LEN + ip_total;

    let mut pkt = vec![0u8; total];

    // VirtioNetHdr: all zeros (no offloading)

    // Ethernet header
    let eth = &mut pkt[VNET_HDR_LEN..];
    eth[0..6].copy_from_slice(dst_mac);
    eth[6..12].copy_from_slice(src_mac);
    eth[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4 header
    let ip = &mut eth[ETH_HDR_LEN..];
    ip[0] = 0x45; // version=4, IHL=5
    ip[1] = 0x00; // DSCP/ECN
    ip[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes()); // id
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    ip[8] = 64; // TTL
    ip[9] = IP_PROTO_TCP;
    // ip[10..12] = checksum (computed below)
    ip[12..16].copy_from_slice(src_ip);
    ip[16..20].copy_from_slice(dst_ip);
    let ip_csum = ipv4_checksum(&ip[..IPV4_HDR_MIN]);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP header
    let tcp = &mut ip[IPV4_HDR_MIN..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack_num.to_be_bytes());
    // data offset = 5 (20 bytes), flags in lower 9 bits
    tcp[12] = (5 << 4) | ((flags >> 8) as u8 & 0x01);
    tcp[13] = (flags & 0xff) as u8;
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
                                                          // tcp[16..18] = checksum (computed below)
    tcp[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent

    if !payload.is_empty() {
        tcp[TCP_HDR_MIN..TCP_HDR_MIN + payload.len()].copy_from_slice(payload);
    }

    let tcp_csum = tcp_checksum(src_ip, dst_ip, &tcp[..tcp_len]);
    let tcp = &mut ip[IPV4_HDR_MIN..];
    tcp[16..18].copy_from_slice(&tcp_csum.to_be_bytes());

    pkt
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        sum += word;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    // Pseudo-header: src_ip(4) + dst_ip(4) + zeros(1) + proto(1) + tcp_len(2)
    let tcp_len = tcp_segment.len() as u16;
    let mut sum: u32 = 0;

    // Pseudo-header
    for i in 0..2 {
        sum += u16::from_be_bytes([src_ip[i * 2], src_ip[i * 2 + 1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[i * 2], dst_ip[i * 2 + 1]]) as u32;
    }
    sum += IP_PROTO_TCP as u32;
    sum += tcp_len as u32;

    // TCP segment
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmds::{MmdsStore, MmdsVersion};
    use std::sync::{Arc, Mutex};

    const MMDS_IP: [u8; 4] = [169, 254, 169, 254];
    const GUEST_IP: [u8; 4] = [192, 168, 1, 100];
    const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x01, 0x02, 0x03];
    const MMDS_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x04, 0x05, 0x06];
    const GUEST_PORT: u16 = 54321;

    fn make_v1_store() -> Arc<Mutex<MmdsStore>> {
        let mut s = MmdsStore::new_default();
        s.config.version = MmdsVersion::V1;
        Arc::new(Mutex::new(s))
    }

    fn make_v2_store() -> Arc<Mutex<MmdsStore>> {
        Arc::new(Mutex::new(MmdsStore::new_v2()))
    }

    fn guest_syn() -> Vec<u8> {
        build_tcp_packet(
            &GUEST_MAC,
            &MMDS_MAC,
            &GUEST_IP,
            &MMDS_IP,
            GUEST_PORT,
            80,
            100,
            0,
            TCP_SYN,
            &[],
        )
    }

    fn guest_ack(seq: u32, ack: u32) -> Vec<u8> {
        build_tcp_packet(
            &GUEST_MAC,
            &MMDS_MAC,
            &GUEST_IP,
            &MMDS_IP,
            GUEST_PORT,
            80,
            seq,
            ack,
            TCP_ACK,
            &[],
        )
    }

    fn guest_data(seq: u32, ack: u32, data: &[u8]) -> Vec<u8> {
        build_tcp_packet(
            &GUEST_MAC,
            &MMDS_MAC,
            &GUEST_IP,
            &MMDS_IP,
            GUEST_PORT,
            80,
            seq,
            ack,
            TCP_PSH | TCP_ACK,
            data,
        )
    }

    // Extract TCP flags from a response packet built by build_tcp_packet.
    fn tcp_flags(pkt: &[u8]) -> u16 {
        let eth = &pkt[VNET_HDR_LEN..];
        let ip = &eth[ETH_HDR_LEN..];
        let ihl = (ip[0] & 0x0f) as usize * 4;
        let tcp = &ip[ihl..];
        ((tcp[12] as u16 & 0x01) << 8) | tcp[13] as u16
    }

    // Extract TCP payload from a response packet.
    fn tcp_payload(pkt: &[u8]) -> Vec<u8> {
        let eth = &pkt[VNET_HDR_LEN..];
        let ip = &eth[ETH_HDR_LEN..];
        let ihl = (ip[0] & 0x0f) as usize * 4;
        let ip_total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let tcp = &ip[ihl..ip_total];
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        tcp[data_offset..].to_vec()
    }

    // Extract server ISN from the SYN-ACK returned for our SYN.
    fn server_isn_from_syn_ack(syn_ack: &[u8]) -> u32 {
        let eth = &syn_ack[VNET_HDR_LEN..];
        let ip = &eth[ETH_HDR_LEN..];
        let ihl = (ip[0] & 0x0f) as usize * 4;
        let tcp = &ip[ihl..];
        u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]])
    }

    // Drive a full SYN→SYN-ACK→ACK handshake and return the server ISN.
    fn do_handshake(stack: &mut MmdsTcpStack) -> u32 {
        let syn_acks = stack.process(&guest_syn());
        assert_eq!(syn_acks.len(), 1, "SYN must produce exactly one SYN-ACK");
        let server_isn = server_isn_from_syn_ack(&syn_acks[0]);
        // client seq after SYN = 101 (100+1); ack = server_isn+1
        let ack_resp = stack.process(&guest_ack(101, server_isn + 1));
        assert!(ack_resp.is_empty(), "pure ACK should produce no response");
        server_isn
    }

    #[test]
    fn test_is_mmds_packet_too_short() {
        assert!(!MmdsTcpStack::is_mmds_packet(&[0u8; 10], &MMDS_IP));
    }

    #[test]
    fn test_is_mmds_packet_arp_too_short() {
        // A packet with ARP ethertype but shorter than ARP_PKT_LEN must be rejected.
        let mut pkt = vec![0u8; VNET_HDR_LEN + ETH_HDR_LEN + 20];
        pkt[VNET_HDR_LEN + 12] = 0x08;
        pkt[VNET_HDR_LEN + 13] = 0x06;
        assert!(!MmdsTcpStack::is_mmds_packet(&pkt, &MMDS_IP));
    }

    #[test]
    fn test_is_mmds_packet_arp_for_mmds_ip() {
        // A well-formed ARP request for the MMDS IP must be recognised.
        let mut pkt = vec![0u8; ARP_PKT_LEN];
        // Ethernet ethertype = ARP
        pkt[VNET_HDR_LEN + 12] = 0x08;
        pkt[VNET_HDR_LEN + 13] = 0x06;
        // ARP opcode = REQUEST (1) at arp[6..8]
        let arp_base = VNET_HDR_LEN + ETH_HDR_LEN;
        pkt[arp_base + 6] = 0x00;
        pkt[arp_base + 7] = 0x01;
        // ARP target IP at arp[24..28]
        pkt[arp_base + 24..arp_base + 28].copy_from_slice(&MMDS_IP);
        assert!(MmdsTcpStack::is_mmds_packet(&pkt, &MMDS_IP));
    }

    #[test]
    fn test_is_mmds_packet_wrong_dst_ip() {
        let pkt = guest_syn();
        assert!(!MmdsTcpStack::is_mmds_packet(&pkt, &[10, 0, 0, 1]));
    }

    #[test]
    fn test_is_mmds_packet_correct() {
        let pkt = guest_syn();
        assert!(MmdsTcpStack::is_mmds_packet(&pkt, &MMDS_IP));
    }

    #[test]
    fn test_syn_produces_syn_ack() {
        let mut stack = MmdsTcpStack::new(make_v1_store());
        let responses = stack.process(&guest_syn());
        assert_eq!(responses.len(), 1);
        let flags = tcp_flags(&responses[0]);
        assert_eq!(flags & (TCP_SYN | TCP_ACK), TCP_SYN | TCP_ACK);
    }

    #[test]
    fn test_http_get_v1_returns_200() {
        let mut stack = MmdsTcpStack::new(make_v1_store());
        let server_isn = do_handshake(&mut stack);

        let req = b"GET /latest/meta-data HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
        let responses = stack.process(&guest_data(101, server_isn + 1, req));

        // Expect at minimum: ACK + PSH|ACK (response) + FIN|ACK
        assert!(responses.len() >= 2, "Expected ACK + HTTP response packets");

        let psh_pkt = responses
            .iter()
            .find(|p| tcp_flags(p) & TCP_PSH != 0)
            .expect("Should have a PSH|ACK response packet");
        let body = tcp_payload(psh_pkt);
        let resp_str = std::str::from_utf8(&body).unwrap();
        assert!(
            resp_str.contains("200 OK"),
            "HTTP response should be 200 OK, got: {}",
            resp_str
        );
    }

    #[test]
    fn test_put_token_returns_200_and_token_is_valid() {
        let store = make_v2_store();
        let mut stack = MmdsTcpStack::new(store.clone());
        let server_isn = do_handshake(&mut stack);

        let req = b"PUT /latest/api/token HTTP/1.1\r\nX-metadata-token-ttl-seconds: 21600\r\nHost: 169.254.169.254\r\n\r\n";
        let responses = stack.process(&guest_data(101, server_isn + 1, req));

        let psh_pkt = responses
            .iter()
            .find(|p| tcp_flags(p) & TCP_PSH != 0)
            .expect("Should have a PSH|ACK response packet");
        let body = tcp_payload(psh_pkt);
        let resp_str = std::str::from_utf8(&body).unwrap();
        assert!(
            resp_str.contains("200 OK"),
            "PUT token should return 200, got: {}",
            resp_str
        );

        // Token is in the response body after the blank line.
        let body_start = resp_str.find("\r\n\r\n").unwrap() + 4;
        let token = resp_str[body_start..].trim();
        assert!(!token.is_empty(), "Response token must not be empty");
        assert!(
            store.lock().unwrap().validate_token(token),
            "Token returned by PUT should be valid in the store"
        );
    }

    #[test]
    fn test_unknown_connection_sends_rst() {
        let mut stack = MmdsTcpStack::new(make_v1_store());
        // Send a PSH|ACK with no prior SYN — should trigger RST.
        let stray = guest_data(999, 1000, b"GET / HTTP/1.1\r\n\r\n");
        let responses = stack.process(&stray);
        assert_eq!(responses.len(), 1);
        assert_ne!(
            tcp_flags(&responses[0]) & TCP_RST,
            0,
            "Expected RST for unknown connection"
        );
    }
}
