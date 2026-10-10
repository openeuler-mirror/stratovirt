// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{bail, Result};
use byteorder::{BigEndian, ByteOrder};
use log::warn;

use crate::aio::{get_iov_size, iov_from_buf_direct, iov_to_buf_direct, Iovec};
use crate::byte_code::ByteCode;

const ETH_HLEN: usize = libc::ETH_HLEN as usize;
const ETH_ALEN: usize = libc::ETH_ALEN as usize;
const ETH_PROTO_OFFSET: usize = 12;
const ETH_P_ARP: u16 = libc::ETH_P_ARP as u16;
// data length of arp protocol
const ARP_DATA_LEN: usize = 28;
// source mac address offset in arp data
const ARP_SRC_MAC: usize = 8;
// destination mac address offset in arp data
const ARP_DST_MAC: usize = 18;

#[repr(C, packed(1))]
#[derive(Default, Clone)]
struct EthHdr {
    pub dst_addr: [u8; ETH_ALEN],
    pub src_addr: [u8; ETH_ALEN],
    pub ether_type: [u8; 2],
}

impl ByteCode for EthHdr {}

impl EthHdr {
    fn set_dst_addr(&mut self, mac: &[u8; ETH_ALEN]) {
        self.dst_addr.clone_from_slice(mac);
    }

    fn set_src_addr(&mut self, mac: &[u8; ETH_ALEN]) {
        self.src_addr.clone_from_slice(mac);
    }
}

pub trait Macnat {
    // Handle mac nat for rx packet. Return None if the packet should be dropped.
    fn handle_rx_packet(
        &self,
        iovecs: &[Iovec],
        offset: usize,
        packet_len: usize,
        guest_mac: &[u8; ETH_ALEN],
        host_mac: &[u8; ETH_ALEN],
    ) -> Result<Option<Vec<u8>>>;
    // Minimal length of rx packet to do mac nat.
    fn rx_min_len(&self) -> usize;
    // Handle mac nat for tx packet. Return true if the packet should be dropped.
    fn handle_tx_packet(
        &self,
        iovecs: &[Iovec],
        offset: usize,
        host_mac: &[u8; ETH_ALEN],
    ) -> Result<bool>;
}

pub struct IpvtapMacnat;

impl Macnat for IpvtapMacnat {
    fn handle_rx_packet(
        &self,
        iovecs: &[Iovec],
        offset: usize,
        packet_len: usize,
        guest_mac: &[u8; ETH_ALEN],
        host_mac: &[u8; ETH_ALEN],
    ) -> Result<Option<Vec<u8>>> {
        let eth_packet_len = offset + ETH_HLEN;
        if packet_len < eth_packet_len {
            warn!(
                "Drop truncated ethernet packet: actual data len {} is less than request len {}",
                packet_len, eth_packet_len
            );
            return Ok(None);
        }

        let mut buf = Self::buf_from_iov(iovecs, eth_packet_len)?;
        let proto = BigEndian::read_u16(&buf[offset + ETH_PROTO_OFFSET..]);
        let required_len = match proto {
            ETH_P_ARP => offset + ETH_HLEN + ARP_DATA_LEN,
            _ => eth_packet_len,
        };
        if packet_len < required_len {
            warn!(
                "Drop truncated rx packet: actual data len {} is less than request len {}",
                packet_len, required_len
            );
            return Ok(None);
        }
        if required_len > buf.len() {
            buf = Self::buf_from_iov(iovecs, required_len)?;
        }

        let ether_buf = &mut buf[offset..];
        if proto == ETH_P_ARP {
            Self::handle_rx_arp(&mut ether_buf[ETH_HLEN..], guest_mac, host_mac);
        }

        // Replace destination mac address if not broadcast or multicast.
        if ether_buf[0] & 0x1 == 0 {
            let mut ethhdr = EthHdr::from_bytes(&ether_buf[..ETH_HLEN]).unwrap();
            ethhdr.set_dst_addr(guest_mac);
            ether_buf[..ETH_HLEN].copy_from_slice(ethhdr.as_bytes());
            // SAFETY: the buffer came from iovces so it's safe to copy back to iovecs.
            unsafe { iov_from_buf_direct(iovecs, &buf)? };
        }
        Ok(Some(buf))
    }

    fn rx_min_len(&self) -> usize {
        ETH_HLEN
    }

    fn handle_tx_packet(
        &self,
        iovecs: &[Iovec],
        offset: usize,
        host_mac: &[u8; ETH_ALEN],
    ) -> Result<bool> {
        // Read the ethernet header first. A short ethernet frame is valid input here because
        // padding to the minimum on-wire frame size can be added by a lower network layer.
        let mut buf = Self::buf_from_iov(iovecs, offset + ETH_HLEN)?;

        let proto = BigEndian::read_u16(&buf[offset + ETH_PROTO_OFFSET..]);
        if proto == ETH_P_ARP {
            // The ARP hardware address fields are only present in a complete ARP packet.
            let arp_packet_len = offset + ETH_HLEN + ARP_DATA_LEN;
            let actual_len = get_iov_size(iovecs);
            if actual_len < arp_packet_len as u64 {
                warn!(
                    "Drop truncated ARP packet: actual data len {} is less than request len {}",
                    actual_len, arp_packet_len
                );
                return Ok(true);
            }
            buf = Self::buf_from_iov(iovecs, arp_packet_len)?;
            Self::handle_tx_arp(&mut buf[offset + ETH_HLEN..], host_mac);
        }

        let ether_buf = &mut buf[offset..];
        let mut ethhdr = EthHdr::from_bytes(&ether_buf[..ETH_HLEN]).unwrap();
        if ethhdr.src_addr[0] & 0x1 == 0 {
            ethhdr.set_src_addr(host_mac);
            ether_buf[..ETH_HLEN].copy_from_slice(ethhdr.as_bytes());
            // SAFETY: the buffer came from iovces so it's safe to copy back to iovecs.
            unsafe { iov_from_buf_direct(iovecs, &buf)? };
        }
        Ok(false)
    }
}

impl IpvtapMacnat {
    fn buf_from_iov(iovecs: &[Iovec], buf_len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; buf_len];
        // SAFETY: `iovecs` are valid and checked by virtio-net.
        let len = unsafe { iov_to_buf_direct(iovecs, 0, &mut buf)? };
        if buf_len != len {
            bail!(
                "the actual data len {} is less than request len {}",
                len,
                buf_len
            );
        }
        Ok(buf)
    }

    fn handle_rx_arp(arp: &mut [u8], guest_mac: &[u8; ETH_ALEN], host_mac: &[u8; ETH_ALEN]) {
        if &arp[ARP_DST_MAC..ARP_DST_MAC + ETH_ALEN] == host_mac {
            arp[ARP_DST_MAC..ARP_DST_MAC + ETH_ALEN].copy_from_slice(guest_mac);
        }
    }

    fn handle_tx_arp(arp: &mut [u8], host_mac: &[u8; ETH_ALEN]) {
        arp[ARP_SRC_MAC..ARP_SRC_MAC + ETH_ALEN].copy_from_slice(host_mac);
    }
}
