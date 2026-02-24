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

use crate::aio::{iov_from_buf_direct, iov_to_buf_direct, Iovec};
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
    // Handle mac nat for rx packet.
    fn handle_rx_packet(
        &self,
        iovecs: &[Iovec],
        offset: usize,
        guest_mac: &[u8; ETH_ALEN],
        host_mac: &[u8; ETH_ALEN],
    ) -> Result<Vec<u8>>;
    // Minimal length of rx packet to do mac nat.
    fn rx_min_len(&self) -> usize;
    // Handle mac nat for tx packet.
    fn handle_tx_packet(
        &self,
        iovecs: &[Iovec],
        offset: usize,
        host_mac: &[u8; ETH_ALEN],
    ) -> Result<()>;
}

pub struct IpvtapMacnat;

impl Macnat for IpvtapMacnat {
    fn handle_rx_packet(
        &self,
        iovecs: &[Iovec],
        offset: usize,
        guest_mac: &[u8; ETH_ALEN],
        host_mac: &[u8; ETH_ALEN],
    ) -> Result<Vec<u8>> {
        let mut buf = Self::buf_from_iov(iovecs, offset + ETH_HLEN + ARP_DATA_LEN)?;

        let ether_buf = &mut buf[offset..];
        let proto = BigEndian::read_u16(&ether_buf[ETH_PROTO_OFFSET..]);
        if proto == ETH_P_ARP {
            Self::handle_rx_arp(&mut ether_buf[ETH_HLEN..], guest_mac, host_mac);
        }

        // Replace destination mac address if not broadcast or multicast.
        if ether_buf[0] & 0x1 == 0 {
            let ethhdr = EthHdr::from_mut_bytes(&mut ether_buf[..ETH_HLEN]).unwrap();
            ethhdr.set_dst_addr(guest_mac);
            // SAFETY: the buffer came from iovces so it's safe to copy back to iovecs.
            unsafe { iov_from_buf_direct(iovecs, &buf)? };
        }
        Ok(buf)
    }

    fn rx_min_len(&self) -> usize {
        ETH_HLEN + ARP_DATA_LEN
    }

    fn handle_tx_packet(
        &self,
        iovecs: &[Iovec],
        offset: usize,
        host_mac: &[u8; ETH_ALEN],
    ) -> Result<()> {
        let mut buf = Self::buf_from_iov(iovecs, offset + ETH_HLEN + ARP_DATA_LEN)?;

        let ether_buf = &mut buf[offset..];
        let proto = BigEndian::read_u16(&ether_buf[ETH_PROTO_OFFSET..]);
        if proto == ETH_P_ARP {
            Self::handle_tx_arp(&mut ether_buf[ETH_HLEN..], host_mac);
        }

        let ethhdr = EthHdr::from_mut_bytes(&mut ether_buf[..ETH_HLEN]).unwrap();
        if ethhdr.src_addr[0] & 0x1 == 0 {
            ethhdr.set_src_addr(host_mac);
            // SAFETY: the buffer came from iovces so it's safe to copy back to iovecs.
            unsafe { iov_from_buf_direct(iovecs, &buf)? };
        }
        Ok(())
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
