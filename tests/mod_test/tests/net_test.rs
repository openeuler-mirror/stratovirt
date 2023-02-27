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

use rand::Rng;
use serde_json::json;
use std::cell::RefCell;
use std::mem::size_of;
use std::process::Command;
use std::rc::Rc;
use std::thread::sleep;
use std::time;
use util::byte_code::ByteCode;
use util::offset_of;

use mod_test::libdriver::machine::TestStdMachine;
use mod_test::libdriver::malloc::GuestAllocator;
use mod_test::libdriver::virtio::{
    TestVirtQueue, TestVringDescEntry, VirtioDeviceOps, VringUsed, VringUsedElem,
    VIRTIO_CONFIG_S_DRIVER_OK, VIRTIO_CONFIG_S_NEEDS_RESET, VIRTIO_F_VERSION_1,
    VIRTIO_RING_F_EVENT_IDX, VRING_DESC_SIZE,
};
use mod_test::libdriver::virtio_pci_modern::TestVirtioPciDev;
use mod_test::libtest::{test_init, TestState};

/// Device handles packets with partial checksum.
const VIRTIO_NET_F_CSUM: u32 = 0;
/// Driver handles packets with partial checksum.
const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;
/// Driver can receive TSOv4.
const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
/// Driver can receive TSOv6.
const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
/// Driver can receive UFO.
const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
/// Device can receive TSOv4.
const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
/// Device can receive TSOv6.
const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
/// Device can receive UFO.
const VIRTIO_NET_F_HOST_UFO: u32 = 14;
/// Control channel is available.
const VIRTIO_NET_F_CTRL_VQ: u32 = 17;
/// Control channel RX mode support.
const VIRTIO_NET_F_CTRL_RX: u32 = 18;
/// Control channel VLAN filtering.
const VIRTIO_NET_F_CTRL_VLAN: u32 = 19;
/// Extra RX mode control support.
const VIRTIO_NET_F_CTRL_RX_EXTRA: u32 = 20;
/// Set Mac Address through control channel.
const VIRTIO_NET_F_CTRL_MAC_ADDR: u32 = 23;

/// The device sets control ok status to driver.
pub const VIRTIO_NET_OK: u8 = 0;
/// The device sets control err status to driver.
pub const VIRTIO_NET_ERR: u8 = 1;

/// Driver can send control commands.
pub const VIRTIO_NET_CTRL_RX: u8 = 0;
/// Control commands for promiscuous mode.
pub const VIRTIO_NET_CTRL_RX_PROMISC: u8 = 0;
/// Control commands for all-multicast receive.
pub const VIRTIO_NET_CTRL_RX_ALLMULTI: u8 = 1;
/// Control commands for all-unicast receive.
pub const VIRTIO_NET_CTRL_RX_ALLUNI: u8 = 2;
/// Control commands for suppressing multicast receive.
pub const VIRTIO_NET_CTRL_RX_NOMULTI: u8 = 3;
/// Control commands for suppressing unicast receive.
pub const VIRTIO_NET_CTRL_RX_NOUNI: u8 = 4;
/// Control commands for suppressing broadcast receive.
pub const VIRTIO_NET_CTRL_RX_NOBCAST: u8 = 5;

/// The driver can send control commands for MAC address filtering.
pub const VIRTIO_NET_CTRL_MAC: u8 = 1;
/// The driver sets the unicast/multicast addresse table.
pub const VIRTIO_NET_CTRL_MAC_TABLE_SET: u8 = 0;
/// The driver sets the default MAC address which rx filtering accepts.
pub const VIRTIO_NET_CTRL_MAC_ADDR_SET: u8 = 1;

/// The driver can send control commands for vlan filtering.
pub const VIRTIO_NET_CTRL_VLAN: u8 = 2;
/// The driver adds a vlan id to the vlan filtering table.
pub const VIRTIO_NET_CTRL_VLAN_ADD: u8 = 0;
/// The driver adds a vlan id from the vlan filtering table.
pub const VIRTIO_NET_CTRL_VLAN_DEL: u8 = 1;

/// Driver configure the class before enabling virtqueue.
pub const VIRTIO_NET_CTRL_MQ: u8 = 4;
/// Driver configure the command before enabling virtqueue.
pub const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u16 = 0;
/// The minimum pairs of multiple queue.
pub const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN: u16 = 1;
/// The maximum pairs of multiple queue.
pub const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX: u16 = 0x8000;
/// Support more than one virtqueue.
pub const VIRTIO_BLK_F_MQ: u32 = 12;

const QUEUE_SIZE_NET: u16 = 256;

const DEFAULT_NET_FEATURES: u64 = 1 << VIRTIO_F_VERSION_1
    | 1 << VIRTIO_NET_F_CSUM
    | 1 << VIRTIO_NET_F_GUEST_CSUM
    | 1 << VIRTIO_NET_F_GUEST_TSO4
    | 1 << VIRTIO_NET_F_GUEST_TSO6
    | 1 << VIRTIO_NET_F_GUEST_UFO
    | 1 << VIRTIO_NET_F_HOST_TSO4
    | 1 << VIRTIO_NET_F_HOST_TSO6
    | 1 << VIRTIO_NET_F_HOST_UFO
    | 1 << VIRTIO_NET_F_CTRL_RX
    | 1 << VIRTIO_NET_F_CTRL_VLAN
    | 1 << VIRTIO_NET_F_CTRL_RX_EXTRA
    | 1 << VIRTIO_NET_F_CTRL_MAC_ADDR
    | 1 << VIRTIO_NET_F_CTRL_VQ
    | 1 << VIRTIO_RING_F_EVENT_IDX;

const TIMEOUT_US: u64 = 15 * 1000 * 1000;

const VIRTIO_NET_HDR_SIZE: usize = size_of::<VirtioNetHdr>();
/// dest_mac(6), source_mac(6), ether_type(2).
const ETHERNET_HDR_SIZE: usize = 14;
/// Arp packet header.
const ARP_HDR_SIZE: usize = 8;

/// The maximum incoming packet(tcp/udp): 65536 byte,
/// plus ethernet header: 14 byte,
/// plus virtio_net_hdr: 12 byte.
const MAX_PACKET_LEN: u64 = 65562;

/// The Mac Address length.
const MAC_ADDR_LEN: usize = 6;
/// The source mac address in arp packet.
const ARP_SOURCE_MAC: [u8; MAC_ADDR_LEN] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const CMD_LINE_MAC: [u8; MAC_ADDR_LEN] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x57];
const MAX_MAC_TABLE_LEN: usize = 64;
const TEST_MAC_ADDR_NUMS: u8 = 2;

static USED_ELEM_SIZE: u64 = size_of::<VringUsedElem>() as u64;

#[repr(C, packed)]
pub struct VirtioNetConfig {
    /// Mac Address.
    pub mac: [u8; MAC_ADDR_LEN],
    /// Device status.
    pub status: u16,
    /// Maximum number of each of transmit and receive queues.
    pub max_virtqueue_pairs: u16,
    /// Maximum Transmission Unit.
    pub mtu: u16,
    /// Speed, in units of 1Mb.
    pub speed: u32,
    /// 0x00 - half duplex
    /// 0x01 - full duplex
    pub duplex: u8,
}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct CtrlHdr {
    class: u8,
    cmd: u8,
}
impl ByteCode for CtrlHdr {}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct CtrlMacAddr {
    ctrl_hdr: CtrlHdr,
    mac: [u8; MAC_ADDR_LEN],
    ack: u8,
}
impl ByteCode for CtrlMacAddr {}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct CtrlRxInfo {
    ctrl_hdr: CtrlHdr,
    switch: u8,
    ack: u8,
}
impl CtrlRxInfo {
    pub fn new(class: u8, cmd: u8, switch: u8) -> Self {
        CtrlRxInfo {
            ctrl_hdr: CtrlHdr { class, cmd },
            switch,
            ack: 0xff,
        }
    }
}
impl ByteCode for CtrlRxInfo {}

#[repr(C, packed)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct CtrlVlanInfo {
    ctrl_hdr: CtrlHdr,
    vid: u16,
    ack: u8,
}
impl CtrlVlanInfo {
    pub fn new(class: u8, cmd: u8, vid: u16) -> Self {
        CtrlVlanInfo {
            ctrl_hdr: CtrlHdr { class, cmd },
            vid,
            ack: 0xff,
        }
    }
}
impl ByteCode for CtrlVlanInfo {}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct EthernetHdr {
    dst_mac: [u8; MAC_ADDR_LEN],
    src_mac: [u8; MAC_ADDR_LEN],
    // 0x0800: IP
    // 0x0806: ARP
    // 0x86dd: IPV6
    // 0x0810: 802.1Q Tag, it has vlan id
    e_type: [u8; 2],
}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct EthernetHdrVlan {
    dst_mac: [u8; MAC_ADDR_LEN],
    src_mac: [u8; MAC_ADDR_LEN],
    tpid: [u8; 2],
    vlan_id: [u8; 2],
    // 0x0800: IP
    // 0x0806: ARP
    // 0x86dd: IPV6
    // 0x0810: 802.1Q Tag, it has vlan id
    e_type: [u8; 2],
}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct ArpPacket {
    h_type: [u8; 2],
    p_type: [u8; 2],
    h_len: u8,
    p_len: u8,
    op: [u8; 2],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct ArpRequestPacket {
    net_hdr: VirtioNetHdr,
    eth_hdr: EthernetHdr,
    arp_packet: ArpPacket,
}
impl ByteCode for ArpRequestPacket {}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy, Default)]
struct ArpRequestPacketVlan {
    net_hdr: VirtioNetHdr,
    eth_hdr: EthernetHdrVlan,
    arp_packet: ArpPacket,
}
impl ByteCode for ArpRequestPacketVlan {}

#[repr(C)]
#[allow(unused)]
#[derive(Clone, Copy)]
struct MacAddress {
    address: [u8; MAC_ADDR_LEN],
}
impl ByteCode for MacAddress {}
impl Default for MacAddress {
    fn default() -> Self {
        MacAddress {
            address: [0; MAC_ADDR_LEN],
        }
    }
}

#[repr(C, packed(2))]
#[allow(unused)]
#[derive(Clone, Copy)]
struct CtrlMacTableReq {
    ctrl_hdr: CtrlHdr,
    uni_entries: u32,
    uni_macs: [MacAddress; MAX_MAC_TABLE_LEN + 1],
    mul_entries: u32,
    mul_macs: [MacAddress; MAX_MAC_TABLE_LEN + 1],
    ack: u8,
}
impl ByteCode for CtrlMacTableReq {}
impl Default for CtrlMacTableReq {
    fn default() -> Self {
        CtrlMacTableReq {
            ctrl_hdr: CtrlHdr::default(),
            uni_entries: 0,
            uni_macs: [MacAddress::default(); MAX_MAC_TABLE_LEN + 1],
            mul_entries: 0,
            mul_macs: [MacAddress::default(); MAX_MAC_TABLE_LEN + 1],
            ack: 0xff,
        }
    }
}

/// Packet header.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}
impl ByteCode for VirtioNetHdr {}

/// Execute cmd used to create br/tap.
fn execute_cmd(cmd: String) {
    let args = cmd.split(' ').collect::<Vec<&str>>();
    if args.len() <= 0 {
        return;
    }

    let mut cmd_exe = Command::new(args[0]);
    for i in 1..args.len() {
        cmd_exe.arg(args[i]);
    }

    let output = cmd_exe
        .output()
        .expect(format!("Failed to execute {}", cmd).as_str());
    assert!(output.status.success());
}

fn create_tap(id: u8, mq: bool) {
    let br_name = "qbr".to_string() + &id.to_string();
    let tap_name = "qtap".to_string() + &id.to_string();
    execute_cmd("brctl addbr ".to_string() + &br_name);
    if mq {
        execute_cmd(
            "ip tuntap add ".to_string() + &tap_name + &" mode tap multi_queue".to_string(),
        );
    } else {
        execute_cmd("ip tuntap add ".to_string() + &tap_name + &" mode tap".to_string());
    }
    execute_cmd("brctl addif ".to_string() + &br_name + &" ".to_string() + &tap_name);
    execute_cmd("ip link set ".to_string() + &br_name + &" up".to_string());
    execute_cmd("ip link set ".to_string() + &tap_name + &" up".to_string());
    execute_cmd(
        "ip address add ".to_string()
            + &id.to_string()
            + &".1.1.".to_string()
            + &id.to_string()
            + &"/24 dev ".to_string()
            + &br_name,
    );
}

fn clear_tap(id: u8, mq: bool) {
    let br_name = "qbr".to_string() + &id.to_string();
    let tap_name = "qtap".to_string() + &id.to_string();
    execute_cmd("ip link set ".to_string() + &tap_name + &" down".to_string());
    execute_cmd("ip link set ".to_string() + &br_name + &" down".to_string());
    if mq {
        execute_cmd(
            "ip tuntap del ".to_string() + &tap_name + &" mode tap multi_queue".to_string(),
        );
    } else {
        execute_cmd("ip tuntap del ".to_string() + &tap_name + &" mode tap".to_string());
    }
    execute_cmd("brctl delbr ".to_string() + &br_name);
}

#[allow(unused)]
pub fn create_net(
    id: u8,
    mq: bool,
    num_queues: u16,
    with_mac: bool,
    iothread: bool,
) -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
) {
    let pci_slot: u8 = 0x4;
    let pci_fn: u8 = 0x0;
    let mut extra_args: Vec<&str> = Vec::new();

    let mut args: Vec<&str> = "-machine virt".split(' ').collect();
    extra_args.append(&mut args);

    let mut iothread_arg = "";
    if iothread {
        let mut args: Vec<&str> = "-object iothread,id=iothread1".split(' ').collect();
        extra_args.append(&mut args);
        iothread_arg = ",iothread=iothread1";
    }
    // Multi-queue command line.
    let mut mq_flag = "";
    let mut mq_queues = "".to_string();
    if mq {
        mq_flag = ",mq=on";
        mq_queues = ",queues=".to_string() + &num_queues.to_string();
    }
    let mut mac_address = "";
    if with_mac {
        // Same as CMD_LINE_MAC.
        mac_address = ",mac=52:54:00:12:34:57";
    }
    let net_pci_args = format!(
        "-device {},id=net0,netdev=netdev0,bus=pcie.{},addr={}.0{}{}{}",
        "virtio-net-pci", pci_fn, pci_slot, mq_flag, mac_address, iothread_arg,
    );
    args = net_pci_args[..].split(' ').collect();
    extra_args.append(&mut args);

    let net_args =
        String::from("-netdev tap,id=netdev0,ifname=qtap") + &id.to_string() + &mq_queues;
    args = net_args.split(' ').collect();
    extra_args.append(&mut args);

    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();
    let virtio_net = Rc::new(RefCell::new(TestVirtioPciDev::new(machine.pci_bus.clone())));
    virtio_net.borrow_mut().init(pci_slot, pci_fn);

    (virtio_net, test_state, allocator)
}

fn set_up(
    id: u8,
    mq: bool,
    num_queues: u16,
    with_mac: bool,
) -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
) {
    create_tap(id, mq);
    create_net(id, mq, num_queues, with_mac, false)
}

// Set the iothread argument in comand line.
fn set_up_iothread(
    id: u8,
    mq: bool,
    num_queues: u16,
    with_mac: bool,
) -> (
    Rc<RefCell<TestVirtioPciDev>>,
    Rc<RefCell<TestState>>,
    Rc<RefCell<GuestAllocator>>,
) {
    create_tap(id, mq);
    create_net(id, mq, num_queues, with_mac, true)
}

fn tear_down(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    id: u8,
    mq: bool,
) {
    net.borrow_mut().destroy_device(alloc.clone(), vqs);
    test_state.borrow_mut().stop();
    clear_tap(id, mq);
}

/// Alloc space for rx virtqueue.
fn fill_rx_vq(
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vq: Rc<RefCell<TestVirtQueue>>,
) {
    let size = vq.borrow().size;
    for _ in 0..size {
        let addr = alloc.borrow_mut().alloc(MAX_PACKET_LEN).try_into().unwrap();
        vq.borrow_mut()
            .add(test_state.clone(), addr, MAX_PACKET_LEN as u32, true);
    }
    vq.borrow().set_used_event(test_state.clone(), 0);
}

fn init_net_device(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    features: u64,
    num_queues: usize,
) -> Vec<Rc<RefCell<TestVirtQueue>>> {
    net.borrow_mut().reset();
    net.borrow_mut().set_acknowledge();
    net.borrow_mut().set_driver();
    net.borrow_mut().negotiate_features(features);
    net.borrow_mut().set_features_ok();
    net.borrow_mut().pci_dev.enable_msix(None);
    net.borrow_mut()
        .setup_msix_configuration_vector(alloc.clone(), 0);
    let vqs = net
        .borrow_mut()
        .init_virtqueue(test_state.clone(), alloc.clone(), num_queues);
    // vqs[0] is rx queue.
    fill_rx_vq(test_state.clone(), alloc.clone(), vqs[0].clone());
    net.borrow().set_driver_ok();

    vqs
}

fn check_arp_mac(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    arp_request: &[u8],
    need_reply: bool,
) {
    let mut start = 0_u64;
    let start_time = time::Instant::now();
    let timeout_us = time::Duration::from_micros(TIMEOUT_US);
    let timeout_us_no_reply = time::Duration::from_micros(TIMEOUT_US / 5);
    loop {
        if need_reply {
            assert!(time::Instant::now() - start_time < timeout_us);
            if !net.borrow().queue_was_notified(vqs[0].clone()) {
                continue;
            }
        } else if time::Instant::now() - start_time > timeout_us_no_reply {
            return;
        }

        let idx = test_state
            .borrow()
            .readw(vqs[0].borrow().used + offset_of!(VringUsed, idx) as u64);
        for i in start..idx as u64 {
            let len = test_state.borrow().readw(
                vqs[0].borrow().used
                    + offset_of!(VringUsed, ring) as u64
                    + i * USED_ELEM_SIZE
                    + offset_of!(VringUsedElem, len) as u64,
            );
            if len == arp_request.len() as u16 {
                let id = test_state.borrow().readw(
                    vqs[0].borrow().used + offset_of!(VringUsed, ring) as u64 + i * USED_ELEM_SIZE,
                );

                let addr = test_state
                    .borrow()
                    .readq(vqs[0].borrow().desc + id as u64 * VRING_DESC_SIZE);
                let packets = test_state.borrow().memread(addr, len as u64);
                let src_mac_pos = VIRTIO_NET_HDR_SIZE + ETHERNET_HDR_SIZE + ARP_HDR_SIZE;
                let dst_mac_pos = src_mac_pos + 10;
                if arp_request[src_mac_pos..src_mac_pos + MAC_ADDR_LEN]
                    == packets[dst_mac_pos..dst_mac_pos + MAC_ADDR_LEN]
                {
                    if need_reply {
                        return;
                    } else {
                        assert!(false);
                    }
                }
            }
        }
        start = idx as u64;
    }
}

fn get_arp_request(id: u8) -> ArpRequestPacket {
    ArpRequestPacket {
        net_hdr: VirtioNetHdr::default(),
        eth_hdr: EthernetHdr {
            dst_mac: [0xff; MAC_ADDR_LEN],
            src_mac: ARP_SOURCE_MAC,
            e_type: [0x08, 0x06],
        },
        arp_packet: ArpPacket {
            h_type: [0x00, 0x01],
            p_type: [0x08, 0x00],
            h_len: 0x06,
            p_len: 0x04,
            op: [0x00, 0x01],
            src_mac: ARP_SOURCE_MAC,
            src_ip: [id, 0x01, 0x01, id + 1],
            dst_mac: [0x00; MAC_ADDR_LEN],
            dst_ip: [id, 0x01, 0x01, id],
        },
    }
}

fn get_arp_request_vlan(id: u8) -> ArpRequestPacketVlan {
    ArpRequestPacketVlan {
        net_hdr: VirtioNetHdr::default(),
        eth_hdr: EthernetHdrVlan {
            dst_mac: [0xff; MAC_ADDR_LEN],
            src_mac: ARP_SOURCE_MAC,
            tpid: [0x81, 0x00],
            vlan_id: [0x08, 0x01],
            e_type: [0x08, 0x06],
        },
        arp_packet: ArpPacket {
            h_type: [0x00, 0x01],
            p_type: [0x08, 0x00],
            h_len: 0x06,
            p_len: 0x04,
            op: [0x00, 0x01],
            src_mac: ARP_SOURCE_MAC,
            src_ip: [id, 0x01, 0x01, id + 1],
            dst_mac: [0x00; MAC_ADDR_LEN],
            dst_ip: [id, 0x01, 0x01, id],
        },
    }
}

fn send_request(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    request: &[u8],
) {
    let length = request.len() as u64;
    let addr = alloc.borrow_mut().alloc(length).try_into().unwrap();

    let k_bytes = 1024;
    let num_k = length / k_bytes;
    let mut offset;
    // write 1024 bytes once.
    for i in 0..num_k {
        offset = i * k_bytes;
        test_state.borrow().memwrite(
            addr + offset,
            &request[offset as usize..(offset + k_bytes) as usize],
        );
    }
    let res = length % k_bytes;
    if res > 0 {
        offset = num_k * k_bytes;
        test_state
            .borrow()
            .memwrite(addr + offset, &request[offset as usize..]);
    }
    let free_head = vqs[1]
        .borrow_mut()
        .add(test_state.clone(), addr, request.len() as u32, false);
    net.borrow().virtqueue_notify(vqs[1].clone());
    net.borrow().poll_used_elem(
        test_state.clone(),
        vqs[1].clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );
}

fn send_arp_request(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    arp_request: &[u8],
    need_reply: bool,
) {
    send_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &arp_request,
    );
    check_arp_mac(
        net.clone(),
        test_state.clone(),
        vqs.clone(),
        &arp_request,
        need_reply,
    );
}

/// Send and receive packet test.
/// TestStep:
///   1. Init device.
///   2. Send ARP packet and check the reply.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_net_rx_tx_test() {
    let id = 1 * TEST_MAC_ADDR_NUMS;
    let (net, test_state, alloc) = set_up(id, false, 0, false);

    // Three virtqueues: tx/rx/ctrl.
    let vqs = init_net_device(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        DEFAULT_NET_FEATURES,
        3,
    );

    let arp_request = get_arp_request(id);
    send_arp_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &arp_request.as_bytes(),
        true,
    );

    tear_down(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        id,
        false,
    );
}

/// Send and receive packet test with iothread.
/// TestStep:
///   1. Init device.
///   2. Send ARP packet and check the reply.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_net_rx_tx_test_iothread() {
    let id = 2 * TEST_MAC_ADDR_NUMS;
    let (net, test_state, alloc) = set_up_iothread(id, false, 0, false);

    // Three virtqueues: tx/rx/ctrl.
    let vqs = init_net_device(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        DEFAULT_NET_FEATURES,
        3,
    );

    let arp_request = get_arp_request(id);
    send_arp_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &arp_request.as_bytes(),
        true,
    );

    tear_down(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        id,
        false,
    );
}

/// Test the control mq command.
/// TestStep:
///   1. Init device: enable multi-queue and VIRTIO_NET_CTRL_MQ.
///   2. Send VIRTIO_NET_CTRL_MQ to set vq pairs:
///     1) set normal vq pairs;
///     2) set invalid request length;
///     3) set invalid request cmd;
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_net_ctrl_mq_test() {
    let id = 3 * TEST_MAC_ADDR_NUMS;
    let queue_pairs: u16 = 4;
    let queues: usize = 2 * queue_pairs as usize + 1;
    let (net, test_state, alloc) = set_up(id, true, queue_pairs, false);

    // Three virtqueues: tx/rx/ctrl.
    let vqs = init_net_device(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        DEFAULT_NET_FEATURES,
        queues,
    );

    // (test_type, queue_pairs, ack)
    // test_type:
    //  0 - normal request
    //  1 - invalid request length
    //  2 - invalid cmd
    let reqs = [
        (0, queue_pairs, VIRTIO_NET_OK),
        (0, u16::MAX, VIRTIO_NET_ERR),
        (0, 0, VIRTIO_NET_ERR),
        (1, queue_pairs, VIRTIO_NET_ERR),
        (2, queue_pairs, VIRTIO_NET_ERR),
    ];

    for (test_type, vq_pairs, status) in reqs {
        let ack: u8 = 0xff;
        // The message: CtrlHdr, vq_pairs, ack.
        let addr = alloc
            .borrow_mut()
            .alloc(size_of::<CtrlHdr>() as u64 + 2 + 1)
            .try_into()
            .unwrap();

        let mut cmd = VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET as u8;
        if test_type == 2 {
            cmd = u8::MAX;
        }
        let ctrl_hdr = CtrlHdr {
            class: VIRTIO_NET_CTRL_MQ,
            cmd,
        };
        test_state.borrow().memwrite(addr, &ctrl_hdr.as_bytes());
        test_state
            .borrow()
            .writew(addr + size_of::<CtrlHdr>() as u64, vq_pairs);
        test_state
            .borrow()
            .writeb(addr + size_of::<CtrlHdr>() as u64 + 2, ack);

        let ctrl_vq = &vqs[queues - 1];
        // CtrlHdr + vq_pairs.
        let mut len = size_of::<CtrlHdr>() as u32 + 2;
        if test_type == 1 {
            len -= 1;
        }

        let data_entries: Vec<TestVringDescEntry> = vec![
            TestVringDescEntry {
                data: addr,
                len,
                write: false,
            },
            TestVringDescEntry {
                data: addr + size_of::<CtrlHdr>() as u64 + 2,
                len: 1,
                write: true,
            },
        ];
        let free_head = ctrl_vq
            .borrow_mut()
            .add_chained(test_state.clone(), data_entries);
        net.borrow()
            .kick_virtqueue(test_state.clone(), ctrl_vq.clone());

        net.borrow().poll_used_elem(
            test_state.clone(),
            ctrl_vq.clone(),
            free_head,
            TIMEOUT_US,
            &mut None,
            true,
        );

        let ack = test_state
            .borrow()
            .readb(addr + size_of::<CtrlHdr>() as u64 + 2);
        assert_eq!(ack, status);
    }

    tear_down(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        id,
        true,
    );
}

/// Write or Read mac address from device config.
fn net_config_mac_rw(
    net: Rc<RefCell<TestVirtioPciDev>>,
    mac: Option<&[u8; MAC_ADDR_LEN]>,
) -> [u8; MAC_ADDR_LEN] {
    if let Some(mac) = mac {
        for i in 0..MAC_ADDR_LEN {
            net.borrow()
                .config_writeb((offset_of!(VirtioNetConfig, mac) + i) as u64, mac[i]);
        }
    }

    let mut mac_read = [0_u8; MAC_ADDR_LEN];
    for i in 0..MAC_ADDR_LEN {
        mac_read[i] = net
            .borrow()
            .config_readb((offset_of!(VirtioNetConfig, mac) + i) as u64);
    }
    mac_read
}

/// Virtio net configure is not allowed to change except mac.
fn write_net_config_check(net: Rc<RefCell<TestVirtioPciDev>>, offset: u64, value: u64, size: u8) {
    let origin_value = net.borrow().config_readw(offset) as u64;
    assert_ne!(origin_value, value);
    match size {
        1 => net.borrow().config_writeb(offset, value as u8),
        2 => net.borrow().config_writew(offset, value as u16),
        4 => net.borrow().config_writel(offset, value as u32),
        _ => (),
    };
    let value = net.borrow().config_readw(offset) as u64;
    assert_eq!(origin_value, value);
}

/// Write value to virtio net configure, and check the write result.
/// TestStep:
///   1. Init device.
///   2. Write value to virtio net configure which can not be changed
///      except mac in some conditions.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_net_write_and_check_config() {
    let id = 4 * TEST_MAC_ADDR_NUMS;
    let queue_pairs: u16 = 1;
    let queues: usize = 2 * queue_pairs as usize + 1;

    let reqs = [
        DEFAULT_NET_FEATURES & !(1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_NET_F_CTRL_MAC_ADDR),
        DEFAULT_NET_FEATURES,
    ];
    for features in reqs {
        let (net, test_state, alloc) = set_up(id, false, queue_pairs, true);

        // Three virtqueues: tx/rx/ctrl.
        let vqs = init_net_device(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            features,
            queues,
        );

        // Get the mac address in the device configure space.
        let mac_origin = net_config_mac_rw(net.clone(), None);
        assert_eq!(mac_origin, CMD_LINE_MAC);

        // Write 0xff:0xff:0xff:0xff:0xff to virtio_net_config->mac.
        let mac = net_config_mac_rw(net.clone(), Some(&[0xff; MAC_ADDR_LEN]));
        if features & (1 << VIRTIO_F_VERSION_1) != 0 {
            assert_eq!(mac, mac_origin);
        } else {
            assert_eq!(mac, [0xff; MAC_ADDR_LEN]);
        }

        // Write abnornal value to virito_net_config.
        write_net_config_check(
            net.clone(),
            offset_of!(VirtioNetConfig, status) as u64,
            u16::MAX as u64,
            2,
        );
        write_net_config_check(
            net.clone(),
            offset_of!(VirtioNetConfig, max_virtqueue_pairs) as u64,
            u16::MAX as u64,
            2,
        );
        write_net_config_check(
            net.clone(),
            offset_of!(VirtioNetConfig, mtu) as u64,
            u16::MAX as u64,
            2,
        );
        write_net_config_check(
            net.clone(),
            offset_of!(VirtioNetConfig, speed) as u64,
            u32::MAX as u64,
            4,
        );
        write_net_config_check(
            net.clone(),
            offset_of!(VirtioNetConfig, duplex) as u64,
            u8::MAX as u64,
            1,
        );

        write_net_config_check(
            net.clone(),
            size_of::<VirtioNetConfig> as u64 + 1,
            u8::MAX as u64,
            1,
        );

        tear_down(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            id,
            false,
        );
    }
}

// Send request with control virtqueue.
fn send_ctrl_vq_request(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    ctrl_data: &[u8],
    ack: u8,
) {
    let ctrl_vq = &vqs[2];
    let addr = alloc
        .borrow_mut()
        .alloc(ctrl_data.len() as u64)
        .try_into()
        .unwrap();
    test_state.borrow().memwrite(addr, &ctrl_data);
    let data_entries: Vec<TestVringDescEntry> = vec![
        TestVringDescEntry {
            data: addr,
            len: ctrl_data.len() as u32 - 1,
            write: false,
        },
        TestVringDescEntry {
            data: addr + ctrl_data.len() as u64 - 1,
            len: 1,
            write: true,
        },
    ];
    let free_head = ctrl_vq
        .borrow_mut()
        .add_chained(test_state.clone(), data_entries);
    net.borrow()
        .kick_virtqueue(test_state.clone(), ctrl_vq.clone());

    net.borrow().poll_used_elem(
        test_state.clone(),
        ctrl_vq.clone(),
        free_head,
        TIMEOUT_US,
        &mut None,
        true,
    );

    let res_ack = test_state.borrow().readb(addr + ctrl_data.len() as u64 - 1);
    assert_eq!(res_ack, ack);
}

// Set uni_entries/mul_entries macs to unicast/multicast mac table.
fn ctrl_vq_set_mac_table(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    uni_entries: u32,
    mul_entries: u32,
    ack: u8,
) {
    let mut ctrl_mac_table = CtrlMacTableReq {
        ctrl_hdr: CtrlHdr {
            class: VIRTIO_NET_CTRL_MAC,
            cmd: VIRTIO_NET_CTRL_MAC_TABLE_SET,
        },
        uni_entries,
        uni_macs: [MacAddress::default(); MAX_MAC_TABLE_LEN + 1],
        mul_entries,
        ..CtrlMacTableReq::default()
    };

    for i in 0..uni_entries + mul_entries {
        let mut mac = MacAddress {
            address: ARP_SOURCE_MAC,
        };
        mac.address[MAC_ADDR_LEN - 1] += i as u8 + 1;
        if i < uni_entries {
            ctrl_mac_table.uni_macs[i as usize] = mac;
        } else {
            mac.address[0] += 1;
            ctrl_mac_table.mul_macs[(i - uni_entries) as usize] = mac;
        }
    }

    let mut ctrl_data: Vec<u8> = Vec::new();
    let mut offset = offset_of!(CtrlMacTableReq, uni_macs) + uni_entries as usize * MAC_ADDR_LEN;
    ctrl_data.append(&mut ctrl_mac_table.as_bytes()[..offset].to_vec());
    ctrl_data.append(&mut mul_entries.as_bytes().to_vec());
    offset = offset_of!(CtrlMacTableReq, mul_macs);
    ctrl_data.append(
        &mut ctrl_mac_table.as_bytes()[offset..offset + mul_entries as usize * MAC_ADDR_LEN]
            .to_vec(),
    );
    ctrl_data.append(&mut ctrl_mac_table.ack.as_bytes().to_vec());

    assert_eq!(
        11 + (uni_entries + mul_entries) as usize * MAC_ADDR_LEN,
        ctrl_data.len()
    );

    send_ctrl_vq_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &ctrl_data,
        ack,
    );
}

fn ctrl_vq_set_mac_address(
    net: Rc<RefCell<TestVirtioPciDev>>,
    test_state: Rc<RefCell<TestState>>,
    alloc: Rc<RefCell<GuestAllocator>>,
    vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
) {
    // Get the mac address in the device configure space.
    let mac_origin = net_config_mac_rw(net.clone(), None);
    assert_eq!(mac_origin, CMD_LINE_MAC);
    // Set mac address.
    let ctrl_mac_addr = CtrlMacAddr {
        ctrl_hdr: CtrlHdr {
            class: VIRTIO_NET_CTRL_MAC,
            cmd: VIRTIO_NET_CTRL_MAC_ADDR_SET,
        },
        mac: ARP_SOURCE_MAC,
        ack: 0xff,
    };
    send_ctrl_vq_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &ctrl_mac_addr.as_bytes(),
        VIRTIO_NET_OK,
    );
    // Check mac address result.
    let config_mac = net_config_mac_rw(net.clone(), None);
    assert_eq!(config_mac, ARP_SOURCE_MAC);
}

/// Test the control vlan command.
/// TestStep:
///   1. Init device with control vq.
///   2. Test the control vlan command:
///    1) add vid 0/0/1/0xfff/0xffff, success(ignore invalid/repeated value)
///    2) del vid 0/0/1/0xfff/0xffff, success(ignore invalid/repeated value)
///    3) invalid ctrl class and cmd, expect reply error
///    4) invalid ctrl cmd, expect reply error
///    5) invalid vid length, expect reply error
///   3. Send ARP packet and check the reply.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn virtio_net_ctrl_vlan_test() {
    let id = 5 * TEST_MAC_ADDR_NUMS;
    let queue_pairs: u16 = 1;
    let queues: usize = 2 * queue_pairs as usize + 1;

    let (net, test_state, alloc) = set_up(id, false, queue_pairs, false);

    let vqs = init_net_device(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        DEFAULT_NET_FEATURES,
        queues,
    );

    // Turn off rx mode promisc.
    let ctrl_rx_info = CtrlRxInfo::new(VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, 0);
    send_ctrl_vq_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &ctrl_rx_info.as_bytes(),
        VIRTIO_NET_OK,
    );

    let reqs = [
        (0, VIRTIO_NET_OK),
        (0, VIRTIO_NET_OK),
        (1, VIRTIO_NET_OK),
        (0xfff, VIRTIO_NET_OK),
        (0xffff, VIRTIO_NET_ERR),
    ];
    // Test VIRTIO_NET_CTRL_VLAN_ADD.
    for (vid, ack) in reqs {
        let ctrl_vlan_info = CtrlVlanInfo::new(VIRTIO_NET_CTRL_VLAN, VIRTIO_NET_CTRL_VLAN_ADD, vid);
        send_ctrl_vq_request(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs.clone(),
            &ctrl_vlan_info.as_bytes(),
            ack,
        );
    }
    // Test VIRTIO_NET_CTRL_VLAN_DEL.
    for (vid, ack) in reqs {
        let ctrl_vlan_info = CtrlVlanInfo::new(VIRTIO_NET_CTRL_VLAN, VIRTIO_NET_CTRL_VLAN_DEL, vid);
        send_ctrl_vq_request(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs.clone(),
            &ctrl_vlan_info.as_bytes(),
            ack,
        );
    }
    // Test invalid class and cmd.
    let ctrl_vlan_info = CtrlVlanInfo::new(u8::MAX, u8::MAX, 0);
    send_ctrl_vq_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &ctrl_vlan_info.as_bytes(),
        VIRTIO_NET_ERR,
    );
    // Test invalid cmd.
    let ctrl_vlan_info = CtrlVlanInfo::new(VIRTIO_NET_CTRL_VLAN, u8::MAX, 0);
    send_ctrl_vq_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &ctrl_vlan_info.as_bytes(),
        VIRTIO_NET_ERR,
    );
    // Test invalid vid length.
    let ctrl_vlan_info = CtrlVlanInfo::new(VIRTIO_NET_CTRL_VLAN, VIRTIO_NET_CTRL_VLAN_ADD, 0);
    let data_size = size_of::<CtrlVlanInfo>() - 1;
    send_ctrl_vq_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &ctrl_vlan_info.as_bytes()[..data_size],
        VIRTIO_NET_ERR,
    );

    send_arp_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &get_arp_request(id).as_bytes(),
        true,
    );
    send_arp_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &get_arp_request_vlan(id).as_bytes(),
        false,
    );

    tear_down(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        id,
        false,
    );
}

/// Test the control mac command.
/// TestStep:
///   1. Init device with control vq.
///   2. Test the control mac command:
///    1) set mac address
///    2) set mac table with different unicast and multicast entries
///    3) invalid test:
///     a) invalid unicast entries
///     b) invalid unicast mac table
///     c) invalid ctrl mac cmd
///   3. Send ARP packet and check the reply.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn virtio_net_ctrl_mac_test() {
    let id = 6 * TEST_MAC_ADDR_NUMS;
    let queue_pairs: u16 = 1;
    let queues: usize = 2 * queue_pairs as usize + 1;

    let max_table_len = MAX_MAC_TABLE_LEN as u32;
    // (type, unicast_macs, multicast_macs)
    let mac_reqs = [
        (VIRTIO_NET_CTRL_MAC_ADDR_SET, 0, 0),
        (VIRTIO_NET_CTRL_MAC_TABLE_SET, 2, 2),
        (VIRTIO_NET_CTRL_MAC_TABLE_SET, 2, max_table_len - 2 + 1),
        (VIRTIO_NET_CTRL_MAC_TABLE_SET, max_table_len - 2, 2),
        (VIRTIO_NET_CTRL_MAC_TABLE_SET, max_table_len + 1, 0),
        (VIRTIO_NET_CTRL_MAC_TABLE_SET, max_table_len + 1, 2),
        (VIRTIO_NET_CTRL_MAC_TABLE_SET, 2, max_table_len),
        (u8::MAX, 0, 0),
    ];

    for (mac_type, uni, mul) in mac_reqs {
        let (net, test_state, alloc) = set_up(id, false, queue_pairs, true);

        let vqs = init_net_device(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            DEFAULT_NET_FEATURES,
            queues,
        );

        let mut arp_request = get_arp_request(id);
        // Test VIRTIO_NET_CTRL_MAC_ADDR_SET.
        match mac_type {
            VIRTIO_NET_CTRL_MAC_ADDR_SET => {
                // Normal test.
                ctrl_vq_set_mac_address(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                );
                // Abnormal test: mac_address(2 byte), ack(1byte)
                let req_data_bytes = [
                    VIRTIO_NET_CTRL_MAC,
                    VIRTIO_NET_CTRL_MAC_ADDR_SET,
                    0,
                    0,
                    0xff,
                ];
                send_ctrl_vq_request(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                    &req_data_bytes,
                    VIRTIO_NET_ERR,
                );
            }
            VIRTIO_NET_CTRL_MAC_TABLE_SET => {
                // Turn off rx mode promisc.
                let ctrl_rx_info =
                    CtrlRxInfo::new(VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, 0);
                send_ctrl_vq_request(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                    &ctrl_rx_info.as_bytes(),
                    VIRTIO_NET_OK,
                );

                // Test VIRTIO_NET_CTRL_MAC_TABLE_SET.
                ctrl_vq_set_mac_table(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                    uni,
                    mul,
                    VIRTIO_NET_OK,
                );
                arp_request.arp_packet.src_mac[MAC_ADDR_LEN - 1] += 2;
            }
            _ => {
                // Invalid unicast entries test.
                let req_data_bytes = [VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_TABLE_SET, 0, 0xff];
                send_ctrl_vq_request(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                    &req_data_bytes,
                    VIRTIO_NET_ERR,
                );
                // Invalid unicast mac table test.
                let req_data_bytes = [
                    VIRTIO_NET_CTRL_MAC,
                    VIRTIO_NET_CTRL_MAC_TABLE_SET,
                    0,
                    0,
                    0,
                    1,
                    0,
                    0xff,
                ];
                send_ctrl_vq_request(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                    &req_data_bytes,
                    VIRTIO_NET_ERR,
                );
                // Invalid cmd test.
                let req_data_bytes = [VIRTIO_NET_CTRL_MAC, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0xff];
                send_ctrl_vq_request(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                    &req_data_bytes,
                    VIRTIO_NET_ERR,
                );
            }
        }

        send_arp_request(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs.clone(),
            &arp_request.as_bytes(),
            true,
        );

        tear_down(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            id,
            false,
        );
    }
}

/// Test the control rx command.
/// TestStep:
///   1. Init device with control vq.
///   2. Test the control rx command:
///     1) PROMISC/NOUNI/ALLUNI/NOBCAST/NOMULTI/ALLMULTI
///     2) invalid class/cmd/switch
///   3. Send ARP packet and check the reply.
///   4. Destroy device.
/// Expect:
///   1/2/3/4: success.
#[test]
fn virtio_net_ctrl_rx_test() {
    let id = 7 * TEST_MAC_ADDR_NUMS;
    let queue_pairs: u16 = 1;
    let queues: usize = 2 * queue_pairs as usize + 1;

    // (req_type, cmd, value, need_reply, with_mac, ack)
    let reqs = [
        (1, VIRTIO_NET_CTRL_RX_PROMISC, 0, true, false, VIRTIO_NET_OK),
        (1, VIRTIO_NET_CTRL_RX_NOUNI, 1, false, false, VIRTIO_NET_OK),
        (1, VIRTIO_NET_CTRL_RX_ALLUNI, 1, true, false, VIRTIO_NET_OK),
        (1, u8::MAX, 0, true, false, VIRTIO_NET_ERR),
        (1, VIRTIO_NET_CTRL_RX_NOBCAST, 1, false, true, VIRTIO_NET_OK),
        (
            2,
            VIRTIO_NET_CTRL_RX_NOMULTI,
            1,
            false,
            false,
            VIRTIO_NET_OK,
        ),
        (
            2,
            VIRTIO_NET_CTRL_RX_ALLMULTI,
            1,
            true,
            false,
            VIRTIO_NET_OK,
        ),
        (
            2,
            u8::MAX,
            MAX_MAC_TABLE_LEN as u8,
            true,
            false,
            VIRTIO_NET_ERR,
        ),
        (2, u8::MAX, 2, true, false, VIRTIO_NET_ERR),
        (3, 0, 0, true, false, VIRTIO_NET_ERR),
        (u8::MAX, 0, 0, true, false, VIRTIO_NET_ERR),
    ];

    for (req_type, cmd, value, need_reply, with_mac, ack) in reqs {
        let (net, test_state, alloc) = set_up(id, false, queue_pairs, with_mac);

        let vqs = init_net_device(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            DEFAULT_NET_FEATURES,
            queues,
        );

        let mut arp_request = get_arp_request(id);
        // Turn off rx mode promisc.
        let ctrl_rx_info = CtrlRxInfo::new(VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, 0);
        send_ctrl_vq_request(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs.clone(),
            &ctrl_rx_info.as_bytes(),
            VIRTIO_NET_OK,
        );
        let mut ctrl_rx_info = CtrlRxInfo::new(VIRTIO_NET_CTRL_RX, 0, 0);
        match req_type {
            1 => {
                ctrl_rx_info = CtrlRxInfo::new(VIRTIO_NET_CTRL_RX, cmd, value);
            }
            2 => {
                ctrl_vq_set_mac_table(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                    0,
                    value as u32,
                    VIRTIO_NET_OK,
                );
                arp_request.arp_packet.src_mac[0] += 1;
                arp_request.arp_packet.src_mac[MAC_ADDR_LEN - 1] += 1;
                ctrl_rx_info = CtrlRxInfo::new(VIRTIO_NET_CTRL_RX, cmd, value);
            }
            3 => {
                // Test invalid class.
                ctrl_rx_info = CtrlRxInfo::new(u8::MAX, 0, 0);
            }
            _ => {
                // Test no switch data.
                let ctrl_rx_data = [VIRTIO_NET_CTRL_RX, 0, 0xff];
                send_ctrl_vq_request(
                    net.clone(),
                    test_state.clone(),
                    alloc.clone(),
                    vqs.clone(),
                    &ctrl_rx_data,
                    VIRTIO_NET_ERR,
                );
            }
        }

        if req_type != u8::MAX {
            send_ctrl_vq_request(
                net.clone(),
                test_state.clone(),
                alloc.clone(),
                vqs.clone(),
                &ctrl_rx_info.as_bytes(),
                ack,
            );
        }

        if cmd == VIRTIO_NET_CTRL_RX_NOBCAST {
            // Test receive filter: broadcast.
            arp_request.arp_packet.src_mac = [0xff; 6];
        }

        send_arp_request(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs.clone(),
            &arp_request.as_bytes(),
            need_reply,
        );

        tear_down(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            id,
            false,
        );
    }
}

/// Test the control abnormal command.
/// TestStep:
///   1. Init device with control vq.
///   2. Test the control rx command without ack, expect NEEDS_RESET.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_net_ctrl_abnormal_test() {
    let id = 8 * TEST_MAC_ADDR_NUMS;
    let queue_pairs: u16 = 1;
    let queues: usize = 2 * queue_pairs as usize + 1;
    let (net, test_state, alloc) = set_up(id, false, queue_pairs, false);

    let vqs = init_net_device(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        DEFAULT_NET_FEATURES,
        queues,
    );

    let ctrl_rx_info = CtrlRxInfo::new(VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, 0);
    let ctrl_data = &ctrl_rx_info.as_bytes();

    let ctrl_vq = &vqs[2];
    let addr = alloc
        .borrow_mut()
        .alloc(ctrl_data.len() as u64)
        .try_into()
        .unwrap();
    test_state.borrow().memwrite(addr, &ctrl_data);

    let data_entries: Vec<TestVringDescEntry> = vec![
        TestVringDescEntry {
            data: addr,
            len: 1,
            write: false,
        },
        TestVringDescEntry {
            data: addr + 1,
            len: 1,
            write: false,
        },
        TestVringDescEntry {
            data: addr + 2,
            len: ctrl_data.len() as u32 - 3,
            write: false,
        },
    ];
    ctrl_vq
        .borrow_mut()
        .add_chained(test_state.clone(), data_entries);
    net.borrow()
        .kick_virtqueue(test_state.clone(), ctrl_vq.clone());
    assert!(net.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET > 0);

    tear_down(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        id,
        false,
    );
}

/// Test the abnormal rx/tx request.
/// TestStep:
///   1. Init device.
///   2. Test the rx/tx request:
///     1) rx queue is full, and recover it
///     2) cause the tx packet limitation once
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_net_abnormal_rx_tx_test() {
    let id = 9 * TEST_MAC_ADDR_NUMS;
    let queue_pairs: u16 = 1;
    let queues: usize = 2 * queue_pairs as usize + 1;

    let (net, test_state, alloc) = set_up(id, false, queue_pairs, false);

    net.borrow_mut().reset();
    net.borrow_mut().set_acknowledge();
    net.borrow_mut().set_driver();
    net.borrow_mut().negotiate_features(DEFAULT_NET_FEATURES);
    net.borrow_mut().set_features_ok();
    net.borrow_mut().pci_dev.enable_msix(None);
    net.borrow_mut()
        .setup_msix_configuration_vector(alloc.clone(), 0);
    let vqs = net
        .borrow_mut()
        .init_virtqueue(test_state.clone(), alloc.clone(), queues);
    fill_rx_vq(test_state.clone(), alloc.clone(), vqs[0].clone());

    // Test rx queue is full.
    // Set 0 to rx->avail->idx.
    test_state.borrow().writew(vqs[0].borrow().avail + 2, 0);
    net.borrow().set_driver_ok();

    // Test send 256 packet to execeed the handle_tx limitation once.
    let request = get_arp_request(id);
    let length = request.as_bytes().len() as u64;
    let size = net.borrow().get_queue_size();
    assert_eq!(size, QUEUE_SIZE_NET);
    for _ in 0..size {
        let addr = alloc.borrow_mut().alloc(length).try_into().unwrap();
        test_state.borrow().memwrite(addr, &request.as_bytes());
        vqs[1]
            .borrow_mut()
            .add(test_state.clone(), addr, length as u32, false);
    }
    net.borrow().virtqueue_notify(vqs[1].clone());

    // Recover the rx->avail->idx for receiving packets.
    test_state
        .borrow()
        .writew(vqs[0].borrow().avail + 2, vqs[0].borrow().size as u16);
    net.borrow().virtqueue_notify(vqs[0].clone());

    // Check rx vq is ok.
    let start_time = time::Instant::now();
    let timeout_us = time::Duration::from_micros(TIMEOUT_US / 5);
    loop {
        if net.borrow().queue_was_notified(vqs[0].clone())
            && vqs[0].borrow_mut().get_buf(test_state.clone())
        {
            break;
        }
        assert!(time::Instant::now() - start_time < timeout_us);
    }

    tear_down(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        id,
        false,
    );
}

/// Test the abnormal rx/tx request 2.
/// TestStep:
///   1. Init device.
///   2. Test the rx/tx request:
///     1) handle rx error
///     2) handle tx error
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_net_abnormal_rx_tx_test_2() {
    let id = 10 * TEST_MAC_ADDR_NUMS;
    let queue_pairs: u16 = 1;
    let queues: usize = 2 * queue_pairs as usize + 1;

    for i in 0..2 {
        let (net, test_state, alloc) = set_up(id, false, queue_pairs, false);

        net.borrow_mut().reset();
        net.borrow_mut().set_acknowledge();
        net.borrow_mut().set_driver();
        net.borrow_mut().negotiate_features(DEFAULT_NET_FEATURES);
        net.borrow_mut().set_features_ok();
        net.borrow_mut().pci_dev.enable_msix(None);
        net.borrow_mut()
            .setup_msix_configuration_vector(alloc.clone(), 0);
        let vqs = net
            .borrow_mut()
            .init_virtqueue(test_state.clone(), alloc.clone(), queues);
        fill_rx_vq(test_state.clone(), alloc.clone(), vqs[0].clone());

        // Test receive packet failed.
        // Set u16::MAX to rx->avail->ring[0].
        if i == 0 {
            test_state
                .borrow()
                .writew(vqs[0].borrow().avail + 4, u16::MAX);
        }
        // Set driver ok.
        let status = net.borrow().get_status() | VIRTIO_CONFIG_S_DRIVER_OK;
        net.borrow().set_status(status);

        let request = get_arp_request(id);
        let length = request.as_bytes().len() as u64;
        let addr = alloc.borrow_mut().alloc(length).try_into().unwrap();
        test_state.borrow().memwrite(addr, &request.as_bytes());
        vqs[1]
            .borrow_mut()
            .add(test_state.clone(), addr, length as u32, false);
        if i == 1 {
            test_state
                .borrow()
                .writew(vqs[1].borrow().avail + 4, u16::MAX);
        }
        net.borrow().virtqueue_notify(vqs[1].clone());
        sleep(time::Duration::from_millis(500));
        assert!(net.borrow().get_status() & VIRTIO_CONFIG_S_NEEDS_RESET > 0);

        tear_down(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs,
            id,
            false,
        );
    }
}

/// Test set abnormal feature.
/// TestStep:
///   1. Init device, set abnormal feature 40 which will be ignored.
///   2. Send ARP packet and check the reply.
///   3. Destroy device.
/// Expect:
///   1/2/3: success.
#[test]
fn virtio_net_set_abnormal_feature() {
    let id = 11 * TEST_MAC_ADDR_NUMS;
    let (net, test_state, alloc) = set_up(id, false, 0, false);

    // Three virtqueues: tx/rx/ctrl.
    let vqs = init_net_device(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        DEFAULT_NET_FEATURES | 1 << 40,
        3,
    );
    assert_eq!(net.borrow().get_guest_features(), DEFAULT_NET_FEATURES);

    let arp_request = get_arp_request(id);
    send_arp_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &arp_request.as_bytes(),
        true,
    );

    tear_down(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        id,
        false,
    );
}

/// Send abnormal packet.
/// TestStep:
///   1. Init device.
///   2. Send abnormal packet:
///     1) invalid virtio_net_hdr
///     2) random a packet
///   3. Send qmp to StratoVirt.
///   4. Destroy device.
/// Expect:
///   2. success or failure.
///   1/3/4: success.
#[test]
fn virtio_net_send_abnormal_packet() {
    let id = 12 * TEST_MAC_ADDR_NUMS;
    let (net, test_state, alloc) = set_up(id, false, 0, false);

    // Three virtqueues: tx/rx/ctrl.
    let vqs = init_net_device(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        DEFAULT_NET_FEATURES,
        3,
    );

    let mut arp_request = get_arp_request(id);
    arp_request.net_hdr.flags = u8::MAX;
    send_arp_request(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs.clone(),
        &arp_request.as_bytes(),
        false,
    );

    let data_bytes = arp_request.as_mut_bytes();
    let mut rng = rand::thread_rng();
    let test_packets = 8;
    for _ in 0..test_packets {
        for _ in 0..data_bytes.len() / 3 {
            let idx = rng.gen_range(0..data_bytes.len());
            data_bytes[idx] = rng.gen_range(0..0xff);
        }

        send_request(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs.clone(),
            &data_bytes,
        );
    }

    for _ in 0..test_packets {
        let mut data_bytes = [0; MAX_PACKET_LEN as usize + 8];
        for j in 0..MAX_PACKET_LEN as usize + 8 {
            data_bytes[j] = rng.gen_range(0..0xff);
        }
        send_request(
            net.clone(),
            test_state.clone(),
            alloc.clone(),
            vqs.clone(),
            &data_bytes,
        );
    }

    let ret = test_state
        .borrow()
        .qmp("{\"execute\": \"qmp_capabilities\"}");
    assert_eq!(*ret.get("return").unwrap(), json!({}));

    tear_down(
        net.clone(),
        test_state.clone(),
        alloc.clone(),
        vqs,
        id,
        false,
    );
}
