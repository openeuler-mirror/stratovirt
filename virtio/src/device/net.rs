// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::HashMap;
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::{cmp, fs, mem};

use anyhow::{bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use log::{error, warn};
use once_cell::sync::Lazy;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use crate::{
    check_config_space_rw, iov_discard_front, iov_to_buf, mem_to_buf, read_config_default,
    report_virtio_error, virtio_has_feature, ElemIovec, Element, Queue, VirtioBase, VirtioDevice,
    VirtioError, VirtioInterrupt, VirtioInterruptType, VirtioNetHdr, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1, VIRTIO_NET_CTRL_MAC,
    VIRTIO_NET_CTRL_MAC_ADDR_SET, VIRTIO_NET_CTRL_MAC_TABLE_SET, VIRTIO_NET_CTRL_MQ,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_ALLMULTI,
    VIRTIO_NET_CTRL_RX_ALLUNI, VIRTIO_NET_CTRL_RX_NOBCAST, VIRTIO_NET_CTRL_RX_NOMULTI,
    VIRTIO_NET_CTRL_RX_NOUNI, VIRTIO_NET_CTRL_RX_PROMISC, VIRTIO_NET_CTRL_VLAN,
    VIRTIO_NET_CTRL_VLAN_ADD, VIRTIO_NET_CTRL_VLAN_DEL, VIRTIO_NET_ERR, VIRTIO_NET_F_CSUM,
    VIRTIO_NET_F_CTRL_MAC_ADDR, VIRTIO_NET_F_CTRL_RX, VIRTIO_NET_F_CTRL_RX_EXTRA,
    VIRTIO_NET_F_CTRL_VLAN, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_ECN,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6, VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO6, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC,
    VIRTIO_NET_F_MQ, VIRTIO_NET_OK, VIRTIO_TYPE_NET,
};
use address_space::{AddressSpace, RegionCache};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use machine_manager::{
    config::{ConfigCheck, NetworkInterfaceConfig},
    event_loop::EventLoop,
};
use migration::{
    migration::Migratable, DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager,
    StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::loop_context::gen_delete_notifiers;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::str_to_num;
use util::tap::{
    Tap, IFF_MULTI_QUEUE, TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6, TUN_F_TSO_ECN, TUN_F_UFO,
};

/// Number of virtqueues(rx/tx/ctrl).
const QUEUE_NUM_NET: usize = 3;
/// The Mac Address length.
pub const MAC_ADDR_LEN: usize = 6;
/// The length of ethernet header.
const ETHERNET_HDR_LENGTH: usize = 14;
/// The max "multicast + unicast" mac address table length.
const CTRL_MAC_TABLE_LEN: usize = 64;
/// From 802.1Q definition, the max vlan ID.
const CTRL_MAX_VLAN: u16 = 1 << 12;
/// The max num of the mac address.
const MAX_MAC_ADDR_NUM: usize = 0xff;
/// The header length of virtio net packet.
const NET_HDR_LENGTH: usize = mem::size_of::<VirtioNetHdr>();
/// The length of vlan tag.
const VLAN_TAG_LENGTH: usize = 4;
/// The offset of vlan tpid for 802.1Q tag.
const VLAN_TPID_LENGTH: usize = 2;

type SenderConfig = Option<Tap>;

/// The first default mac address.
const FIRST_DEFAULT_MAC: [u8; MAC_ADDR_LEN] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
/// Used to mark if the last byte of the mac address is used.
static USED_MAC_TABLE: Lazy<Arc<Mutex<[i8; MAX_MAC_ADDR_NUM]>>> =
    Lazy::new(|| Arc::new(Mutex::new([0_i8; MAX_MAC_ADDR_NUM])));

/// Configuration of virtio-net devices.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
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

impl ByteCode for VirtioNetConfig {}

/// The control mode used for packet receive filtering.
struct CtrlRxMode {
    /// If the device should receive all incoming packets.
    promisc: bool,
    /// If the device should allow all incoming multicast packets.
    all_multi: bool,
    /// If the device should allow all incoming unicast packets.
    all_uni: bool,
    /// Used to suppress multicast receive.
    no_multi: bool,
    /// Used to suppress unicast receive.
    no_uni: bool,
    /// Used to suppresses broadcast receive.
    no_bcast: bool,
}

impl Default for CtrlRxMode {
    fn default() -> Self {
        Self {
            // For compatibility with older guest drivers, it
            // needs to default to promiscuous.
            promisc: true,
            all_multi: false,
            all_uni: false,
            no_multi: false,
            no_uni: false,
            no_bcast: false,
        }
    }
}

#[derive(Default, Clone)]
struct MacAddress {
    address: [u8; MAC_ADDR_LEN],
}

/// The Mac information used to filter incoming packet.
#[derive(Default)]
struct CtrlMacInfo {
    /// Unicast mac address table.
    uni_mac_table: Vec<MacAddress>,
    /// Unicast mac address overflow.
    uni_mac_of: bool,
    /// Multicast mac address table.
    multi_mac_table: Vec<MacAddress>,
    /// Multicast mac address overflow.
    multi_mac_of: bool,
}

pub struct CtrlInfo {
    /// The control rx mode for packet receive filtering.
    rx_mode: CtrlRxMode,
    /// The mac address information for packet receive filtering.
    mac_info: CtrlMacInfo,
    /// The map of all the vlan ids.
    vlan_map: HashMap<u16, u32>,
    /// The net device status.
    config: Arc<Mutex<VirtioNetConfig>>,
}

impl CtrlInfo {
    pub fn new(config: Arc<Mutex<VirtioNetConfig>>) -> Self {
        CtrlInfo {
            rx_mode: CtrlRxMode::default(),
            mac_info: CtrlMacInfo::default(),
            vlan_map: HashMap::new(),
            config,
        }
    }

    fn handle_rx_mode(
        &mut self,
        mem_space: &AddressSpace,
        cmd: u8,
        data_iovec: &mut [ElemIovec],
    ) -> Result<u8> {
        // Get the command specific data, one byte containing 0(off) or 1(on).
        let mut status: u8 = 0;
        get_buf_and_discard(mem_space, data_iovec, status.as_mut_bytes())
            .with_context(|| "Failed to get control data")?;
        // 0: off, 1: on.
        if ![0, 1].contains(&status) {
            return Ok(VIRTIO_NET_ERR);
        }
        let mut on_off = false;
        if status == 1 {
            on_off = true;
        }
        let mut ack = VIRTIO_NET_OK;
        match cmd {
            VIRTIO_NET_CTRL_RX_PROMISC => self.rx_mode.promisc = on_off,
            VIRTIO_NET_CTRL_RX_ALLMULTI => self.rx_mode.all_multi = on_off,
            VIRTIO_NET_CTRL_RX_ALLUNI => self.rx_mode.all_uni = on_off,
            VIRTIO_NET_CTRL_RX_NOMULTI => self.rx_mode.no_multi = on_off,
            VIRTIO_NET_CTRL_RX_NOUNI => self.rx_mode.no_uni = on_off,
            VIRTIO_NET_CTRL_RX_NOBCAST => self.rx_mode.no_bcast = on_off,
            _ => {
                error!("Invalid command {} for control rx mode", cmd);
                ack = VIRTIO_NET_ERR;
            }
        }
        Ok(ack)
    }

    fn set_mac_table(
        &mut self,
        mem_space: &AddressSpace,
        data_iovec: &mut Vec<ElemIovec>,
    ) -> Result<u8> {
        let ack = VIRTIO_NET_OK;
        let mut mac_table_len = 0;
        // Default for unicast.
        let mut overflow = &mut self.mac_info.uni_mac_of;
        let mut mac_table = &mut self.mac_info.uni_mac_table;

        // 0 for unicast, 1 for multicast.
        for i in 0..2 {
            if i == 1 {
                overflow = &mut self.mac_info.multi_mac_of;
                mac_table_len = self.mac_info.uni_mac_table.len();
                mac_table = &mut self.mac_info.multi_mac_table;
            }

            let mut entries: u32 = 0;
            *data_iovec = get_buf_and_discard(mem_space, data_iovec, entries.as_mut_bytes())
                .with_context(|| "Failed to get MAC entries".to_string())?;
            if entries == 0 {
                mac_table.clear();
                continue;
            }

            let size = entries as u64 * MAC_ADDR_LEN as u64;
            let res_len = Element::iovec_size(data_iovec);
            if size > res_len {
                bail!("Invalid request for setting mac table.");
            }
            if entries as usize > CTRL_MAC_TABLE_LEN - mac_table_len {
                if size < res_len {
                    *data_iovec = iov_discard_front(data_iovec, size)
                        .with_context(|| "Failed to discard iovec from front side".to_string())?
                        .to_vec();
                }
                *overflow = true;
                mac_table.clear();
                continue;
            }

            let mut macs = vec![0_u8; size as usize];
            *data_iovec = get_buf_and_discard(mem_space, data_iovec, &mut macs)
                .with_context(|| "Failed to get MAC entries".to_string())?;

            mac_table.clear();
            for i in 0..entries {
                let offset = i as usize * MAC_ADDR_LEN;
                let mut mac: MacAddress = Default::default();
                mac.address
                    .copy_from_slice(&macs[offset..offset + MAC_ADDR_LEN]);
                mac_table.push(mac);
            }
        }
        Ok(ack)
    }

    fn handle_mac(
        &mut self,
        mem_space: &AddressSpace,
        cmd: u8,
        data_iovec: &mut Vec<ElemIovec>,
    ) -> u8 {
        let mut ack = VIRTIO_NET_OK;
        match cmd {
            VIRTIO_NET_CTRL_MAC_ADDR_SET => {
                let mut mac = [0; MAC_ADDR_LEN];
                *data_iovec =
                    get_buf_and_discard(mem_space, data_iovec, &mut mac).unwrap_or_else(|e| {
                        error!("Failed to get MAC address, error is {:?}", e);
                        ack = VIRTIO_NET_ERR;
                        Vec::new()
                    });
                if ack == VIRTIO_NET_ERR {
                    return VIRTIO_NET_ERR;
                }
                self.config.lock().unwrap().mac.copy_from_slice(&mac);
            }
            VIRTIO_NET_CTRL_MAC_TABLE_SET => {
                ack = self
                    .set_mac_table(mem_space, data_iovec)
                    .unwrap_or_else(|e| {
                        error!("Failed to get Unicast Mac address, error is {:?}", e);
                        VIRTIO_NET_ERR
                    });
            }
            _ => {
                error!("Invalid cmd {} when handling control mac", cmd);
                return VIRTIO_NET_ERR;
            }
        }

        ack
    }

    fn handle_vlan_table(
        &mut self,
        mem_space: &AddressSpace,
        cmd: u8,
        data_iovec: &mut Vec<ElemIovec>,
    ) -> u8 {
        let mut ack = VIRTIO_NET_OK;
        let mut vid: u16 = 0;

        *data_iovec = get_buf_and_discard(mem_space, data_iovec, vid.as_mut_bytes())
            .unwrap_or_else(|e| {
                error!("Failed to get vlan id, error is {:?}", e);
                ack = VIRTIO_NET_ERR;
                Vec::new()
            });
        if ack == VIRTIO_NET_ERR {
            return ack;
        }
        vid = LittleEndian::read_u16(vid.as_bytes());
        if vid >= CTRL_MAX_VLAN {
            return VIRTIO_NET_ERR;
        }

        match cmd {
            VIRTIO_NET_CTRL_VLAN_ADD => {
                if let Some(value) = self.vlan_map.get_mut(&(vid >> 5)) {
                    *value |= 1 << (vid & 0x1f);
                } else {
                    self.vlan_map.insert(vid >> 5, 1 << (vid & 0x1f));
                }
            }
            VIRTIO_NET_CTRL_VLAN_DEL => {
                if let Some(value) = self.vlan_map.get_mut(&(vid >> 5)) {
                    *value &= !(1 << (vid & 0x1f));
                }
            }
            _ => {
                error!("Invalid cmd {} when handling control vlan", cmd);
                ack = VIRTIO_NET_ERR;
            }
        }
        ack
    }

    fn handle_mq(
        &mut self,
        mem_space: &AddressSpace,
        taps: Option<&mut Vec<Tap>>,
        cmd: u8,
        data_iovec: &mut Vec<ElemIovec>,
    ) -> u8 {
        let mut ack = VIRTIO_NET_OK;
        if cmd as u16 == VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET {
            let mut queue_pairs: u16 = 0;
            *data_iovec = get_buf_and_discard(mem_space, data_iovec, queue_pairs.as_mut_bytes())
                .unwrap_or_else(|e| {
                    error!("Failed to get queue pairs {:?}", e);
                    ack = VIRTIO_NET_ERR;
                    Vec::new()
                });
            if ack == VIRTIO_NET_ERR {
                return ack;
            }

            queue_pairs = LittleEndian::read_u16(queue_pairs.as_bytes());
            let max_pairs = self.config.lock().unwrap().max_virtqueue_pairs;
            if !(VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN..=max_pairs).contains(&queue_pairs) {
                error!("Invalid queue pairs {}", queue_pairs);
                return VIRTIO_NET_ERR;
            }
            if let Some(taps) = taps {
                for (index, tap) in taps.iter_mut().enumerate() {
                    if tap.set_queue(index < queue_pairs as usize) != 0 {
                        error!("Failed to set queue, index is {}", index);
                        return VIRTIO_NET_ERR;
                    }
                }
            }
        } else {
            error!(
                "Control queue header command can't match {}",
                VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET
            );
            ack = VIRTIO_NET_ERR;
        }

        ack
    }

    fn filter_packets(&mut self, buf: &[u8]) -> bool {
        // Broadcast address: 0xff:0xff:0xff:0xff:0xff:0xff.
        let bcast = [0xff; MAC_ADDR_LEN];
        // TPID of the vlan tag, defined in IEEE 802.1Q, is 0x8100.
        let vlan = [0x81, 0x00];

        if self.rx_mode.promisc {
            return false;
        }

        if buf[ETHERNET_HDR_LENGTH - VLAN_TPID_LENGTH..ETHERNET_HDR_LENGTH] == vlan {
            let vid = u16::from_be_bytes([buf[ETHERNET_HDR_LENGTH], buf[ETHERNET_HDR_LENGTH + 1]]);
            let value = if let Some(value) = self.vlan_map.get(&(vid >> 5)) {
                *value
            } else {
                0
            };

            if value & (1 << (vid & 0x1f)) == 0 {
                return true;
            }
        }

        // The bit 0 in byte[0] means unicast(0) or multicast(1).
        if buf[0] & 0x01 > 0 {
            if buf[..MAC_ADDR_LEN] == bcast {
                return self.rx_mode.no_bcast;
            }
            if self.rx_mode.no_multi {
                return true;
            }
            if self.rx_mode.all_multi || self.mac_info.multi_mac_of {
                return false;
            }
            for mac in self.mac_info.multi_mac_table.iter() {
                if buf[..MAC_ADDR_LEN] == mac.address {
                    return false;
                }
            }
        } else {
            if self.rx_mode.no_uni {
                return true;
            }
            if self.rx_mode.all_uni
                || self.mac_info.uni_mac_of
                || buf[..MAC_ADDR_LEN] == self.config.lock().unwrap().mac
            {
                return false;
            }
            for mac in self.mac_info.uni_mac_table.iter() {
                if buf[..MAC_ADDR_LEN] == mac.address {
                    return false;
                }
            }
        }

        true
    }
}

fn get_buf_and_discard(
    mem_space: &AddressSpace,
    iovec: &mut [ElemIovec],
    buf: &mut [u8],
) -> Result<Vec<ElemIovec>> {
    iov_to_buf(mem_space, iovec, buf).and_then(|size| {
        if size < buf.len() {
            error!("Invalid length {}, expected length {}", size, buf.len());
            bail!("Invalid length {}, expected length {}", size, buf.len());
        }
        Ok(())
    })?;

    if let Some(data_iovec) = iov_discard_front(iovec, buf.len() as u64) {
        Ok(data_iovec.to_vec())
    } else {
        Ok(Vec::new())
    }
}

/// The control queue is used to verify the multi queue feature.
pub struct CtrlVirtio {
    /// The control queue.
    queue: Arc<Mutex<Queue>>,
    /// The eventfd used to notify the control queue event.
    queue_evt: Arc<EventFd>,
    /// The information about control command.
    ctrl_info: Arc<Mutex<CtrlInfo>>,
}

impl CtrlVirtio {
    pub fn new(
        queue: Arc<Mutex<Queue>>,
        queue_evt: Arc<EventFd>,
        ctrl_info: Arc<Mutex<CtrlInfo>>,
    ) -> Self {
        Self {
            queue,
            queue_evt,
            ctrl_info,
        }
    }
}

/// Handle the frontend and the backend control channel virtio queue events and data.
pub struct NetCtrlHandler {
    /// The control virtio queue.
    pub ctrl: CtrlVirtio,
    /// Memory space.
    pub mem_space: Arc<AddressSpace>,
    /// The interrupt call back function.
    pub interrupt_cb: Arc<VirtioInterrupt>,
    /// Bit mask of features negotiated by the backend and the frontend.
    pub driver_features: u64,
    /// Device is broken or not.
    pub device_broken: Arc<AtomicBool>,
    pub taps: Option<Vec<Tap>>,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct CtrlHdr {
    class: u8,
    cmd: u8,
}

impl ByteCode for CtrlHdr {}

impl NetCtrlHandler {
    fn handle_ctrl(&mut self) -> Result<()> {
        let mut locked_queue = self.ctrl.queue.lock().unwrap();
        loop {
            let mut ack = VIRTIO_NET_OK;
            let mut elem = locked_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for net control queue")?;
            if elem.desc_num == 0 {
                break;
            }

            // Validate the control request.
            let in_size = Element::iovec_size(&elem.in_iovec);
            let out_size = Element::iovec_size(&elem.out_iovec);
            if in_size < mem::size_of_val(&ack) as u64
                || out_size < mem::size_of::<CtrlHdr>() as u64
            {
                bail!(
                    "Invalid length, in_iovec size is {}, out_iovec size is {}",
                    in_size,
                    out_size
                );
            }

            // Get the control request header.
            let mut ctrl_hdr = CtrlHdr::default();
            let mut data_iovec = get_buf_and_discard(
                &self.mem_space,
                &mut elem.out_iovec,
                ctrl_hdr.as_mut_bytes(),
            )
            .with_context(|| "Failed to get control header")?;

            trace::virtio_net_handle_ctrl(ctrl_hdr.class, ctrl_hdr.cmd);
            match ctrl_hdr.class {
                VIRTIO_NET_CTRL_RX => {
                    ack = self
                        .ctrl
                        .ctrl_info
                        .lock()
                        .unwrap()
                        .handle_rx_mode(&self.mem_space, ctrl_hdr.cmd, &mut data_iovec)
                        .unwrap_or_else(|e| {
                            error!("Failed to handle rx mode, error is {:?}", e);
                            VIRTIO_NET_ERR
                        });
                }
                VIRTIO_NET_CTRL_MAC => {
                    ack = self.ctrl.ctrl_info.lock().unwrap().handle_mac(
                        &self.mem_space,
                        ctrl_hdr.cmd,
                        &mut data_iovec,
                    );
                }
                VIRTIO_NET_CTRL_VLAN => {
                    ack = self.ctrl.ctrl_info.lock().unwrap().handle_vlan_table(
                        &self.mem_space,
                        ctrl_hdr.cmd,
                        &mut data_iovec,
                    );
                }
                VIRTIO_NET_CTRL_MQ => {
                    ack = self.ctrl.ctrl_info.lock().unwrap().handle_mq(
                        &self.mem_space,
                        self.taps.as_mut(),
                        ctrl_hdr.cmd,
                        &mut data_iovec,
                    );
                }
                _ => {
                    error!(
                        "Control queue header class {} not supported",
                        ctrl_hdr.class
                    );
                    ack = VIRTIO_NET_ERR;
                }
            }

            // Write result to the device writable iovec.
            let status = elem
                .in_iovec
                .get(0)
                .with_context(|| "Failed to get device writable iovec")?;
            self.mem_space.write_object::<u8>(&ack, status.addr)?;

            locked_queue
                .vring
                .add_used(&self.mem_space, elem.index, mem::size_of_val(&ack) as u32)
                .with_context(|| format!("Failed to add used ring {}", elem.index))?;

            if locked_queue
                .vring
                .should_notify(&self.mem_space, self.driver_features)
            {
                (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&locked_queue), false)
                    .with_context(|| {
                        VirtioError::InterruptTrigger("ctrl", VirtioInterruptType::Vring)
                    })?;
                trace::virtqueue_send_interrupt("Net", &*locked_queue as *const _ as u64);
            }
        }

        Ok(())
    }
}

impl EventNotifierHelper for NetCtrlHandler {
    fn internal_notifiers(net_io: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let locked_net_io = net_io.lock().unwrap();
        let cloned_net_io = net_io.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut locked_net_io = cloned_net_io.lock().unwrap();
            if locked_net_io.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            locked_net_io.handle_ctrl().unwrap_or_else(|e| {
                error!("Failed to handle ctrl queue, error is {:?}.", e);
                report_virtio_error(
                    locked_net_io.interrupt_cb.clone(),
                    locked_net_io.driver_features,
                    &locked_net_io.device_broken,
                );
            });
            None
        });
        notifiers.push(build_event_notifier(
            locked_net_io.ctrl.queue_evt.as_raw_fd(),
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        ));

        notifiers
    }
}

struct TxVirtio {
    queue: Arc<Mutex<Queue>>,
    queue_evt: Arc<EventFd>,
}

impl TxVirtio {
    fn new(queue: Arc<Mutex<Queue>>, queue_evt: Arc<EventFd>) -> Self {
        TxVirtio { queue, queue_evt }
    }
}

struct RxVirtio {
    queue_full: bool,
    queue: Arc<Mutex<Queue>>,
    queue_evt: Arc<EventFd>,
    recv_evt: Arc<EventFd>,
}

impl RxVirtio {
    fn new(queue: Arc<Mutex<Queue>>, queue_evt: Arc<EventFd>, recv_evt: Arc<EventFd>) -> Self {
        RxVirtio {
            queue_full: false,
            queue,
            queue_evt,
            recv_evt,
        }
    }
}

struct NetIoHandler {
    rx: RxVirtio,
    tx: TxVirtio,
    tap: Option<Tap>,
    tap_fd: RawFd,
    mem_space: Arc<AddressSpace>,
    interrupt_cb: Arc<VirtioInterrupt>,
    driver_features: u64,
    receiver: Receiver<SenderConfig>,
    update_evt: Arc<EventFd>,
    device_broken: Arc<AtomicBool>,
    is_listening: bool,
    ctrl_info: Arc<Mutex<CtrlInfo>>,
    queue_size: u16,
}

impl NetIoHandler {
    fn read_from_tap(iovecs: &[libc::iovec], tap: &mut Tap) -> i32 {
        // SAFETY: the arguments of readv has been checked and is correct.
        let size = unsafe {
            libc::readv(
                tap.as_raw_fd() as libc::c_int,
                iovecs.as_ptr() as *const libc::iovec,
                iovecs.len() as libc::c_int,
            )
        } as i32;
        if size < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return size;
            }

            // If the backend tap device is removed, readv returns less than 0.
            // At this time, the content in the tap needs to be cleaned up.
            // Here, read is called to process, otherwise handle_rx may be triggered all the time.
            let mut buf = [0; 1024];
            match tap.read(&mut buf) {
                Ok(cnt) => error!("Failed to call readv but tap read is ok: cnt {}", cnt),
                Err(e) => {
                    // When the backend tap device is abnormally removed, read return EBADFD.
                    error!("Failed to read tap: {:?}", e);
                }
            }
            error!("Failed to call readv for net handle_rx: {:?}", e);
        }

        size
    }

    fn get_libc_iovecs(
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem_iovecs: &[ElemIovec],
    ) -> Vec<libc::iovec> {
        let mut iovecs = Vec::new();
        for elem_iov in elem_iovecs.iter() {
            // elem_iov.addr has been checked in pop_avail().
            let mut len = elem_iov.len;
            let mut start = elem_iov.addr;
            loop {
                let io_vec = mem_space
                    .get_host_address_from_cache(start, cache)
                    .map(|(hva, fr_len)| libc::iovec {
                        iov_base: hva as *mut libc::c_void,
                        iov_len: std::cmp::min(elem_iov.len, fr_len as u32) as libc::size_t,
                    })
                    .unwrap();
                start = start.unchecked_add(io_vec.iov_len as u64);
                len -= io_vec.iov_len as u32;
                iovecs.push(io_vec);
                if len == 0 {
                    break;
                }
            }
        }
        iovecs
    }

    fn handle_rx(&mut self) -> Result<()> {
        trace::virtio_receive_request("Net".to_string(), "to rx".to_string());
        if self.tap.is_none() {
            return Ok(());
        }

        let mut queue = self.rx.queue.lock().unwrap();
        let mut rx_packets = 0;
        loop {
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for net rx")?;
            if elem.desc_num == 0 {
                self.rx.queue_full = true;
                break;
            } else if elem.in_iovec.is_empty() {
                bail!("The length of in iovec is 0");
            }
            let iovecs = NetIoHandler::get_libc_iovecs(
                &self.mem_space,
                queue.vring.get_cache(),
                &elem.in_iovec,
            );

            if MigrationManager::is_active() {
                // FIXME: mark dirty page needs to be managed by `AddressSpace` crate.
                for iov in iovecs.iter() {
                    // Mark vmm dirty page manually if live migration is active.
                    MigrationManager::mark_dirty_log(iov.iov_base as u64, iov.iov_len as u64);
                }
            }

            // Read the data from the tap device.
            let size = NetIoHandler::read_from_tap(&iovecs, self.tap.as_mut().unwrap());
            if size < (NET_HDR_LENGTH + ETHERNET_HDR_LENGTH + VLAN_TAG_LENGTH) as i32 {
                queue.vring.push_back();
                break;
            }

            let mut buf = vec![0_u8; NET_HDR_LENGTH + ETHERNET_HDR_LENGTH + VLAN_TAG_LENGTH];
            get_net_header(&iovecs, &mut buf).and_then(|size| {
                if size != buf.len() {
                    bail!(
                        "Invalid header length {}, expected length {}",
                        size,
                        buf.len()
                    );
                }
                Ok(())
            })?;
            if self
                .ctrl_info
                .lock()
                .unwrap()
                .filter_packets(&buf[NET_HDR_LENGTH..])
            {
                queue.vring.push_back();
                continue;
            }

            queue
                .vring
                .add_used(&self.mem_space, elem.index, size as u32)
                .with_context(|| {
                    format!(
                        "Failed to add used ring for net rx, index: {}, len: {}",
                        elem.index, size
                    )
                })?;

            if queue
                .vring
                .should_notify(&self.mem_space, self.driver_features)
            {
                (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue), false)
                    .with_context(|| {
                        VirtioError::InterruptTrigger("net", VirtioInterruptType::Vring)
                    })?;
                trace::virtqueue_send_interrupt("Net", &*queue as *const _ as u64);
            }

            rx_packets += 1;
            if rx_packets >= self.queue_size {
                self.rx
                    .recv_evt
                    .write(1)
                    .with_context(|| "Failed to trigger tap queue event".to_string())?;
                break;
            }
        }

        Ok(())
    }

    fn send_packets(&self, tap_fd: libc::c_int, iovecs: &[libc::iovec]) -> i8 {
        loop {
            // SAFETY: the arguments of writev has been checked and is correct.
            let size = unsafe {
                libc::writev(
                    tap_fd,
                    iovecs.as_ptr() as *const libc::iovec,
                    iovecs.len() as libc::c_int,
                )
            };
            if size < 0 {
                let e = std::io::Error::last_os_error();
                match e.kind() {
                    ErrorKind::Interrupted => continue,
                    ErrorKind::WouldBlock => return -1_i8,
                    // Ignore other errors which can not be handled.
                    _ => error!("Failed to call writev for net handle_tx: {:?}", e),
                }
            }
            break;
        }
        0_i8
    }

    fn handle_tx(&mut self) -> Result<()> {
        trace::virtio_receive_request("Net".to_string(), "to tx".to_string());
        let mut queue = self.tx.queue.lock().unwrap();

        let mut tx_packets = 0;
        loop {
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for net tx")?;
            if elem.desc_num == 0 {
                break;
            } else if elem.out_iovec.is_empty() {
                bail!("The length of out iovec is 0");
            }

            let iovecs = NetIoHandler::get_libc_iovecs(
                &self.mem_space,
                queue.vring.get_cache(),
                &elem.out_iovec,
            );
            let tap_fd = if let Some(tap) = self.tap.as_mut() {
                tap.as_raw_fd() as libc::c_int
            } else {
                -1_i32
            };
            if tap_fd != -1 && self.send_packets(tap_fd, &iovecs) == -1 {
                queue.vring.push_back();
                self.tx.queue_evt.write(1).with_context(|| {
                    "Failed to trigger tx queue event when writev blocked".to_string()
                })?;
                return Ok(());
            }

            queue
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .with_context(|| format!("Net tx: Failed to add used ring {}", elem.index))?;

            if queue
                .vring
                .should_notify(&self.mem_space, self.driver_features)
            {
                (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue), false)
                    .with_context(|| {
                        VirtioError::InterruptTrigger("net", VirtioInterruptType::Vring)
                    })?;
                trace::virtqueue_send_interrupt("Net", &*queue as *const _ as u64);
            }
            tx_packets += 1;
            if tx_packets >= self.queue_size {
                self.tx
                    .queue_evt
                    .write(1)
                    .with_context(|| "Failed to trigger tx queue event".to_string())?;
                break;
            }
        }

        Ok(())
    }

    fn update_evt_handler(net_io: &Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut locked_net_io = net_io.lock().unwrap();
        locked_net_io.tap = match locked_net_io.receiver.recv() {
            Ok(tap) => tap,
            Err(e) => {
                error!("Failed to receive the tap {:?}", e);
                None
            }
        };
        let old_tap_fd = locked_net_io.tap_fd;
        locked_net_io.tap_fd = -1;
        if let Some(tap) = locked_net_io.tap.as_ref() {
            locked_net_io.tap_fd = tap.as_raw_fd();
        }

        let mut notifiers_fds = vec![
            locked_net_io.update_evt.as_raw_fd(),
            locked_net_io.rx.queue_evt.as_raw_fd(),
            locked_net_io.rx.recv_evt.as_raw_fd(),
            locked_net_io.tx.queue_evt.as_raw_fd(),
        ];
        if old_tap_fd != -1 {
            notifiers_fds.push(old_tap_fd);
        }
        let mut notifiers = gen_delete_notifiers(&notifiers_fds);
        drop(locked_net_io);

        notifiers.append(&mut EventNotifierHelper::internal_notifiers(net_io.clone()));
        notifiers
    }
}

fn get_net_header(iovec: &[libc::iovec], buf: &mut [u8]) -> Result<usize> {
    let mut start: usize = 0;
    let mut end: usize = 0;

    for elem in iovec {
        end = start
            .checked_add(elem.iov_len)
            .with_context(|| "Overflow when getting the net header")?;
        end = cmp::min(end, buf.len());
        mem_to_buf(&mut buf[start..end], elem.iov_base as u64)?;
        if end >= buf.len() {
            break;
        }
        start = end;
    }
    Ok(end)
}

fn build_event_notifier(
    fd: RawFd,
    handler: Option<Rc<NotifierCallback>>,
    op: NotifierOperation,
    event: EventSet,
) -> EventNotifier {
    let mut handlers = Vec::new();
    if let Some(h) = handler {
        handlers.push(h);
    }
    EventNotifier::new(op, fd, None, event, handlers)
}

impl EventNotifierHelper for NetIoHandler {
    fn internal_notifiers(net_io: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        // Register event notifier for update_evt.
        let locked_net_io = net_io.lock().unwrap();
        let cloned_net_io = net_io.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            if cloned_net_io
                .lock()
                .unwrap()
                .device_broken
                .load(Ordering::SeqCst)
            {
                return None;
            }
            Some(NetIoHandler::update_evt_handler(&cloned_net_io))
        });
        let mut notifiers = vec![build_event_notifier(
            locked_net_io.update_evt.as_raw_fd(),
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        )];

        // Register event notifier for rx.
        let cloned_net_io = net_io.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut locked_net_io = cloned_net_io.lock().unwrap();
            if locked_net_io.device_broken.load(Ordering::SeqCst) {
                return None;
            }

            if let Err(ref e) = locked_net_io.rx.recv_evt.write(1) {
                error!("Failed to trigger tap receive event, {:?}", e);
                report_virtio_error(
                    locked_net_io.interrupt_cb.clone(),
                    locked_net_io.driver_features,
                    &locked_net_io.device_broken,
                );
            }

            if let Some(tap) = locked_net_io.tap.as_ref() {
                if !locked_net_io.is_listening {
                    let notifier = vec![EventNotifier::new(
                        NotifierOperation::Resume,
                        tap.as_raw_fd(),
                        None,
                        EventSet::IN | EventSet::EDGE_TRIGGERED,
                        Vec::new(),
                    )];
                    locked_net_io.is_listening = true;
                    locked_net_io.rx.queue_full = false;
                    return Some(notifier);
                }
            }
            None
        });
        let rx_fd = locked_net_io.rx.queue_evt.as_raw_fd();
        notifiers.push(build_event_notifier(
            rx_fd,
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        ));

        // Register event notifier for tx.
        let cloned_net_io = net_io.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut locked_net_io = cloned_net_io.lock().unwrap();
            if locked_net_io.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            if let Err(ref e) = locked_net_io.handle_tx() {
                error!("Failed to handle tx(tx event) for net, {:?}", e);
                report_virtio_error(
                    locked_net_io.interrupt_cb.clone(),
                    locked_net_io.driver_features,
                    &locked_net_io.device_broken,
                );
            }
            None
        });
        let tx_fd = locked_net_io.tx.queue_evt.as_raw_fd();
        notifiers.push(build_event_notifier(
            tx_fd,
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        ));

        // Register event notifier for tap.
        let cloned_net_io = net_io.clone();
        if let Some(tap) = locked_net_io.tap.as_ref() {
            let handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
                let mut locked_net_io = cloned_net_io.lock().unwrap();
                if locked_net_io.device_broken.load(Ordering::SeqCst) {
                    return None;
                }

                if let Err(ref e) = locked_net_io.handle_rx() {
                    error!("Failed to handle rx(tap event), {:?}", e);
                    report_virtio_error(
                        locked_net_io.interrupt_cb.clone(),
                        locked_net_io.driver_features,
                        &locked_net_io.device_broken,
                    );
                    return None;
                }

                if let Some(tap) = locked_net_io.tap.as_ref() {
                    if locked_net_io.rx.queue_full && locked_net_io.is_listening {
                        let notifier = vec![EventNotifier::new(
                            NotifierOperation::Park,
                            tap.as_raw_fd(),
                            None,
                            EventSet::IN | EventSet::EDGE_TRIGGERED,
                            Vec::new(),
                        )];
                        locked_net_io.is_listening = false;
                        return Some(notifier);
                    }
                }
                None
            });
            let tap_fd = tap.as_raw_fd();
            notifiers.push(build_event_notifier(
                tap_fd,
                Some(handler.clone()),
                NotifierOperation::AddShared,
                EventSet::IN | EventSet::EDGE_TRIGGERED,
            ));
            let recv_evt_fd = locked_net_io.rx.recv_evt.as_raw_fd();
            notifiers.push(build_event_notifier(
                recv_evt_fd,
                Some(handler),
                NotifierOperation::AddShared,
                EventSet::IN | EventSet::EDGE_TRIGGERED,
            ));
        }

        notifiers
    }
}

/// Status of net device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct VirtioNetState {
    /// Bit mask of features supported by the backend.
    pub device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    pub driver_features: u64,
    /// Virtio net configurations.
    pub config_space: VirtioNetConfig,
    /// Device broken status.
    broken: bool,
}

/// Network device structure.
#[derive(Default)]
pub struct Net {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the network device.
    net_cfg: NetworkInterfaceConfig,
    /// Virtio net configurations.
    config_space: Arc<Mutex<VirtioNetConfig>>,
    /// Tap device opened.
    taps: Option<Vec<Tap>>,
    /// The send half of Rust's channel to send tap information.
    senders: Option<Vec<Sender<SenderConfig>>>,
    /// Eventfd for config space update.
    update_evts: Vec<Arc<EventFd>>,
    /// The information about control command.
    ctrl_info: Option<Arc<Mutex<CtrlInfo>>>,
}

impl Net {
    pub fn new(net_cfg: NetworkInterfaceConfig) -> Self {
        let queue_num = if net_cfg.mq {
            (net_cfg.queues + 1) as usize
        } else {
            QUEUE_NUM_NET
        };
        let queue_size = net_cfg.queue_size;

        Self {
            base: VirtioBase::new(VIRTIO_TYPE_NET, queue_num, queue_size),
            net_cfg,
            ..Default::default()
        }
    }
}

/// Set Mac address configured into the virtio configuration, and return features mask with
/// VIRTIO_NET_F_MAC set.
///
/// # Arguments
///
/// * `device_config` - Virtio net configurations.
/// * `mac` - Mac address configured by user.
pub fn build_device_config_space(device_config: &mut VirtioNetConfig, mac: &str) -> u64 {
    let mut bytes = [0_u8; 6];
    for (i, s) in mac.split(':').collect::<Vec<&str>>().iter().enumerate() {
        bytes[i] = if let Ok(v) = u8::from_str_radix(s, 16) {
            v
        } else {
            return 0_u64;
        };
    }
    device_config.mac.copy_from_slice(&bytes);
    1 << VIRTIO_NET_F_MAC
}

/// Mark the mac table used or free.
fn mark_mac_table(mac: &[u8], used: bool) {
    if mac[..MAC_ADDR_LEN - 1] != FIRST_DEFAULT_MAC[..MAC_ADDR_LEN - 1] {
        return;
    }
    let mut val = -1_i8;
    if used {
        val = 1;
    }
    let mut locked_mac_table = USED_MAC_TABLE.lock().unwrap();
    for i in FIRST_DEFAULT_MAC[MAC_ADDR_LEN - 1]..MAX_MAC_ADDR_NUM as u8 {
        if mac[MAC_ADDR_LEN - 1] == i {
            locked_mac_table[i as usize] += val;
        }
    }
}

/// Get a default free mac address.
fn get_default_mac_addr() -> Result<[u8; MAC_ADDR_LEN]> {
    let mut mac = [0_u8; MAC_ADDR_LEN];
    mac.copy_from_slice(&FIRST_DEFAULT_MAC);
    let mut locked_mac_table = USED_MAC_TABLE.lock().unwrap();
    for i in FIRST_DEFAULT_MAC[MAC_ADDR_LEN - 1]..MAX_MAC_ADDR_NUM as u8 {
        if locked_mac_table[i as usize] == 0 {
            mac[MAC_ADDR_LEN - 1] = i;
            locked_mac_table[i as usize] = 1;
            return Ok(mac);
        }
    }
    bail!("Failed to get a free mac address");
}

/// Check that tap flag supports multi queue feature.
///
/// # Arguments
///
/// * `dev_name` - The name of tap device on host.
/// * `queue_pairs` - The number of virtio queue pairs.
fn check_mq(dev_name: &str, queue_pair: u16) -> Result<()> {
    let path = format!("/sys/class/net/{}/tun_flags", dev_name);
    let tap_path = Path::new(&path);
    if !tap_path.exists() {
        warn!("Tap interface does not exist");
        return Ok(());
    }

    let is_mq = queue_pair > 1;
    let ifr_flag = fs::read_to_string(tap_path)
        .with_context(|| "Failed to read content from tun_flags file")?;
    let flags = str_to_num::<u16>(&ifr_flag)?;
    if (flags & IFF_MULTI_QUEUE != 0) && !is_mq {
        bail!(format!(
            "Tap device supports mq, but command set queue pairs {}.",
            queue_pair
        ));
    } else if (flags & IFF_MULTI_QUEUE == 0) && is_mq {
        bail!(format!(
            "Tap device doesn't support mq, but command set queue pairs {}.",
            queue_pair
        ));
    }

    Ok(())
}

/// Open tap device if no fd provided, configure and return it.
///
/// # Arguments
///
/// * `net_fd` - Fd of tap device opened.
/// * `host_dev_name` - Path of tap device on host.
/// * `queue_pairs` - The number of virtio queue pairs.
pub fn create_tap(
    net_fds: Option<&Vec<i32>>,
    host_dev_name: Option<&str>,
    queue_pairs: u16,
) -> Result<Option<Vec<Tap>>> {
    if net_fds.is_none() && host_dev_name.is_none() {
        return Ok(None);
    }
    if net_fds.is_some() && host_dev_name.is_some() {
        error!("Create tap: fd and file_path exist meanwhile (use fd by default)");
    }

    let mut taps = Vec::with_capacity(queue_pairs as usize);
    for index in 0..queue_pairs {
        let tap = if let Some(fds) = net_fds {
            let fd = fds
                .get(index as usize)
                .with_context(|| format!("Failed to get fd from index {}", index))?;
            Tap::new(None, Some(*fd), queue_pairs)
                .with_context(|| format!("Failed to create tap, index is {}", index))?
        } else {
            // `unwrap()` won't fail because the arguments have been checked
            let dev_name = host_dev_name.unwrap();
            check_mq(dev_name, queue_pairs)?;
            Tap::new(Some(dev_name), None, queue_pairs).with_context(|| {
                format!(
                    "Failed to create tap with name {}, index is {}",
                    dev_name, index
                )
            })?
        };

        tap.set_hdr_size(NET_HDR_LENGTH as u32)
            .with_context(|| "Failed to set tap hdr size")?;

        taps.push(tap);
    }

    Ok(Some(taps))
}

/// Get the tap offload flags from driver features.
///
/// # Arguments
///
/// * `features` - The driver features.
fn get_tap_offload_flags(features: u64) -> u32 {
    let mut flags: u32 = 0;
    if virtio_has_feature(features, VIRTIO_NET_F_GUEST_CSUM) {
        flags |= TUN_F_CSUM;
    }
    if virtio_has_feature(features, VIRTIO_NET_F_GUEST_TSO4) {
        flags |= TUN_F_TSO4;
    }
    if virtio_has_feature(features, VIRTIO_NET_F_GUEST_TSO6) {
        flags |= TUN_F_TSO6;
    }
    if virtio_has_feature(features, VIRTIO_NET_F_GUEST_ECN) {
        flags |= TUN_F_TSO_ECN;
    }
    if virtio_has_feature(features, VIRTIO_NET_F_GUEST_UFO) {
        flags |= TUN_F_UFO;
    }
    flags
}

impl VirtioDevice for Net {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        // if iothread not found, return err
        if self.net_cfg.iothread.is_some()
            && EventLoop::get_ctx(self.net_cfg.iothread.as_ref()).is_none()
        {
            bail!(
                "IOThread {:?} of Net is not configured in params.",
                self.net_cfg.iothread,
            );
        }

        let queue_pairs = self.net_cfg.queues / 2;
        if !self.net_cfg.host_dev_name.is_empty() {
            self.taps = create_tap(None, Some(&self.net_cfg.host_dev_name), queue_pairs)
                .with_context(|| "Failed to open tap with file path")?;
        } else if let Some(fds) = self.net_cfg.tap_fds.as_mut() {
            let mut created_fds = 0;
            if let Some(taps) = &self.taps {
                for (index, tap) in taps.iter().enumerate() {
                    if fds.get(index).map_or(-1, |fd| *fd as RawFd) == tap.as_raw_fd() {
                        created_fds += 1;
                    }
                }
            }

            if created_fds != fds.len() {
                self.taps = create_tap(Some(fds), None, queue_pairs)
                    .with_context(|| "Failed to open tap")?;
            }
        } else {
            self.taps = None;
        }

        self.init_config_features()?;

        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = 1 << VIRTIO_F_VERSION_1
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
            | 1 << VIRTIO_F_RING_INDIRECT_DESC
            | 1 << VIRTIO_F_RING_EVENT_IDX;

        let mut locked_config = self.config_space.lock().unwrap();

        let queue_pairs = self.net_cfg.queues / 2;
        if self.net_cfg.mq
            && (VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN..=VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX)
                .contains(&queue_pairs)
        {
            self.base.device_features |= 1 << VIRTIO_NET_F_MQ;
            locked_config.max_virtqueue_pairs = queue_pairs;
        }

        // Using the first tap to test if all the taps have ufo.
        if let Some(tap) = self.taps.as_ref().map(|t| &t[0]) {
            if !tap.has_ufo() {
                self.base.device_features &=
                    !(1 << VIRTIO_NET_F_GUEST_UFO | 1 << VIRTIO_NET_F_HOST_UFO);
            }
        }

        if let Some(mac) = &self.net_cfg.mac {
            self.base.device_features |= build_device_config_space(&mut locked_config, mac);
            mark_mac_table(&locked_config.mac, true);
        } else if locked_config.mac == [0; MAC_ADDR_LEN] {
            let mac =
                get_default_mac_addr().with_context(|| "Failed to get a default mac address")?;
            locked_config.mac.copy_from_slice(&mac);
            self.base.device_features |= 1 << VIRTIO_NET_F_MAC;
        } else {
            // For microvm which will call realize() twice for one virtio-net-device.
            self.base.device_features |= 1 << VIRTIO_NET_F_MAC;
        }

        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        mark_mac_table(&self.config_space.lock().unwrap().mac, false);
        MigrationManager::unregister_device_instance(
            VirtioNetState::descriptor(),
            &self.net_cfg.id,
        );
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let config_space = self.config_space.lock().unwrap();
        read_config_default(config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let mut config_space = self.config_space.lock().unwrap();
        let config_slice = &mut config_space.as_mut_bytes()[..MAC_ADDR_LEN];
        check_config_space_rw(config_slice, offset, data)?;

        let data_len = data.len();
        let driver_features = self.base.driver_features;
        if !virtio_has_feature(driver_features, VIRTIO_NET_F_CTRL_MAC_ADDR)
            && !virtio_has_feature(driver_features, VIRTIO_F_VERSION_1)
            && *data != config_slice[offset as usize..(offset as usize + data_len)]
        {
            config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);
        }

        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = self.base.queues.clone();
        let queue_num = queues.len();
        let ctrl_info = Arc::new(Mutex::new(CtrlInfo::new(self.config_space.clone())));
        self.ctrl_info = Some(ctrl_info.clone());
        let driver_features = self.base.driver_features;
        if (driver_features & 1 << VIRTIO_NET_F_CTRL_VQ != 0) && (queue_num % 2 != 0) {
            let ctrl_queue = queues[queue_num - 1].clone();
            let ctrl_queue_evt = queue_evts[queue_num - 1].clone();

            let ctrl_handler = NetCtrlHandler {
                ctrl: CtrlVirtio::new(ctrl_queue, ctrl_queue_evt, ctrl_info.clone()),
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features,
                device_broken: self.base.broken.clone(),
                taps: self.taps.clone(),
            };

            let notifiers =
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(ctrl_handler)));
            register_event_helper(
                notifiers,
                self.net_cfg.iothread.as_ref(),
                &mut self.base.deactivate_evts,
            )?;
        }

        // The features about offload is included in bits 0 to 31.
        let features = self.driver_features(0_u32);
        let flags = get_tap_offload_flags(features as u64);

        let mut senders = Vec::new();
        let queue_pairs = queue_num / 2;
        for index in 0..queue_pairs {
            let rx_queue = queues[index * 2].clone();
            let rx_queue_evt = queue_evts[index * 2].clone();
            let tx_queue = queues[index * 2 + 1].clone();
            let tx_queue_evt = queue_evts[index * 2 + 1].clone();

            let (sender, receiver) = channel();
            senders.push(sender);

            if let Some(tap) = self.taps.as_ref().map(|t| t[index].clone()) {
                tap.set_offload(flags)
                    .with_context(|| "Failed to set tap offload")?;
            }

            let update_evt = Arc::new(EventFd::new(libc::EFD_NONBLOCK)?);
            let recv_evt = Arc::new(EventFd::new(libc::EFD_NONBLOCK)?);
            let mut handler = NetIoHandler {
                rx: RxVirtio::new(rx_queue, rx_queue_evt, recv_evt),
                tx: TxVirtio::new(tx_queue, tx_queue_evt),
                tap: self.taps.as_ref().map(|t| t[index].clone()),
                tap_fd: -1,
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features,
                receiver,
                update_evt: update_evt.clone(),
                device_broken: self.base.broken.clone(),
                is_listening: true,
                ctrl_info: ctrl_info.clone(),
                queue_size: self.queue_size_max(),
            };
            if let Some(tap) = &handler.tap {
                handler.tap_fd = tap.as_raw_fd();
            }

            let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
            register_event_helper(
                notifiers,
                self.net_cfg.iothread.as_ref(),
                &mut self.base.deactivate_evts,
            )?;
            self.update_evts.push(update_evt);
        }
        self.senders = Some(senders);
        self.base.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn update_config(&mut self, dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        if let Some(conf) = dev_config {
            self.net_cfg = conf
                .as_any()
                .downcast_ref::<NetworkInterfaceConfig>()
                .unwrap()
                .clone();

            // Set tap offload.
            // The features about offload is included in bits 0 to 31.
            let features = self.driver_features(0_u32);
            let flags = get_tap_offload_flags(features as u64);
            if let Some(taps) = &self.taps {
                for (_, tap) in taps.iter().enumerate() {
                    tap.set_offload(flags)
                        .with_context(|| "Failed to set tap offload")?;
                }
            }
        } else {
            self.net_cfg = Default::default();
        }

        self.realize()?;

        if let Some(senders) = &self.senders {
            for (index, sender) in senders.iter().enumerate() {
                match self.taps.take() {
                    Some(taps) => {
                        let tap = taps
                            .get(index)
                            .cloned()
                            .with_context(|| format!("Failed to get index {} tap", index))?;
                        sender
                            .send(Some(tap))
                            .with_context(|| VirtioError::ChannelSend("tap fd".to_string()))?;
                    }
                    None => sender
                        .send(None)
                        .with_context(|| "Failed to send status of None to channel".to_string())?,
                }
            }

            for update_evt in &self.update_evts {
                update_evt
                    .write(1)
                    .with_context(|| VirtioError::EventFdWrite)?;
            }
        }

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(
            self.net_cfg.iothread.as_ref(),
            &mut self.base.deactivate_evts,
        )?;
        self.update_evts.clear();
        self.ctrl_info = None;
        Ok(())
    }
}

// SAFETY: Send and Sync is not auto-implemented for `Sender` type.
// Implementing them is safe because `Sender` field of Net won't
// change in migration workflow.
unsafe impl Sync for Net {}

impl StateTransfer for Net {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = VirtioNetState {
            device_features: self.base.device_features,
            driver_features: self.base.driver_features,
            config_space: *self.config_space.lock().unwrap(),
            broken: self.base.broken.load(Ordering::SeqCst),
        };
        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let s_len = std::mem::size_of::<VirtioNetState>();
        if state.len() != s_len {
            bail!("Invalid state length {}, expected {}", state.len(), s_len);
        }
        let state = VirtioNetState::from_bytes(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("NET"))?;
        self.base.device_features = state.device_features;
        self.base.driver_features = state.driver_features;
        self.base.broken.store(state.broken, Ordering::SeqCst);
        *self.config_space.lock().unwrap() = state.config_space;
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&VirtioNetState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for Net {}

#[cfg(test)]
mod tests {
    pub use super::*;

    #[test]
    fn test_net_init() {
        // test net new method
        let mut net = Net::new(NetworkInterfaceConfig::default());
        assert_eq!(net.base.device_features, 0);
        assert_eq!(net.base.driver_features, 0);

        assert_eq!(net.taps.is_none(), true);
        assert_eq!(net.senders.is_none(), true);
        assert_eq!(net.net_cfg.mac.is_none(), true);
        assert_eq!(net.net_cfg.tap_fds.is_none(), true);
        assert_eq!(net.net_cfg.vhost_type.is_none(), true);
        assert_eq!(net.net_cfg.vhost_fds.is_none(), true);

        // test net realize method
        net.realize().unwrap();
        assert_eq!(net.device_type(), 1);
        assert_eq!(net.queue_num(), 3);
        assert_eq!(net.queue_size_max(), 256);

        // test read_config and write_config method
        let write_data: Vec<u8> = vec![7; 4];
        let mut random_data: Vec<u8> = vec![0; 4];
        let mut origin_data: Vec<u8> = vec![0; 4];
        net.read_config(0x00, &mut origin_data).unwrap();

        net.write_config(0x00, &write_data).unwrap();
        net.read_config(0x00, &mut random_data).unwrap();
        assert_eq!(random_data, write_data);

        net.write_config(0x00, &origin_data).unwrap();

        // test boundary condition of offset and data parameters
        let config_space = net.config_space.lock().unwrap();
        let device_config = config_space.as_bytes();
        let len = device_config.len() as u64;
        drop(config_space);

        let mut data: Vec<u8> = vec![0; 10];
        let offset: u64 = len + 1;
        assert_eq!(net.read_config(offset, &mut data).is_ok(), false);

        let offset: u64 = len;
        assert_eq!(net.read_config(offset, &mut data).is_ok(), false);

        let offset: u64 = 0;
        assert_eq!(net.read_config(offset, &mut data).is_ok(), true);

        let offset: u64 = len;
        let mut data: Vec<u8> = vec![0; 1];
        assert_eq!(net.write_config(offset, &mut data).is_ok(), false);

        let offset: u64 = len - 1;
        let mut data: Vec<u8> = vec![0; 1];
        assert_eq!(net.write_config(offset, &mut data).is_ok(), false);

        let offset: u64 = 0;
        let mut data: Vec<u8> = vec![0; len as usize];
        assert_eq!(net.write_config(offset, &mut data).is_ok(), false);
    }

    #[test]
    fn test_net_create_tap() {
        // Test None net_fds and host_dev_name.
        assert!(create_tap(None, None, 16).unwrap().is_none());

        // Test create tap with net_fds and host_dev_name.
        let net_fds = vec![32, 33];
        let tap_name = "tap0";
        if let Err(err) = create_tap(Some(&net_fds), Some(&tap_name), 1) {
            let err_msg = format!("Failed to create tap, index is 0");
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }

        // Test create tap with empty net_fds.
        if let Err(err) = create_tap(Some(&vec![]), None, 1) {
            let err_msg = format!("Failed to get fd from index 0");
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }

        // Test create tap with tap_name which is not exist.
        if let Err(err) = create_tap(None, Some("the_tap_is_not_exist"), 1) {
            let err_msg =
                format!("Failed to create tap with name the_tap_is_not_exist, index is 0");
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_net_filter_vlan() {
        let mut ctrl_info = CtrlInfo::new(Arc::new(Mutex::new(VirtioNetConfig::default())));
        ctrl_info.rx_mode.promisc = false;
        let mut buf = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x00,
            0x00, 0x00,
        ];
        // It has no vla vid, the packet is filtered.
        assert_eq!(ctrl_info.filter_packets(&buf), true);

        // It has valid vlan id, the packet is not filtered.
        let vid: u16 = 1023;
        buf[ETHERNET_HDR_LENGTH] = u16::to_be_bytes(vid)[0];
        buf[ETHERNET_HDR_LENGTH + 1] = u16::to_be_bytes(vid)[1];
        ctrl_info.vlan_map.insert(vid >> 5, 1 << (vid & 0x1f));
        assert_eq!(ctrl_info.filter_packets(&buf), false);
    }

    #[test]
    fn test_net_config_space() {
        let mut net_config = VirtioNetConfig::default();
        // Parsing the normal mac address.
        let mac = "52:54:00:12:34:56";
        let ret = build_device_config_space(&mut net_config, &mac);
        assert_eq!(ret, 1 << VIRTIO_NET_F_MAC);

        // Parsing the abnormale mac address.
        let mac = "52:54:00:12:34:";
        let ret = build_device_config_space(&mut net_config, &mac);
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_mac_table() {
        let mut mac = FIRST_DEFAULT_MAC;
        // Add mac to mac table.
        mark_mac_table(&mac, true);
        assert_eq!(
            USED_MAC_TABLE.lock().unwrap()[mac[MAC_ADDR_LEN - 1] as usize],
            1
        );
        // Delete mac from mac table.
        mark_mac_table(&mac, false);
        assert_eq!(
            USED_MAC_TABLE.lock().unwrap()[mac[MAC_ADDR_LEN - 1] as usize],
            0
        );

        // Mac not in the default mac range.
        mac[0] += 1;
        mark_mac_table(&mac, true);
        assert_eq!(
            USED_MAC_TABLE.lock().unwrap()[mac[MAC_ADDR_LEN - 1] as usize],
            0
        );

        // Test no free mac in mac table.
        for i in FIRST_DEFAULT_MAC[MAC_ADDR_LEN - 1]..MAX_MAC_ADDR_NUM as u8 {
            USED_MAC_TABLE.lock().unwrap()[i as usize] = 1;
        }
        assert!(get_default_mac_addr().is_err());
        // Recover it.
        for i in FIRST_DEFAULT_MAC[MAC_ADDR_LEN - 1]..MAX_MAC_ADDR_NUM as u8 {
            USED_MAC_TABLE.lock().unwrap()[i as usize] = 0;
        }
    }

    #[test]
    fn test_iothread() {
        let mut net = Net::new(NetworkInterfaceConfig::default());
        net.net_cfg.iothread = Some("iothread".to_string());
        if let Err(err) = net.realize() {
            let err_msg = format!(
                "IOThread {:?} of Net is not configured in params.",
                net.net_cfg.iothread
            );
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }
    }
}
