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
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::{cmp, fs, mem};

use anyhow::{bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use log::{error, warn};
use once_cell::sync::Lazy;
use util::aio::Iovec;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use crate::{
    check_config_space_rw, gpa_hva_iovec_map, iov_discard_front, iov_to_buf, mem_to_buf,
    read_config_default, report_virtio_error, virtio_has_feature, ElemIovec, Element, Queue,
    VirtioBase, VirtioDevice, VirtioError, VirtioInterrupt, VirtioInterruptType, VirtioNetHdr,
    VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1, VIRTIO_NET_CTRL_MAC,
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
use address_space::{AddressAttr, AddressSpace};
use machine_manager::config::{ConfigCheck, NetDevcfg, NetworkInterfaceConfig};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper, EventLoop};
use machine_manager::state_query::{
    register_state_query_callback, unregister_state_query_callback,
};
use migration::{
    migration::Migratable, DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager,
    StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::gen_base_func;
use util::loop_context::{
    create_new_eventfd, read_fd, EventNotifier, EventNotifierHelper, NotifierCallback,
    NotifierOperation,
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
        let mut mac_table_len: usize = 0;
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

            let size = u64::from(entries) * MAC_ADDR_LEN as u64;
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
        if u16::from(cmd) == VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET {
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
    iov_to_buf(mem_space, &None, iovec, buf).and_then(|size| {
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
                .first()
                .with_context(|| "Failed to get device writable iovec")?;
            self.mem_space
                .write_object::<u8>(&ack, status.addr, AddressAttr::Ram)?;

            locked_queue
                .vring
                .add_used(elem.index, mem::size_of_val(&ack) as u32)
                .with_context(|| format!("Failed to add used ring {}", elem.index))?;

            if locked_queue.vring.should_notify(self.driver_features) {
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

struct RTxVirtio {
    queue: Arc<Mutex<Queue>>,
    queue_evt: Arc<EventFd>,
}

impl RTxVirtio {
    fn new(queue: Arc<Mutex<Queue>>, queue_evt: Arc<EventFd>) -> Self {
        TxVirtio { queue, queue_evt }
    }
}

type RxVirtio = RTxVirtio;
type TxVirtio = RTxVirtio;

struct NetIoQueue {
    rx: RxVirtio,
    tx: TxVirtio,
    ctrl_info: Arc<Mutex<CtrlInfo>>,
    mem_space: Arc<AddressSpace>,
    interrupt_cb: Arc<VirtioInterrupt>,
    listen_state: Arc<Mutex<ListenState>>,
    driver_features: u64,
    queue_size: u16,
}

impl NetIoQueue {
    fn handle_rx(&self, tap: &Arc<RwLock<Option<Tap>>>) -> Result<()> {
        trace::virtio_receive_request("Net".to_string(), "to rx".to_string());
        if tap.read().unwrap().is_none() {
            return Ok(());
        }

        let mut queue = self.rx.queue.lock().unwrap();
        let mut rx_packets: u16 = 0;
        loop {
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for net rx")?;
            if elem.desc_num == 0 {
                queue
                    .vring
                    .suppress_queue_notify(self.driver_features, false)
                    .with_context(|| "Failed to enable rx queue notify")?;
                self.listen_state.lock().unwrap().set_queue_avail(false);
                break;
            } else if elem.in_iovec.is_empty() {
                bail!("The length of in iovec is 0");
            }
            let (_, iovecs) =
                gpa_hva_iovec_map(&elem.in_iovec, &self.mem_space, queue.vring.get_cache())?;

            if MigrationManager::is_active() {
                // FIXME: mark dirty page needs to be managed by `AddressSpace` crate.
                for iov in iovecs.iter() {
                    // Mark vmm dirty page manually if live migration is active.
                    MigrationManager::mark_dirty_log(iov.iov_base, iov.iov_len);
                }
            }

            // Read the data from the tap device.
            let locked_tap = tap.read().unwrap();
            let size = if locked_tap.is_some() {
                locked_tap.as_ref().unwrap().receive_packets(&iovecs)
            } else {
                -1
            };
            drop(locked_tap);
            if size < (NET_HDR_LENGTH + ETHERNET_HDR_LENGTH + VLAN_TAG_LENGTH) as isize {
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
                .add_used(elem.index, u32::try_from(size)?)
                .with_context(|| {
                    format!(
                        "Failed to add used ring for net rx, index: {}, len: {}",
                        elem.index, size
                    )
                })?;

            if queue.vring.should_notify(self.driver_features) {
                (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue), false)
                    .with_context(|| {
                        VirtioError::InterruptTrigger("net", VirtioInterruptType::Vring)
                    })?;
                trace::virtqueue_send_interrupt("Net", &*queue as *const _ as u64);
            }

            rx_packets += 1;
            if rx_packets >= self.queue_size {
                self.rx
                    .queue_evt
                    .write(1)
                    .with_context(|| "Failed to trigger rx queue event".to_string())?;
                break;
            }
        }

        Ok(())
    }

    fn handle_tx(&self, tap: &Arc<RwLock<Option<Tap>>>) -> Result<()> {
        trace::virtio_receive_request("Net".to_string(), "to tx".to_string());
        let mut queue = self.tx.queue.lock().unwrap();

        let mut tx_packets: u16 = 0;
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

            let (_, iovecs) =
                gpa_hva_iovec_map(&elem.out_iovec, &self.mem_space, queue.vring.get_cache())?;
            let locked_tap = tap.read().unwrap();
            if locked_tap.is_none() || locked_tap.as_ref().unwrap().send_packets(&iovecs) == -1 {
                queue.vring.push_back();
                queue
                    .vring
                    .suppress_queue_notify(self.driver_features, true)
                    .with_context(|| "Failed to suppress tx queue notify")?;
                self.listen_state.lock().unwrap().set_tap_full(true);
                break;
            }
            drop(locked_tap);

            queue
                .vring
                .add_used(elem.index, 0)
                .with_context(|| format!("Net tx: Failed to add used ring {}", elem.index))?;

            if queue.vring.should_notify(self.driver_features) {
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
}

struct ListenState {
    queue_avail: bool,
    tap_full: bool,
    is_listening: bool,
    has_changed: bool,
}

impl ListenState {
    fn new() -> Self {
        Self {
            queue_avail: true,
            tap_full: false,
            is_listening: true,
            has_changed: false,
        }
    }

    fn set_tap_full(&mut self, value: bool) {
        if self.tap_full == value {
            return;
        }
        self.tap_full = value;
        self.has_changed = true;
    }

    fn set_queue_avail(&mut self, value: bool) {
        if self.queue_avail == value {
            return;
        }
        self.queue_avail = value;
        self.has_changed = true;
    }

    fn tap_fd_handler(&mut self, tap: &Tap) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        if !self.is_listening && (self.queue_avail || self.tap_full) {
            notifiers.push(EventNotifier::new(
                NotifierOperation::Resume,
                tap.as_raw_fd(),
                None,
                EventSet::empty(),
                Vec::new(),
            ));
            self.is_listening = true;
        }

        if !self.is_listening {
            return notifiers;
        }

        // NOTE: We want to poll for OUT event when the tap is full, and for IN event when the
        // virtio queue is available.
        let tap_events = match (self.queue_avail, self.tap_full) {
            (true, true) => EventSet::OUT | EventSet::IN | EventSet::EDGE_TRIGGERED,
            (false, true) => EventSet::OUT | EventSet::EDGE_TRIGGERED,
            (true, false) => EventSet::IN | EventSet::EDGE_TRIGGERED,
            (false, false) => EventSet::empty(),
        };

        let tap_operation = if tap_events.is_empty() {
            self.is_listening = false;
            NotifierOperation::Park
        } else {
            NotifierOperation::Modify
        };

        notifiers.push(EventNotifier::new(
            tap_operation,
            tap.as_raw_fd(),
            None,
            tap_events,
            Vec::new(),
        ));
        notifiers
    }
}

fn get_net_header(iovec: &[Iovec], buf: &mut [u8]) -> Result<usize> {
    let mut start: usize = 0;
    let mut end: usize = 0;

    for elem in iovec {
        end = start
            .checked_add(elem.iov_len as usize)
            .with_context(|| "Overflow when getting the net header")?;
        end = cmp::min(end, buf.len());
        // SAFETY: iovec is generated by address_space and len is not less than buf's.
        unsafe {
            mem_to_buf(&mut buf[start..end], elem.iov_base)?;
        }
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

struct NetIoHandler {
    /// The context name of iothread for tap and rx virtio queue.
    /// Since we placed the handlers of RxVirtio, TxVirtio and tap_fd in different threads,
    /// thread name is needed to change the monitoring status of tap_fd.
    rx_iothread: Option<String>,
    /// Virtio queue used for net io.
    net_queue: Arc<NetIoQueue>,
    /// The context of tap device.
    tap: Arc<RwLock<Option<Tap>>>,
    /// Device is broken or not.
    device_broken: Arc<AtomicBool>,
    /// The receiver half of Rust's channel to recv tap information.
    receiver: Receiver<SenderConfig>,
    /// Eventfd for config space update.
    update_evt: Arc<EventFd>,
}

impl NetIoHandler {
    fn update_evt_handler(&mut self) -> Result<()> {
        let mut locked_tap = self.tap.write().unwrap();
        let old_tap_fd = if locked_tap.is_some() {
            locked_tap.as_ref().unwrap().as_raw_fd()
        } else {
            -1
        };

        *locked_tap = match self.receiver.recv() {
            Ok(tap) => tap,
            Err(e) => {
                error!("Failed to receive the tap {:?}", e);
                None
            }
        };
        drop(locked_tap);

        if old_tap_fd != -1 {
            unregister_event_helper(self.rx_iothread.as_ref(), &mut vec![old_tap_fd])?;
        }
        if self.tap.read().unwrap().is_some() {
            EventLoop::update_event(self.tap_notifier(), self.rx_iothread.as_ref())?;
        }
        Ok(())
    }

    /// Register event notifier for update_evt.
    fn update_evt_notifier(&self, net_io: Arc<Mutex<NetIoHandler>>) -> Vec<EventNotifier> {
        let device_broken = self.device_broken.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);

            if device_broken.load(Ordering::SeqCst) {
                return None;
            }

            if let Err(e) = net_io.lock().unwrap().update_evt_handler() {
                error!("Update net events failed: {:?}", e);
            }

            None
        });
        let notifiers = vec![build_event_notifier(
            self.update_evt.as_raw_fd(),
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        )];
        notifiers
    }

    /// Register event notifier for rx.
    fn rx_virtio_notifier(&self) -> Vec<EventNotifier> {
        let net_queue = self.net_queue.clone();
        let device_broken = self.device_broken.clone();
        let tap = self.tap.clone();
        let rx_iothread = self.rx_iothread.as_ref().cloned();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);

            if device_broken.load(Ordering::SeqCst) {
                return None;
            }

            net_queue.listen_state.lock().unwrap().set_queue_avail(true);
            let mut locked_queue = net_queue.rx.queue.lock().unwrap();

            if let Err(ref err) = locked_queue
                .vring
                .suppress_queue_notify(net_queue.driver_features, true)
            {
                error!("Failed to suppress rx queue notify: {:?}", err);
                report_virtio_error(
                    net_queue.interrupt_cb.clone(),
                    net_queue.driver_features,
                    &device_broken,
                );
                return None;
            };

            drop(locked_queue);

            if let Err(ref err) = net_queue.handle_rx(&tap) {
                error!("Failed to handle receive queue event: {:?}", err);
                report_virtio_error(
                    net_queue.interrupt_cb.clone(),
                    net_queue.driver_features,
                    &device_broken,
                );
                return None;
            }

            let mut locked_listen = net_queue.listen_state.lock().unwrap();
            let locked_tap = tap.read().unwrap();
            if locked_tap.is_none() || !locked_listen.has_changed {
                return None;
            }

            let notifiers = locked_listen.tap_fd_handler(locked_tap.as_ref().unwrap());
            locked_listen.has_changed = false;
            drop(locked_tap);
            drop(locked_listen);

            if let Err(e) = EventLoop::update_event(notifiers, rx_iothread.as_ref()) {
                error!("Update tap notifiers failed in handle rx: {:?}", e);
            }
            None
        });
        let rx_fd = self.net_queue.rx.queue_evt.as_raw_fd();
        let notifiers = vec![build_event_notifier(
            rx_fd,
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        )];
        notifiers
    }

    /// Register event notifier for tx.
    fn tx_virtio_notifier(&self) -> Vec<EventNotifier> {
        let net_queue = self.net_queue.clone();
        let device_broken = self.device_broken.clone();
        let tap = self.tap.clone();
        let rx_iothread = self.rx_iothread.as_ref().cloned();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);

            if device_broken.load(Ordering::SeqCst) {
                return None;
            }

            if let Err(ref e) = net_queue.handle_tx(&tap) {
                error!("Failed to handle tx(tx event) for net, {:?}", e);
                report_virtio_error(
                    net_queue.interrupt_cb.clone(),
                    net_queue.driver_features,
                    &device_broken,
                );
            }

            let mut locked_listen = net_queue.listen_state.lock().unwrap();
            let locked_tap = tap.read().unwrap();
            if locked_tap.is_none() || !locked_listen.has_changed {
                return None;
            }

            let notifiers = locked_listen.tap_fd_handler(locked_tap.as_ref().unwrap());
            locked_listen.has_changed = false;
            drop(locked_tap);
            drop(locked_listen);

            if let Err(e) = EventLoop::update_event(notifiers, rx_iothread.as_ref()) {
                error!("Update tap notifiers failed in handle tx: {:?}", e);
            }

            None
        });
        let tx_fd = self.net_queue.tx.queue_evt.as_raw_fd();
        let notifiers = vec![build_event_notifier(
            tx_fd,
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        )];
        notifiers
    }

    /// Register event notifier for tap.
    fn tap_notifier(&self) -> Vec<EventNotifier> {
        let tap = self.tap.clone();
        let net_queue = self.net_queue.clone();
        let device_broken = self.device_broken.clone();
        let locked_tap = self.tap.read().unwrap();
        if locked_tap.is_none() {
            return vec![];
        }
        let handler: Rc<NotifierCallback> = Rc::new(move |events: EventSet, _| {
            if device_broken.load(Ordering::SeqCst) {
                return None;
            }

            if events.contains(EventSet::OUT) {
                net_queue.listen_state.lock().unwrap().set_tap_full(false);
                net_queue
                    .tx
                    .queue_evt
                    .write(1)
                    .unwrap_or_else(|e| error!("Failed to notify tx thread: {:?}", e));
            }

            if events.contains(EventSet::IN) {
                if let Err(ref err) = net_queue.handle_rx(&tap) {
                    error!("Failed to handle receive queue event: {:?}", err);
                    report_virtio_error(
                        net_queue.interrupt_cb.clone(),
                        net_queue.driver_features,
                        &device_broken,
                    );
                    return None;
                }
            }

            let mut locked_listen = net_queue.listen_state.lock().unwrap();
            let locked_tap = tap.read().unwrap();
            if !locked_listen.has_changed || locked_tap.is_none() {
                return None;
            }
            let tap_notifiers = locked_listen.tap_fd_handler(locked_tap.as_ref().unwrap());
            locked_listen.has_changed = false;
            drop(locked_tap);
            drop(locked_listen);

            Some(tap_notifiers)
        });
        let tap_fd = locked_tap.as_ref().unwrap().as_raw_fd();
        let notifiers = vec![build_event_notifier(
            tap_fd,
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN | EventSet::EDGE_TRIGGERED,
        )];

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
    /// Configuration of the network device.
    netdev_cfg: NetDevcfg,
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
    /// The deactivate events for receiving.
    rx_deactivate_evts: Vec<RawFd>,
    /// The deactivate events for transporting.
    tx_deactivate_evts: Vec<RawFd>,
}

impl Net {
    pub fn new(net_cfg: NetworkInterfaceConfig, netdev_cfg: NetDevcfg) -> Self {
        let queue_num = if net_cfg.mq {
            (netdev_cfg.queues + 1) as usize
        } else {
            QUEUE_NUM_NET
        };
        let queue_size = net_cfg.queue_size;

        Self {
            base: VirtioBase::new(VIRTIO_TYPE_NET, queue_num, queue_size),
            net_cfg,
            netdev_cfg,
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
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

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

        let queue_pairs = self.netdev_cfg.queues / 2;
        if !self.netdev_cfg.ifname.is_empty() {
            self.taps = create_tap(None, Some(&self.netdev_cfg.ifname), queue_pairs)
                .with_context(|| "Failed to open tap with file path")?;
        } else if let Some(fds) = self.netdev_cfg.tap_fds.as_mut() {
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

        if let Some(ref taps) = self.taps {
            for (idx, tap) in taps.iter().enumerate() {
                let upload_stats = tap.upload_stats.clone();
                let download_stats = tap.download_stats.clone();
                register_state_query_callback(
                    format!("tap-{}", idx),
                    Arc::new(move || {
                        let upload = upload_stats.load(Ordering::SeqCst);
                        let download = download_stats.load(Ordering::SeqCst);
                        format!("upload: {} download: {}", upload, download)
                    }),
                )
            }
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

        let queue_pairs = self.netdev_cfg.queues / 2;
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
        if let Some(ref taps) = self.taps {
            for (idx, _) in taps.iter().enumerate() {
                unregister_state_query_callback(&format!("tap-{}", idx));
            }
        }
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
        let flags = get_tap_offload_flags(u64::from(features));

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

            let update_evt = Arc::new(create_new_eventfd()?);
            let net_queue = Arc::new(NetIoQueue {
                rx: RxVirtio::new(rx_queue, rx_queue_evt),
                tx: TxVirtio::new(tx_queue, tx_queue_evt),
                ctrl_info: ctrl_info.clone(),
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features,
                listen_state: Arc::new(Mutex::new(ListenState::new())),
                queue_size: self.queue_size_max(),
            });
            let tap = Arc::new(RwLock::new(self.taps.as_ref().map(|t| t[index].clone())));
            let net_io = Arc::new(Mutex::new(NetIoHandler {
                rx_iothread: self.net_cfg.rx_iothread.as_ref().cloned(),
                net_queue,
                tap,
                device_broken: self.base.broken.clone(),
                receiver,
                update_evt: update_evt.clone(),
            }));
            let cloned_net_io = net_io.clone();
            let locked_net_io = net_io.lock().unwrap();
            let update_evt_notifiers = locked_net_io.update_evt_notifier(cloned_net_io);
            let rx_notifiers = locked_net_io.rx_virtio_notifier();
            let tx_notifiers = locked_net_io.tx_virtio_notifier();
            let tap_notifiers = locked_net_io.tap_notifier();
            drop(locked_net_io);
            register_event_helper(
                update_evt_notifiers,
                self.net_cfg.iothread.as_ref(),
                &mut self.base.deactivate_evts,
            )?;
            register_event_helper(
                rx_notifiers,
                self.net_cfg.rx_iothread.as_ref(),
                &mut self.rx_deactivate_evts,
            )?;
            register_event_helper(
                tap_notifiers,
                self.net_cfg.rx_iothread.as_ref(),
                &mut self.rx_deactivate_evts,
            )?;
            register_event_helper(
                tx_notifiers,
                self.net_cfg.tx_iothread.as_ref(),
                &mut self.tx_deactivate_evts,
            )?;
            self.update_evts.push(update_evt);
        }
        self.senders = Some(senders);
        self.base.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    // configs[0]: NetDevcfg. configs[1]: NetworkInterfaceConfig.
    fn update_config(&mut self, dev_config: Vec<Arc<dyn ConfigCheck>>) -> Result<()> {
        if dev_config.len() == 2 {
            self.netdev_cfg = dev_config[0]
                .as_any()
                .downcast_ref::<NetDevcfg>()
                .unwrap()
                .clone();
            self.net_cfg = dev_config[1]
                .as_any()
                .downcast_ref::<NetworkInterfaceConfig>()
                .unwrap()
                .clone();

            // Set tap offload.
            // The features about offload is included in bits 0 to 31.
            let features = self.driver_features(0_u32);
            let flags = get_tap_offload_flags(u64::from(features));
            if let Some(taps) = &self.taps {
                for tap in taps.iter() {
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
        unregister_event_helper(
            self.net_cfg.rx_iothread.as_ref(),
            &mut self.rx_deactivate_evts,
        )?;
        unregister_event_helper(
            self.net_cfg.tx_iothread.as_ref(),
            &mut self.tx_deactivate_evts,
        )?;
        self.update_evts.clear();
        self.ctrl_info = None;
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        if let Some(ref mut taps) = self.taps {
            for tap in taps.iter_mut() {
                tap.download_stats.store(0, Ordering::SeqCst);
                tap.upload_stats.store(0, Ordering::SeqCst);
            }
        }
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
    use super::*;

    #[test]
    fn test_net_init() {
        // test net new method
        let mut net = Net::new(NetworkInterfaceConfig::default(), NetDevcfg::default());
        assert_eq!(net.base.device_features, 0);
        assert_eq!(net.base.driver_features, 0);

        assert!(net.taps.is_none());
        assert!(net.senders.is_none());
        assert!(net.net_cfg.mac.is_none());
        assert!(net.netdev_cfg.tap_fds.is_none());
        assert!(net.netdev_cfg.vhost_type().is_none());
        assert!(net.netdev_cfg.vhost_fds.is_none());

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
        assert!(net.read_config(offset, &mut data).is_err());

        let offset: u64 = len;
        assert!(net.read_config(offset, &mut data).is_err());

        let offset: u64 = 0;
        assert!(net.read_config(offset, &mut data).is_ok());

        let offset: u64 = len;
        let mut data: Vec<u8> = vec![0; 1];
        assert!(net.write_config(offset, &mut data).is_err());

        let offset: u64 = len - 1;
        let mut data: Vec<u8> = vec![0; 1];
        assert!(net.write_config(offset, &mut data).is_err());

        let offset: u64 = 0;
        let mut data: Vec<u8> = vec![0; len as usize];
        assert!(net.write_config(offset, &mut data).is_err());
    }

    #[test]
    fn test_net_create_tap() {
        // Test None net_fds and host_dev_name.
        assert!(create_tap(None, None, 16).unwrap().is_none());

        // Test create tap with net_fds and host_dev_name.
        let net_fds = vec![32, 33];
        let tap_name = "tap0";
        if let Err(err) = create_tap(Some(&net_fds), Some(tap_name), 1) {
            let err_msg = "Failed to create tap, index is 0".to_string();
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }

        // Test create tap with empty net_fds.
        if let Err(err) = create_tap(Some(&vec![]), None, 1) {
            let err_msg = "Failed to get fd from index 0".to_string();
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }

        // Test create tap with tap_name which is not exist.
        if let Err(err) = create_tap(None, Some("the_tap_is_not_exist"), 1) {
            let err_msg =
                "Failed to create tap with name the_tap_is_not_exist, index is 0".to_string();
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
        assert!(ctrl_info.filter_packets(&buf));

        // It has valid vlan id, the packet is not filtered.
        let vid: u16 = 1023;
        buf[ETHERNET_HDR_LENGTH] = u16::to_be_bytes(vid)[0];
        buf[ETHERNET_HDR_LENGTH + 1] = u16::to_be_bytes(vid)[1];
        ctrl_info.vlan_map.insert(vid >> 5, 1 << (vid & 0x1f));
        assert!(!ctrl_info.filter_packets(&buf));
    }

    #[test]
    fn test_net_config_space() {
        let mut net_config = VirtioNetConfig::default();
        // Parsing the normal mac address.
        let mac = "52:54:00:12:34:56";
        let ret = build_device_config_space(&mut net_config, mac);
        assert_eq!(ret, 1 << VIRTIO_NET_F_MAC);

        // Parsing the abnormale mac address.
        let mac = "52:54:00:12:34:";
        let ret = build_device_config_space(&mut net_config, mac);
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
        EventLoop::object_init(&None).unwrap();

        let mut net = Net::new(NetworkInterfaceConfig::default(), NetDevcfg::default());
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

        EventLoop::loop_clean();
    }
}
