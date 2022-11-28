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
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::{cmp, fs, mem};

use super::{
    Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VirtioNetHdr, VirtioTrace,
    VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1, VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_ADDR_SET,
    VIRTIO_NET_CTRL_MAC_TABLE_SET, VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, VIRTIO_NET_CTRL_RX,
    VIRTIO_NET_CTRL_RX_ALLMULTI, VIRTIO_NET_CTRL_RX_ALLUNI, VIRTIO_NET_CTRL_RX_NOBCAST,
    VIRTIO_NET_CTRL_RX_NOMULTI, VIRTIO_NET_CTRL_RX_NOUNI, VIRTIO_NET_CTRL_RX_PROMISC,
    VIRTIO_NET_CTRL_VLAN, VIRTIO_NET_CTRL_VLAN_ADD, VIRTIO_NET_CTRL_VLAN_DEL, VIRTIO_NET_ERR,
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_CTRL_MAC_ADDR, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_ECN, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO6, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MQ, VIRTIO_NET_OK, VIRTIO_TYPE_NET,
};
use crate::{
    iov_discard_front, iov_to_buf, mem_to_buf, report_virtio_error, virtio_has_feature, ElemIovec,
    Element, VirtioError,
};
use address_space::AddressSpace;
use anyhow::{anyhow, bail, Context, Result};
use log::error;
use machine_manager::{
    config::{ConfigCheck, NetworkInterfaceConfig},
    event_loop::EventLoop,
};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::read_u32;
use util::tap::{
    Tap, IFF_MULTI_QUEUE, TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6, TUN_F_TSO_ECN, TUN_F_UFO,
};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};
/// Number of virtqueues.
const QUEUE_NUM_NET: usize = 2;
/// Size of each virtqueue.
const QUEUE_SIZE_NET: u16 = 256;
/// The Mac Address length.
pub const MAC_ADDR_LEN: usize = 6;
/// The length of ethernet header.
const ETHERNET_HDR_LENGTH: usize = 14;
/// The max "multicast + unicast" mac address table length.
const CTRL_MAC_TABLE_LEN: usize = 64;
/// From 802.1Q definition, the max vlan ID.
const CTRL_MAX_VLAN: u16 = 1 << 12;

type SenderConfig = Option<Tap>;

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
pub struct CtrlRxMode {
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
    pub address: [u8; MAC_ADDR_LEN],
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
    state: Arc<Mutex<VirtioNetState>>,
}

impl CtrlInfo {
    fn new(state: Arc<Mutex<VirtioNetState>>) -> Self {
        CtrlInfo {
            rx_mode: CtrlRxMode::default(),
            mac_info: CtrlMacInfo::default(),
            vlan_map: HashMap::new(),
            state,
        }
    }

    fn handle_rx_mode(
        &mut self,
        mem_space: &AddressSpace,
        cmd: u8,
        data_iovec: &mut Vec<ElemIovec>,
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
                .with_context(|| "Failed to get unicast MAC entries".to_string())?;
            if entries == 0 {
                mac_table.clear();
                continue;
            }

            let mut macs = vec![0_u8; entries as usize * MAC_ADDR_LEN];
            *data_iovec = get_buf_and_discard(mem_space, data_iovec, &mut macs)
                .with_context(|| "Failed to get multicast MAC entries".to_string())?;
            if entries as usize > CTRL_MAC_TABLE_LEN - mac_table_len {
                *overflow = true;
                mac_table.clear();
                continue;
            }

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
                        error!("Failed to get MAC address, error is {}", e);
                        ack = VIRTIO_NET_ERR;
                        Vec::new()
                    });
                if ack == VIRTIO_NET_ERR {
                    return VIRTIO_NET_ERR;
                }
                self.state
                    .lock()
                    .unwrap()
                    .config_space
                    .mac
                    .copy_from_slice(&mac);
            }
            VIRTIO_NET_CTRL_MAC_TABLE_SET => {
                ack = self
                    .set_mac_table(mem_space, data_iovec)
                    .unwrap_or_else(|e| {
                        error!("Failed to get Unicast Mac address, error is {}", e);
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
                error!("Failed to get vlan id, error is {}", e);
                ack = VIRTIO_NET_ERR;
                Vec::new()
            });
        if ack == VIRTIO_NET_ERR {
            return ack;
        }
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

    fn filter_packets(&mut self, buf: &[u8]) -> bool {
        // Broadcast address: 0xff:0xff:0xff:0xff:0xff:0xff.
        let bcast = [0xff; MAC_ADDR_LEN];
        // TPID of the vlan tag, defined in IEEE 802.1Q, is 0x8100.
        let vlan = [0x81, 0x00];

        if self.rx_mode.promisc {
            return false;
        }

        if buf[..vlan.len()] == vlan {
            let vid = u16::from_be_bytes([buf[14], buf[15]]);
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
                || buf[..MAC_ADDR_LEN] == self.state.lock().unwrap().config_space.mac
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
    iovec: &mut Vec<ElemIovec>,
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
    queue_evt: EventFd,
    /// The information about control command.
    ctrl_info: Option<Arc<Mutex<CtrlInfo>>>,
}

impl CtrlVirtio {
    pub fn new(
        queue: Arc<Mutex<Queue>>,
        queue_evt: EventFd,
        ctrl_info: Option<Arc<Mutex<CtrlInfo>>>,
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
    /// Deactivate event to delete net control handler.
    pub deactivate_evt: EventFd,
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
            if in_size < mem::size_of_val(&ack) as u32
                || out_size < mem::size_of::<CtrlHdr>() as u32
            {
                bail!(
                    "Invalid length, in_iovec size is {}, out_iovec size is {}",
                    in_size,
                    out_size
                );
            }

            // Get the control information first.
            let ctrl_info = if let Some(ctrl_info) = &self.ctrl.ctrl_info {
                ctrl_info
            } else {
                bail!("Control information is None");
            };

            // Get the control request header.
            let mut ctrl_hdr = CtrlHdr::default();
            let mut data_iovec = get_buf_and_discard(
                &self.mem_space,
                &mut elem.out_iovec,
                ctrl_hdr.as_mut_bytes(),
            )
            .with_context(|| "Failed to get control header")?;

            match ctrl_hdr.class {
                VIRTIO_NET_CTRL_RX => {
                    ack = ctrl_info
                        .lock()
                        .unwrap()
                        .handle_rx_mode(&self.mem_space, ctrl_hdr.cmd, &mut data_iovec)
                        .unwrap_or_else(|e| {
                            error!("Failed to handle rx mode, error is {}", e);
                            VIRTIO_NET_ERR
                        });
                }
                VIRTIO_NET_CTRL_MAC => {
                    ack = ctrl_info.lock().unwrap().handle_mac(
                        &self.mem_space,
                        ctrl_hdr.cmd,
                        &mut data_iovec,
                    );
                }
                VIRTIO_NET_CTRL_VLAN => {
                    ack = ctrl_info.lock().unwrap().handle_vlan_table(
                        &self.mem_space,
                        ctrl_hdr.cmd,
                        &mut data_iovec,
                    );
                }
                VIRTIO_NET_CTRL_MQ => {
                    if ctrl_hdr.cmd as u16 != VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET {
                        error!(
                            "Control queue header command can't match {}",
                            VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET
                        );
                        ack = VIRTIO_NET_ERR;
                    }
                    if let Some(mq_desc) = elem.out_iovec.get(1) {
                        let queue_pairs = self
                            .mem_space
                            .read_object::<u16>(mq_desc.addr)
                            .with_context(|| "Failed to read multi queue descriptor")?;
                        if !(VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN..=VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX)
                            .contains(&queue_pairs)
                        {
                            error!("Invalid queue pairs {}", queue_pairs);
                            ack = VIRTIO_NET_ERR;
                        }
                    }
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
                        anyhow!(VirtioError::InterruptTrigger(
                            "ctrl",
                            VirtioInterruptType::Vring
                        ))
                    })?;
            }
        }

        Ok(())
    }

    fn deactivate_evt_handler(&mut self) -> Vec<EventNotifier> {
        let notifiers = vec![
            EventNotifier::new(
                NotifierOperation::Delete,
                self.ctrl.queue_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.deactivate_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
        ];

        notifiers
    }
}

impl EventNotifierHelper for NetCtrlHandler {
    fn internal_notifiers(net_io: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let locked_net_io = net_io.lock().unwrap();
        let cloned_net_io = net_io.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut locked_net_io = cloned_net_io.lock().unwrap();
            locked_net_io.handle_ctrl().unwrap_or_else(|e| {
                error!("Failed to handle ctrl queue, error is {}.", e);
                report_virtio_error(
                    locked_net_io.interrupt_cb.clone(),
                    locked_net_io.driver_features,
                    Some(&locked_net_io.deactivate_evt),
                );
            });
            None
        });
        let mut notifiers = Vec::new();
        let ctrl_fd = locked_net_io.ctrl.queue_evt.as_raw_fd();
        notifiers.push(build_event_notifier(
            ctrl_fd,
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        ));

        // Register event notifier for deactivate_evt.
        let cloned_net_io = net_io.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            Some(cloned_net_io.lock().unwrap().deactivate_evt_handler())
        });
        notifiers.push(build_event_notifier(
            locked_net_io.deactivate_evt.as_raw_fd(),
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        ));

        notifiers
    }
}

struct TxVirtio {
    queue: Arc<Mutex<Queue>>,
    queue_evt: EventFd,
}

impl TxVirtio {
    fn new(queue: Arc<Mutex<Queue>>, queue_evt: EventFd) -> Self {
        TxVirtio { queue, queue_evt }
    }
}

struct RxVirtio {
    queue_full: bool,
    queue: Arc<Mutex<Queue>>,
    queue_evt: EventFd,
}

impl RxVirtio {
    fn new(queue: Arc<Mutex<Queue>>, queue_evt: EventFd) -> Self {
        RxVirtio {
            queue_full: false,
            queue,
            queue_evt,
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
    update_evt: EventFd,
    deactivate_evt: EventFd,
    is_listening: bool,
    ctrl_info: Arc<Mutex<CtrlInfo>>,
}

impl NetIoHandler {
    fn read_from_tap(queue: &mut Queue, iovecs: &[libc::iovec], tap: &mut Tap) -> i32 {
        let size = unsafe {
            libc::readv(
                tap.as_raw_fd() as libc::c_int,
                iovecs.as_ptr() as *const libc::iovec,
                iovecs.len() as libc::c_int,
            )
        } as i32;
        if size < 0 {
            let e = std::io::Error::last_os_error();
            queue.vring.push_back();
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
                    error!("Failed to read tap: {}", e);
                }
            }
            error!("Failed to call readv for net handle_rx: {}", e);
        }

        size
    }

    fn handle_rx(&mut self) -> Result<()> {
        self.trace_request("Net".to_string(), "to rx".to_string());
        let mut queue = self.rx.queue.lock().unwrap();
        while let Some(tap) = self.tap.as_mut() {
            if queue.vring.avail_ring_len(&self.mem_space)? == 0 {
                self.rx.queue_full = true;
                break;
            }
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for net rx")?;
            if elem.desc_num == 0 {
                break;
            }
            let mut iovecs = Vec::new();
            for elem_iov in elem.in_iovec.iter() {
                let host_addr = queue
                    .vring
                    .get_host_address_from_cache(elem_iov.addr, &self.mem_space);
                if host_addr != 0 {
                    let iovec = libc::iovec {
                        iov_base: host_addr as *mut libc::c_void,
                        iov_len: elem_iov.len as libc::size_t,
                    };
                    iovecs.push(iovec);
                } else {
                    bail!("Failed to get host address for {}", elem_iov.addr.0);
                }
            }

            // Read the data from the tap device.
            let size = NetIoHandler::read_from_tap(&mut queue, &iovecs, tap);
            if size < 0 {
                break;
            }

            let net_hdr_len = mem::size_of::<VirtioNetHdr>();
            let mut buf = vec![0_u8; net_hdr_len + ETHERNET_HDR_LENGTH];
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
                .filter_packets(&buf[net_hdr_len..])
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
                        anyhow!(VirtioError::InterruptTrigger(
                            "net",
                            VirtioInterruptType::Vring
                        ))
                    })?;
                self.trace_send_interrupt("Net".to_string());
            }
        }

        Ok(())
    }

    fn handle_tx(&mut self) -> Result<()> {
        self.trace_request("Net".to_string(), "to tx".to_string());
        let mut queue = self.tx.queue.lock().unwrap();

        loop {
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for net tx")?;
            if elem.desc_num == 0 {
                break;
            }
            let mut iovecs = Vec::new();
            for elem_iov in elem.out_iovec.iter() {
                let host_addr = queue
                    .vring
                    .get_host_address_from_cache(elem_iov.addr, &self.mem_space);
                if host_addr != 0 {
                    let iovec = libc::iovec {
                        iov_base: host_addr as *mut libc::c_void,
                        iov_len: elem_iov.len as libc::size_t,
                    };
                    iovecs.push(iovec);
                } else {
                    error!("Failed to get host address for {}", elem_iov.addr.0);
                }
            }
            let mut read_len = 0;
            if let Some(tap) = self.tap.as_mut() {
                if !iovecs.is_empty() {
                    read_len = unsafe {
                        libc::writev(
                            tap.as_raw_fd() as libc::c_int,
                            iovecs.as_ptr() as *const libc::iovec,
                            iovecs.len() as libc::c_int,
                        )
                    };
                }
            };
            if read_len < 0 {
                let e = std::io::Error::last_os_error();
                bail!("Failed to call writev for net handle_tx: {}", e);
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
                        anyhow!(VirtioError::InterruptTrigger(
                            "net",
                            VirtioInterruptType::Vring
                        ))
                    })?;
                self.trace_send_interrupt("Net".to_string());
            }
        }

        Ok(())
    }

    fn update_evt_handler(net_io: &Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut locked_net_io = net_io.lock().unwrap();
        locked_net_io.tap = match locked_net_io.receiver.recv() {
            Ok(tap) => tap,
            Err(e) => {
                error!("Failed to receive the tap {}", e);
                None
            }
        };
        let old_tap_fd = locked_net_io.tap_fd;
        locked_net_io.tap_fd = -1;
        if let Some(tap) = locked_net_io.tap.as_ref() {
            locked_net_io.tap_fd = tap.as_raw_fd();
        }

        let mut notifiers = vec![
            build_event_notifier(
                locked_net_io.update_evt.as_raw_fd(),
                None,
                NotifierOperation::Delete,
                EventSet::IN,
            ),
            build_event_notifier(
                locked_net_io.rx.queue_evt.as_raw_fd(),
                None,
                NotifierOperation::Delete,
                EventSet::IN,
            ),
            build_event_notifier(
                locked_net_io.tx.queue_evt.as_raw_fd(),
                None,
                NotifierOperation::Delete,
                EventSet::IN,
            ),
        ];
        if old_tap_fd != -1 {
            notifiers.push(build_event_notifier(
                old_tap_fd,
                None,
                NotifierOperation::Delete,
                EventSet::IN,
            ));
        }
        drop(locked_net_io);

        notifiers.append(&mut EventNotifierHelper::internal_notifiers(net_io.clone()));
        notifiers
    }

    fn deactivate_evt_handler(&mut self) -> Vec<EventNotifier> {
        let mut notifiers = vec![
            EventNotifier::new(
                NotifierOperation::Delete,
                self.update_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.deactivate_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.rx.queue_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.tx.queue_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
        ];
        if self.tap_fd != -1 {
            notifiers.push(EventNotifier::new(
                NotifierOperation::Delete,
                self.tap_fd,
                None,
                EventSet::IN,
                Vec::new(),
            ));
            self.tap_fd = -1;
        }

        notifiers
    }
}

fn get_net_header(iovec: &[libc::iovec], buf: &mut [u8]) -> Result<usize> {
    let mut start: usize = 0;
    let mut end: usize = 0;

    for elem in iovec {
        end = cmp::min(start + elem.iov_len as usize, buf.len());
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
    handler: Option<Box<NotifierCallback>>,
    op: NotifierOperation,
    event: EventSet,
) -> EventNotifier {
    let mut handlers = Vec::new();
    if let Some(h) = handler {
        handlers.push(Arc::new(Mutex::new(h)));
    }
    EventNotifier::new(op, fd, None, event, handlers)
}

impl EventNotifierHelper for NetIoHandler {
    fn internal_notifiers(net_io: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        // Register event notifier for update_evt.
        let locked_net_io = net_io.lock().unwrap();
        let cloned_net_io = net_io.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            Some(NetIoHandler::update_evt_handler(&cloned_net_io))
        });
        let mut notifiers = vec![build_event_notifier(
            locked_net_io.update_evt.as_raw_fd(),
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        )];

        // Register event notifier for deactivate_evt.
        let cloned_net_io = net_io.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            Some(cloned_net_io.lock().unwrap().deactivate_evt_handler())
        });
        notifiers.push(build_event_notifier(
            locked_net_io.deactivate_evt.as_raw_fd(),
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        ));

        // Register event notifier for rx.
        let cloned_net_io = net_io.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            let mut locked_net_io = cloned_net_io.lock().unwrap();
            read_fd(fd);
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
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            if let Err(ref e) = cloned_net_io.lock().unwrap().handle_tx() {
                error!("Failed to handle tx(tx event) for net, {:?}", e);
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
            let handler: Box<NotifierCallback> = Box::new(move |_, _| {
                let mut locked_net_io = cloned_net_io.lock().unwrap();
                if let Err(ref e) = locked_net_io.handle_rx() {
                    error!("Failed to handle rx(tap event), {:?}", e);
                    report_virtio_error(
                        locked_net_io.interrupt_cb.clone(),
                        locked_net_io.driver_features,
                        Some(&locked_net_io.deactivate_evt),
                    );
                }

                if let Some(tap) = locked_net_io.tap.as_ref() {
                    if locked_net_io.rx.queue_full {
                        let notifier = vec![EventNotifier::new(
                            NotifierOperation::Park,
                            tap.as_raw_fd(),
                            None,
                            EventSet::IN | EventSet::EDGE_TRIGGERED,
                            Vec::new(),
                        )];
                        locked_net_io.is_listening = false;
                        locked_net_io.rx.queue_full = false;
                        return Some(notifier);
                    }
                }
                None
            });
            let tap_fd = tap.as_raw_fd();
            notifiers.push(build_event_notifier(
                tap_fd,
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
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Virtio net configurations.
    config_space: VirtioNetConfig,
}

/// Network device structure.
pub struct Net {
    /// Configuration of the network device.
    net_cfg: NetworkInterfaceConfig,
    /// Tap device opened.
    taps: Option<Vec<Tap>>,
    /// The status of net device.
    state: Arc<Mutex<VirtioNetState>>,
    /// The send half of Rust's channel to send tap information.
    senders: Option<Vec<Sender<SenderConfig>>>,
    /// Eventfd for config space update.
    update_evt: EventFd,
    /// Eventfd for device deactivate.
    deactivate_evt: EventFd,
    /// The information about control command.
    ctrl_info: Option<Arc<Mutex<CtrlInfo>>>,
}

impl Default for Net {
    fn default() -> Self {
        Self {
            net_cfg: Default::default(),
            taps: None,
            state: Arc::new(Mutex::new(VirtioNetState::default())),
            senders: None,
            update_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            ctrl_info: None,
        }
    }
}

impl Net {
    pub fn new(net_cfg: NetworkInterfaceConfig) -> Self {
        Self {
            net_cfg,
            taps: None,
            state: Arc::new(Mutex::new(VirtioNetState::default())),
            senders: None,
            update_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            ctrl_info: None,
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
    let mut config_features = 0_u64;
    let mut bytes = [0_u8; 6];
    for (i, s) in mac.split(':').collect::<Vec<&str>>().iter().enumerate() {
        bytes[i] = if let Ok(v) = u8::from_str_radix(s, 16) {
            v
        } else {
            return config_features;
        };
    }
    device_config.mac.copy_from_slice(&bytes);
    config_features |= 1 << VIRTIO_NET_F_MAC;

    config_features
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
    let flags = u16::from_str_radix(ifr_flag.trim().trim_start_matches("0x"), 16)
        .with_context(|| "Failed to parse tap ifr flag")?;
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

        let vnet_hdr_size = mem::size_of::<VirtioNetHdr>() as u32;
        tap.set_hdr_size(vnet_hdr_size)
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
    /// Realize virtio network device.
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

        let mut locked_state = self.state.lock().unwrap();
        locked_state.device_features = 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_TSO6
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_TSO6
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_RING_EVENT_IDX;

        let queue_pairs = self.net_cfg.queues / 2;
        if self.net_cfg.mq
            && queue_pairs >= VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN
            && queue_pairs <= VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX
        {
            locked_state.device_features |= 1 << VIRTIO_NET_F_MQ;
            locked_state.device_features |= 1 << VIRTIO_NET_F_CTRL_VQ;
            locked_state.config_space.max_virtqueue_pairs = queue_pairs;
        }

        if !self.net_cfg.host_dev_name.is_empty() {
            self.taps = None;
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

        // Using the first tap to test if all the taps have ufo.
        if let Some(tap) = self.taps.as_ref().map(|t| &t[0]) {
            if !tap.has_ufo() {
                locked_state.device_features &=
                    !(1 << VIRTIO_NET_F_GUEST_UFO | 1 << VIRTIO_NET_F_HOST_UFO);
            }
        }

        if let Some(mac) = &self.net_cfg.mac {
            locked_state.device_features |=
                build_device_config_space(&mut locked_state.config_space, mac);
        }

        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        MigrationManager::unregister_device_instance(
            VirtioNetState::descriptor(),
            &self.net_cfg.id,
        );
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_NET
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        if self.net_cfg.mq {
            (self.net_cfg.queues + 1) as usize
        } else {
            QUEUE_NUM_NET
        }
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_NET
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.lock().unwrap().device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        self.state.lock().unwrap().driver_features = self.checked_driver_features(page, value);
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.lock().unwrap().driver_features, features_select)
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let locked_state = self.state.lock().unwrap();
        let config_slice = locked_state.config_space.as_bytes();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_len)));
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])?;
        }
        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let mut locked_state = self.state.lock().unwrap();
        let driver_features = locked_state.driver_features;
        let config_slice = locked_state.config_space.as_mut_bytes();
        if !virtio_has_feature(driver_features, VIRTIO_NET_F_CTRL_MAC_ADDR)
            && !virtio_has_feature(driver_features, VIRTIO_F_VERSION_1)
            && offset == 0
            && data_len == MAC_ADDR_LEN
            && *data != config_slice[0..data_len]
        {
            config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);
        }

        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        mut queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let queue_num = queues.len();
        let ctrl_info = Arc::new(Mutex::new(CtrlInfo::new(self.state.clone())));
        self.ctrl_info = Some(ctrl_info.clone());
        if (self.state.lock().unwrap().driver_features & 1 << VIRTIO_NET_F_CTRL_VQ != 0)
            && (queue_num % 2 != 0)
        {
            let ctrl_queue = queues[queue_num - 1].clone();
            let ctrl_queue_evt = queue_evts.remove(queue_num - 1);

            let ctrl_handler = NetCtrlHandler {
                ctrl: CtrlVirtio::new(ctrl_queue, ctrl_queue_evt, Some(ctrl_info.clone())),
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features: self.state.lock().unwrap().driver_features,
                deactivate_evt: self.deactivate_evt.try_clone().unwrap(),
            };

            EventLoop::update_event(
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(ctrl_handler))),
                self.net_cfg.iothread.as_ref(),
            )?;
        }

        // The features about offload is included in bits 0 to 31.
        let features = self.get_driver_features(0_u32);
        let flags = get_tap_offload_flags(features as u64);

        let mut senders = Vec::new();
        let queue_pairs = queue_num / 2;
        for index in 0..queue_pairs {
            let rx_queue = queues[index * 2].clone();
            let rx_queue_evt = queue_evts.remove(0);
            let tx_queue = queues[index * 2 + 1].clone();
            let tx_queue_evt = queue_evts.remove(0);

            let (sender, receiver) = channel();
            senders.push(sender);

            if let Some(tap) = self.taps.as_ref().map(|t| t[index].clone()) {
                tap.set_offload(flags)
                    .with_context(|| "Failed to set tap offload")?;
            }

            let mut handler = NetIoHandler {
                rx: RxVirtio::new(rx_queue, rx_queue_evt),
                tx: TxVirtio::new(tx_queue, tx_queue_evt),
                tap: self.taps.as_ref().map(|t| t[index].clone()),
                tap_fd: -1,
                mem_space: mem_space.clone(),
                interrupt_cb: interrupt_cb.clone(),
                driver_features: self.state.lock().unwrap().driver_features,
                receiver,
                update_evt: self.update_evt.try_clone().unwrap(),
                deactivate_evt: self.deactivate_evt.try_clone().unwrap(),
                is_listening: true,
                ctrl_info: ctrl_info.clone(),
            };
            if let Some(tap) = &handler.tap {
                handler.tap_fd = tap.as_raw_fd();
            }

            EventLoop::update_event(
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
                self.net_cfg.iothread.as_ref(),
            )?;
        }
        self.senders = Some(senders);

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
            let features = self.get_driver_features(0_u32);
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
                        sender.send(Some(tap)).with_context(|| {
                            anyhow!(VirtioError::ChannelSend("tap fd".to_string()))
                        })?;
                    }
                    None => sender
                        .send(None)
                        .with_context(|| "Failed to send status of None to channel".to_string())?,
                }
            }

            self.update_evt
                .write(1)
                .with_context(|| anyhow!(VirtioError::EventFdWrite))?;
        }

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.deactivate_evt
            .write(1)
            .with_context(|| anyhow!(VirtioError::EventFdWrite))
    }

    fn reset(&mut self) -> Result<()> {
        if let Some(ctrl_info) = &self.ctrl_info {
            let mut locked_ctrl = ctrl_info.lock().unwrap();
            locked_ctrl.rx_mode = Default::default();
            locked_ctrl.mac_info = Default::default();
            locked_ctrl.vlan_map = HashMap::new();
        } else {
            bail!("Control information is None");
        }

        Ok(())
    }
}

// Send and Sync is not auto-implemented for `Sender` type.
// Implementing them is safe because `Sender` field of Net won't change in migration
// workflow.
unsafe impl Sync for Net {}

impl StateTransfer for Net {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        Ok(self.state.lock().unwrap().as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::Result<()> {
        let s_len = std::mem::size_of::<VirtioNetState>();
        if state.len() != s_len {
            bail!("Invalid state length {}, expected {}", state.len(), s_len);
        }
        let mut locked_state = self.state.lock().unwrap();
        locked_state.as_mut_bytes().copy_from_slice(state);

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        if let Some(alias) = MigrationManager::get_desc_alias(&VirtioNetState::descriptor().name) {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for Net {}

impl VirtioTrace for NetIoHandler {}

#[cfg(test)]
mod tests {
    pub use super::super::*;
    pub use super::*;

    #[test]
    fn test_net_init() {
        // test net new method
        let mut net = Net::default();
        assert_eq!(net.state.lock().unwrap().device_features, 0);
        assert_eq!(net.state.lock().unwrap().driver_features, 0);

        assert_eq!(net.taps.is_none(), true);
        assert_eq!(net.senders.is_none(), true);
        assert_eq!(net.net_cfg.mac.is_none(), true);
        assert_eq!(net.net_cfg.tap_fds.is_none(), true);
        assert_eq!(net.net_cfg.vhost_type.is_none(), true);
        assert_eq!(net.net_cfg.vhost_fds.is_none(), true);

        // test net realize method
        net.realize().unwrap();
        assert_eq!(net.device_type(), 1);
        assert_eq!(net.queue_num(), 2);
        assert_eq!(net.queue_size(), 256);

        // test read_config and write_config method
        let write_data: Vec<u8> = vec![7; 4];
        let mut random_data: Vec<u8> = vec![0; 4];
        let mut origin_data: Vec<u8> = vec![0; 4];
        net.read_config(0x00, &mut origin_data).unwrap();

        net.write_config(0x00, &write_data).unwrap();
        net.read_config(0x00, &mut random_data).unwrap();
        assert_ne!(random_data, write_data);

        net.write_config(0x00, &origin_data).unwrap();

        // test boundary condition of offset and data parameters
        let locked_state = net.state.lock().unwrap();
        let device_config = locked_state.config_space.as_bytes();
        let len = device_config.len() as u64;
        drop(locked_state);

        let mut data: Vec<u8> = vec![0; 10];
        let offset: u64 = len + 1;
        assert_eq!(net.read_config(offset, &mut data).is_ok(), false);

        let offset: u64 = len;
        assert_eq!(net.read_config(offset, &mut data).is_ok(), false);

        let offset: u64 = 0;
        assert_eq!(net.read_config(offset, &mut data).is_ok(), true);

        let offset: u64 = len;
        let mut data: Vec<u8> = vec![0; 1];
        assert_eq!(net.write_config(offset, &mut data).is_ok(), true);

        let offset: u64 = len - 1;
        let mut data: Vec<u8> = vec![0; 1];
        assert_eq!(net.write_config(offset, &mut data).is_ok(), true);

        let offset: u64 = 0;
        let mut data: Vec<u8> = vec![0; len as usize];
        assert_eq!(net.write_config(offset, &mut data).is_ok(), true);
    }
}
