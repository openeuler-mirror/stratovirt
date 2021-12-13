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

use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::{cmp, mem};

use address_space::AddressSpace;
use machine_manager::{
    config::{ConfigCheck, NetworkInterfaceConfig},
    event_loop::EventLoop,
};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::{read_u32, write_u32};
use util::tap::{Tap, TUN_F_VIRTIO};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use super::errors::{ErrorKind, Result, ResultExt};
use super::{
    Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VirtioNetHdr,
    VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC, VIRTIO_TYPE_NET,
};

/// Number of virtqueues.
const QUEUE_NUM_NET: usize = 2;
/// Size of each virtqueue.
const QUEUE_SIZE_NET: u16 = 256;

type SenderConfig = Option<Tap>;

/// Configuration of virtio-net devices.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioNetConfig {
    /// Mac Address.
    pub mac: [u8; 6],
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
    need_irqs: bool,
    queue: Arc<Mutex<Queue>>,
    queue_evt: EventFd,
}

impl RxVirtio {
    fn new(queue: Arc<Mutex<Queue>>, queue_evt: EventFd) -> Self {
        RxVirtio {
            queue_full: false,
            need_irqs: false,
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
    update_evt: RawFd,
    deactivate_evt: RawFd,
    is_listening: bool,
}

impl NetIoHandler {
    fn handle_rx(&mut self) -> Result<()> {
        let mut queue = self.rx.queue.lock().unwrap();
        while let Some(tap) = self.tap.as_mut() {
            if queue.vring.avail_ring_len(&self.mem_space)? == 0 {
                self.rx.queue_full = true;
                break;
            }
            let elem = queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .chain_err(|| "Failed to pop avail ring for net rx")?;
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
                    error!("Failed to get host address for {}", elem_iov.addr.0);
                }
            }
            let write_count = unsafe {
                libc::readv(
                    tap.as_raw_fd() as libc::c_int,
                    iovecs.as_ptr() as *const libc::iovec,
                    iovecs.len() as libc::c_int,
                )
            };
            if write_count < 0 {
                let e = std::io::Error::last_os_error();
                queue.vring.push_back();
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                bail!("Failed to call readv for net handle_rx: {}", e);
            }

            queue
                .vring
                .add_used(&self.mem_space, elem.index, write_count as u32)
                .chain_err(|| {
                    format!(
                        "Failed to add used ring for net rx, index: {}, len: {}",
                        elem.index, write_count
                    )
                })?;
            self.rx.need_irqs = true;
        }

        if self.rx.need_irqs {
            self.rx.need_irqs = false;
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue))
                .chain_err(|| ErrorKind::InterruptTrigger("net", VirtioInterruptType::Vring))?;
        }

        Ok(())
    }

    fn handle_tx(&mut self) -> Result<()> {
        let mut queue = self.tx.queue.lock().unwrap();
        let mut need_irq = false;

        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
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
                .chain_err(|| format!("Net tx: Failed to add used ring {}", elem.index))?;

            need_irq = true;
        }

        if need_irq {
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&queue))
                .chain_err(|| ErrorKind::InterruptTrigger("net", VirtioInterruptType::Vring))?;
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
                locked_net_io.update_evt,
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
                self.update_evt,
                None,
                EventSet::IN,
                Vec::new(),
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.deactivate_evt,
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
        let mut notifiers = Vec::new();
        let update_fd = locked_net_io.update_evt;
        notifiers.push(build_event_notifier(
            update_fd,
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
            locked_net_io.deactivate_evt,
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
                        EventSet::IN,
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
                error!(
                    "Failed to handle tx(tx event) for net, {}",
                    error_chain::ChainedError::display_chain(e)
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
            let handler: Box<NotifierCallback> = Box::new(move |_, _| {
                let mut locked_net_io = cloned_net_io.lock().unwrap();
                if let Err(ref e) = locked_net_io.handle_rx() {
                    error!(
                        "Failed to handle rx(tap event), {}",
                        error_chain::ChainedError::display_chain(e)
                    );
                }

                if let Some(tap) = locked_net_io.tap.as_ref() {
                    if locked_net_io.rx.queue_full {
                        let notifier = vec![EventNotifier::new(
                            NotifierOperation::Park,
                            tap.as_raw_fd(),
                            None,
                            EventSet::IN,
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
                EventSet::IN,
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
    tap: Option<Tap>,
    /// The status of net device.
    state: VirtioNetState,
    /// The send half of Rust's channel to send tap information.
    sender: Option<Sender<SenderConfig>>,
    /// Eventfd for config space update.
    update_evt: EventFd,
    /// Eventfd for device deactivate.
    deactivate_evt: EventFd,
}

impl Default for Net {
    fn default() -> Self {
        Self {
            net_cfg: Default::default(),
            tap: None,
            state: VirtioNetState::default(),
            sender: None,
            update_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl Net {
    pub fn new(net_cfg: NetworkInterfaceConfig) -> Self {
        Self {
            net_cfg,
            tap: None,
            state: VirtioNetState::default(),
            sender: None,
            update_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
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

/// Open tap device if no fd provided, configure and return it.
///
/// # Arguments
///
/// * `net_fd` - Fd of tap device opened.
/// * `host_dev_name` - Path of tap device on host.
pub fn create_tap(net_fd: Option<i32>, host_dev_name: Option<&str>) -> Result<Option<Tap>> {
    if net_fd.is_none() && host_dev_name.is_none() {
        return Ok(None);
    }
    if net_fd.is_some() && host_dev_name.is_some() {
        error!("Create tap: fd and file_path exist meanwhile (use fd by default)");
    }

    let tap = if let Some(fd) = net_fd {
        Tap::new(None, Some(fd)).chain_err(|| "Failed to create tap")?
    } else {
        // `unwrap()` won't fail because the arguments have been checked
        let dev_name = host_dev_name.unwrap();
        Tap::new(Some(dev_name), None)
            .chain_err(|| format!("Failed to create tap with name {}", dev_name))?
    };

    tap.set_offload(TUN_F_VIRTIO)
        .chain_err(|| "Failed to set tap offload")?;

    let vnet_hdr_size = mem::size_of::<VirtioNetHdr>() as u32;
    tap.set_hdr_size(vnet_hdr_size)
        .chain_err(|| "Failed to set tap hdr size")?;

    Ok(Some(tap))
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

        self.state.device_features = 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_RING_EVENT_IDX;

        if let Some(mac) = &self.net_cfg.mac {
            self.state.device_features |=
                build_device_config_space(&mut self.state.config_space, mac);
        }

        if !self.net_cfg.host_dev_name.is_empty() {
            self.tap = None;
            self.tap = create_tap(None, Some(&self.net_cfg.host_dev_name))
                .chain_err(|| "Failed to open tap with file path")?;
        } else if let Some(fd) = self.net_cfg.tap_fd {
            let mut need_create = true;
            if let Some(tap) = &self.tap {
                if fd == tap.as_raw_fd() {
                    need_create = false;
                }
            }

            if need_create {
                self.tap = create_tap(Some(fd), None).chain_err(|| "Failed to open tap")?;
            }
        } else {
            self.tap = None;
        }

        if let Some(mac) = &self.net_cfg.mac {
            self.state.device_features |=
                build_device_config_space(&mut self.state.config_space, mac);
        }

        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_NET
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_NET
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_NET
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut v = write_u32(value, page);
        let unrequested_features = v & !self.state.device_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request with unknown feature: {:x}", v);
            v &= !unrequested_features;
        }
        self.state.driver_features |= v;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.state.config_space.as_bytes();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len).into());
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])?;
        }
        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_slice = self.state.config_space.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);

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
        let rx_queue = queues[0].clone();
        let rx_queue_evt = queue_evts.remove(0);
        let tx_queue = queues[1].clone();
        let tx_queue_evt = queue_evts.remove(0);

        let (sender, receiver) = channel();
        self.sender = Some(sender);

        let mut handler = NetIoHandler {
            rx: RxVirtio::new(rx_queue, rx_queue_evt),
            tx: TxVirtio::new(tx_queue, tx_queue_evt),
            tap: self.tap.as_ref().map(|t| Tap {
                file: t.file.try_clone().unwrap(),
            }),
            tap_fd: -1,
            mem_space,
            interrupt_cb,
            driver_features: self.state.driver_features,
            receiver,
            update_evt: self.update_evt.as_raw_fd(),
            deactivate_evt: self.deactivate_evt.as_raw_fd(),
            is_listening: true,
        };
        if let Some(tap) = &handler.tap {
            handler.tap_fd = tap.as_raw_fd();
        }

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
            self.net_cfg.iothread.as_ref(),
        )?;

        Ok(())
    }

    fn update_config(&mut self, dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        if let Some(conf) = dev_config {
            self.net_cfg = conf
                .as_any()
                .downcast_ref::<NetworkInterfaceConfig>()
                .unwrap()
                .clone();
        } else {
            self.net_cfg = Default::default();
        }

        self.realize()?;

        if let Some(sender) = &self.sender {
            sender
                .send(self.tap.take())
                .chain_err(|| ErrorKind::ChannelSend("tap fd".to_string()))?;

            self.update_evt
                .write(1)
                .chain_err(|| ErrorKind::EventFdWrite)?;
        }

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.deactivate_evt
            .write(1)
            .chain_err(|| ErrorKind::EventFdWrite)
    }
}

// Send and Sync is not auto-implemented for `Sender` type.
// Implementing them is safe because `Sender` field of Net won't change in migration
// workflow.
unsafe impl Sync for Net {}

impl StateTransfer for Net {
    fn get_state_vec(&self) -> migration::errors::Result<Vec<u8>> {
        Ok(self.state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::errors::Result<()> {
        self.state = *VirtioNetState::from_bytes(state)
            .ok_or(migration::errors::ErrorKind::FromBytesError("NET"))?;

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

#[cfg(test)]
mod tests {
    pub use super::super::*;
    pub use super::*;

    #[test]
    fn test_net_init() {
        // test net new method
        let mut net = Net::default();
        assert_eq!(net.state.device_features, 0);
        assert_eq!(net.state.driver_features, 0);

        assert_eq!(net.tap.is_none(), true);
        assert_eq!(net.sender.is_none(), true);
        assert_eq!(net.net_cfg.mac.is_none(), true);
        assert_eq!(net.net_cfg.tap_fd.is_none(), true);
        assert_eq!(net.net_cfg.vhost_type.is_none(), true);
        assert_eq!(net.net_cfg.vhost_fd.is_none(), true);

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
        assert_eq!(random_data, write_data);

        net.write_config(0x00, &origin_data).unwrap();

        // test boundary condition of offset and data parameters
        let device_config = net.state.config_space.as_bytes();
        let len = device_config.len() as u64;

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
        assert_eq!(net.write_config(offset, &mut data).is_ok(), true);

        let offset: u64 = 0;
        let mut data: Vec<u8> = vec![0; len as usize];
        assert_eq!(net.write_config(offset, &mut data).is_ok(), true);
    }
}
