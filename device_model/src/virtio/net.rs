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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::{cmp, mem};

use address_space::AddressSpace;
use machine_manager::config::{ConfigCheck, NetworkInterfaceConfig};
use util::byte_code::ByteCode;
use util::epoll_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::{read_u32, write_u32};
use util::tap::{Tap, TUN_F_VIRTIO};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use super::super::micro_vm::main_loop::MainLoop;
use super::errors::{ErrorKind, Result, ResultExt};
use super::{
    Queue, VirtioDevice, VirtioNetHdr, VIRTIO_F_VERSION_1, VIRTIO_MMIO_INT_VRING,
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC, VIRTIO_TYPE_NET,
};

/// Number of virtqueues.
const QUEUE_NUM_NET: usize = 2;
/// Size of each virtqueue.
const QUEUE_SIZE_NET: u16 = 256;
/// The maximum buffer size when segmentation offload is enabled.
/// This includes a 12-byte virtio net header, refer to Virtio Spec.
const FRAME_BUF_SIZE: usize = 65562;

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

/// Transmit virtqueue.
struct TxVirtio {
    /// Virtqueue.
    queue: Arc<Mutex<Queue>>,
    /// Eventfd of this virtqueue for notifing.
    queue_evt: EventFd,
    /// Buffer data to transmit.
    frame_buf: [u8; FRAME_BUF_SIZE],
}

impl TxVirtio {
    /// Create a transmit virqueue.
    ///
    /// # Arguments
    ///
    /// * `queue` - The virtqueue.
    /// * `queue_evt` - Eventfd of this virtqueue for notifing.
    fn new(queue: Arc<Mutex<Queue>>, queue_evt: EventFd) -> Self {
        TxVirtio {
            queue,
            queue_evt,
            frame_buf: [0u8; FRAME_BUF_SIZE],
        }
    }
}

/// Receive virtqueue.
struct RxVirtio {
    /// True if some frame not received successfully.
    unfinished_frame: bool,
    /// True if interrupt is required to notify the guest.
    need_irqs: bool,
    /// Virtqueue.
    queue: Arc<Mutex<Queue>>,
    /// Eventfd of this virtqueue for notifing.
    queue_evt: EventFd,
    /// Size of data received.
    bytes_read: usize,
    /// Buffer data received.
    frame_buf: [u8; FRAME_BUF_SIZE],
}

impl RxVirtio {
    /// Create a receive virqueue.
    ///
    /// # Arguments
    ///
    /// * `queue` - The virtqueue.
    /// * `queue_evt` - Eventfd of this virtqueue for notifing.
    fn new(queue: Arc<Mutex<Queue>>, queue_evt: EventFd) -> Self {
        RxVirtio {
            unfinished_frame: false,
            need_irqs: false,
            queue,
            queue_evt,
            bytes_read: 0,
            frame_buf: [0u8; FRAME_BUF_SIZE],
        }
    }
}

/// Control block of network IO.
pub struct NetIoHandler {
    /// The receive virtqueue.
    rx: RxVirtio,
    /// The transmit virtqueue.
    tx: TxVirtio,
    /// Tap device opened.
    tap: Option<Tap>,
    tap_fd: RawFd,
    /// The address space to which the network device belongs.
    mem_space: Arc<AddressSpace>,
    /// Eventfd for interrupt.
    interrupt_evt: EventFd,
    /// State of the interrupt in the device/function.
    interrupt_status: Arc<AtomicU32>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// The receiving half of Rust's channel to receive tap information.
    receiver: Receiver<SenderConfig>,
    /// Eventfd for config space update.
    update_evt: RawFd,
}

impl NetIoHandler {
    #[allow(clippy::useless_asref)]
    fn handle_frame_rx(&mut self) -> Result<()> {
        let elem = self
            .rx
            .queue
            .lock()
            .unwrap()
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
            .chain_err(|| "Failed to pop avail ring")?;

        let mut write_count = 0;
        for elem_iov in elem.in_iovec.iter() {
            let allow_write_count =
                cmp::min(write_count + elem_iov.len as usize, self.rx.bytes_read);

            let source_slice = &self.rx.frame_buf[write_count..allow_write_count];
            match self.mem_space.write(
                &mut source_slice.as_ref(),
                elem_iov.addr,
                source_slice.len() as u64,
            ) {
                Ok(_) => {
                    write_count = allow_write_count;
                }
                Err(e) => {
                    error!("Failed to write slice: err {:?}", e);
                    break;
                }
            }

            if write_count >= self.rx.bytes_read {
                break;
            }
        }

        self.rx
            .queue
            .lock()
            .unwrap()
            .vring
            .add_used(&self.mem_space, elem.index, write_count as u32)
            .chain_err(|| format!("Failed to add used ring {}", elem.index))?;
        self.rx.need_irqs = true;

        if write_count < self.rx.bytes_read {
            bail!(
                "The length {} which is written is less than the length {} of buffer which is read",
                write_count,
                self.rx.bytes_read
            );
        }

        Ok(())
    }

    fn handle_last_frame_rx(&mut self) -> Result<()> {
        if self.handle_frame_rx().is_ok() {
            self.rx.unfinished_frame = false;
            self.handle_rx()?;
        } else if self.rx.need_irqs {
            self.rx.need_irqs = false;
            self.interrupt_status
                .fetch_or(VIRTIO_MMIO_INT_VRING, Ordering::SeqCst);
            self.interrupt_evt
                .write(1)
                .chain_err(|| ErrorKind::EventFdWrite)?;
        }

        Ok(())
    }

    fn handle_rx(&mut self) -> Result<()> {
        while let Some(tap) = self.tap.as_mut() {
            match tap.read(&mut self.rx.frame_buf) {
                Ok(count) => {
                    self.rx.bytes_read = count;
                    if self.handle_frame_rx().is_err() {
                        self.rx.unfinished_frame = true;
                        break;
                    }
                }
                Err(e) => {
                    match e.raw_os_error() {
                        Some(err) if err == libc::EAGAIN => (),
                        _ => {
                            bail!("Failed to read tap");
                        }
                    };
                    break;
                }
            }
        }

        if self.rx.need_irqs {
            self.rx.need_irqs = false;
            self.interrupt_status
                .fetch_or(VIRTIO_MMIO_INT_VRING, Ordering::SeqCst);
            self.interrupt_evt
                .write(1)
                .chain_err(|| ErrorKind::EventFdWrite)?;
        }

        Ok(())
    }

    fn handle_tx(&mut self) -> Result<()> {
        let mut queue = self.tx.queue.lock().unwrap();

        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
            let mut read_count = 0;
            for elem_iov in elem.out_iovec.iter() {
                let alloc_read_count =
                    cmp::min(read_count + elem_iov.len as usize, self.tx.frame_buf.len());

                let mut slice = &mut self.tx.frame_buf[read_count..alloc_read_count as usize];
                self.mem_space
                    .read(
                        &mut slice,
                        elem_iov.addr,
                        (alloc_read_count - read_count) as u64,
                    )
                    .chain_err(|| "Failed to read buffer for transmit")?;

                read_count = alloc_read_count;
            }
            if let Some(tap) = self.tap.as_mut() {
                tap.write(&self.tx.frame_buf[..read_count as usize])
                    .chain_err(|| "Net: tx: failed to write to tap")?;
            }

            queue
                .vring
                .add_used(&self.mem_space, elem.index, 0)
                .chain_err(|| format!("Net tx：Failed to add used ring {}", elem.index))?;
        }

        Ok(())
    }

    fn update_evt_handler(net_io: &Arc<Mutex<Self>>) -> Option<Vec<EventNotifier>> {
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

        let mut notifiers = Vec::new();
        notifiers.push(build_event_notifier(
            locked_net_io.update_evt,
            None,
            NotifierOperation::Delete,
            EventSet::IN,
        ));
        notifiers.push(build_event_notifier(
            locked_net_io.rx.queue_evt.as_raw_fd(),
            None,
            NotifierOperation::Delete,
            EventSet::IN,
        ));
        notifiers.push(build_event_notifier(
            locked_net_io.tx.queue_evt.as_raw_fd(),
            None,
            NotifierOperation::Delete,
            EventSet::IN,
        ));
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
        Some(notifiers)
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
            NetIoHandler::update_evt_handler(&cloned_net_io)
        });
        let mut notifiers = Vec::new();
        let update_fd = locked_net_io.update_evt;
        notifiers.push(build_event_notifier(
            update_fd,
            Some(handler),
            NotifierOperation::AddShared,
            EventSet::IN,
        ));

        // Register event notifier for rx.
        let cloned_net_io = net_io.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            let mut locked_net_io = cloned_net_io.lock().unwrap();
            read_fd(fd);
            if locked_net_io.rx.unfinished_frame {
                locked_net_io
                    .handle_last_frame_rx()
                    .map_err(|e| error!("Failed to handle last frame(rx), {}", e))
                    .ok();
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
            cloned_net_io
                .lock()
                .unwrap()
                .handle_tx()
                .map_err(|e| error!("Failed to handle tx, {}", e))
                .ok();
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
                if locked_net_io.rx.unfinished_frame {
                    locked_net_io
                        .handle_last_frame_rx()
                        .map_err(|e| error!("Failed to handle last frame(rx), {}", e))
                        .ok();
                } else {
                    locked_net_io
                        .handle_rx()
                        .map_err(|e| error!("Failed to handle rx, {}", e))
                        .ok();
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

/// Network device structure.
pub struct Net {
    /// Configuration of the network device.
    net_cfg: NetworkInterfaceConfig,
    /// Tap device opened.
    tap: Option<Tap>,
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Virtio net configurations.
    device_config: VirtioNetConfig,
    /// The send half of Rust's channel to send tap information.
    sender: Option<Sender<SenderConfig>>,
    /// Eventfd for config space update.
    update_evt: EventFd,
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

impl Net {
    /// Create a new virtio network device.
    ///
    /// # Arguments
    ///
    /// * `net_cfg` - Configuration of the network device.
    pub fn new() -> Self {
        Net {
            net_cfg: Default::default(),
            tap: None,
            device_features: 0_u64,
            driver_features: 0_u64,
            device_config: VirtioNetConfig::default(),
            sender: None,
            update_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl VirtioDevice for Net {
    /// Realize vhost virtio network device.
    fn realize(&mut self) -> Result<()> {
        self.device_features = 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO;

        if let Some(mac) = &self.net_cfg.mac {
            self.device_features |= build_device_config_space(&mut self.device_config, mac);
        }

        if self.net_cfg.host_dev_name != "" {
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
            self.device_features |= build_device_config_space(&mut self.device_config, mac);
        }

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
        read_u32(self.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut v = write_u32(value, page);
        let unrequested_features = v & !self.device_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request with unknown feature: {:x}", v);
            v &= !unrequested_features;
        }
        self.driver_features |= v;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.device_config.as_bytes();
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
        let config_slice = self.device_config.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(&data[..]);

        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_evt: EventFd,
        interrupt_status: Arc<AtomicU32>,
        mut queues: Vec<Arc<Mutex<Queue>>>,
        mut queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let rx_queue = queues.remove(0);
        let rx_queue_evt = queue_evts.remove(0);
        let tx_queue = queues.remove(0);
        let tx_queue_evt = queue_evts.remove(0);

        let (sender, receiver) = channel();
        self.sender = Some(sender);

        let tap_fd = if let Some(tap) = &self.tap {
            tap.as_raw_fd()
        } else {
            -1
        };

        let handler = NetIoHandler {
            rx: RxVirtio::new(rx_queue, rx_queue_evt),
            tx: TxVirtio::new(tx_queue, tx_queue_evt),
            tap: self.tap.take(),
            tap_fd,
            mem_space,
            interrupt_evt: interrupt_evt.try_clone()?,
            interrupt_status,
            driver_features: self.driver_features,
            receiver,
            update_evt: self.update_evt.as_raw_fd(),
        };
        MainLoop::update_event(EventNotifierHelper::internal_notifiers(Arc::new(
            Mutex::new(handler),
        )))?;

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
}
