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

use std::cmp;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use address_space::{AddressSpace, GuestAddress};
use machine_manager::{
    config::{ConfigCheck, DriveConfig},
    event_loop::EventLoop,
};
use util::aio::{Aio, AioCb, AioCompleteFunc, IoCmd, Iovec};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::{read_u32, write_u32};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use super::errors::{ErrorKind, Result, ResultExt};
use super::{
    Element, Queue, VirtioDevice, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_FLUSH,
    VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1, VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING,
    VIRTIO_TYPE_BLOCK,
};

/// Number of virtqueues.
const QUEUE_NUM_BLK: usize = 1;
/// Size of each virtqueue.
const QUEUE_SIZE_BLK: u16 = 256;
/// Size of configuration space of the virtio block device.
const CONFIG_SPACE_SIZE: usize = 16;
/// Used to compute the number of sectors.
const SECTOR_SHIFT: u8 = 9;
/// Size of a sector of the block device.
const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;
/// Size of the dummy block device.
const DUMMY_IMG_SIZE: u64 = 0;

type SenderConfig = (Option<File>, u64, Option<String>, bool);
type VirtioBlockInterrupt = Box<dyn Fn(u32) -> Result<()> + Send + Sync>;

fn get_serial_num_config(serial_num: &str) -> Vec<u8> {
    let mut id_bytes = vec![0; VIRTIO_BLK_ID_BYTES as usize];
    let bytes_to_copy = cmp::min(serial_num.len(), VIRTIO_BLK_ID_BYTES as usize);

    let serial_bytes = serial_num.as_bytes();
    id_bytes[..bytes_to_copy].clone_from_slice(&serial_bytes[..bytes_to_copy]);
    id_bytes
}

/// Write data to memory at specified address.
///
/// # Arguments
///
/// * `buf` - The data buffer.
/// * `hva` - The destination address in the memory.
///
/// # Safety
///
/// hva is non-null which is guaranteed by the caller, and the entire memory range
/// of this slice is contained within a single allocated object.
pub fn write_buf_mem(buf: &[u8], hva: u64) -> Result<()> {
    let mut slice = unsafe { std::slice::from_raw_parts_mut(hva as *mut u8, buf.len()) };
    (&mut slice)
        .write(buf)
        .chain_err(|| format!("Failed to write buf(hva:{})", hva))?;

    Ok(())
}

/// The unwritable header of virtio block's request.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RequestOutHeader {
    /// Request type.
    request_type: u32,
    /// The priority of request.
    io_prio: u32,
    /// The offset sector of request.
    sector: u64,
}

impl RequestOutHeader {
    /// Return true if the request type is valid.
    pub fn is_valid(&self) -> bool {
        match self.request_type {
            VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT | VIRTIO_BLK_T_FLUSH | VIRTIO_BLK_T_GET_ID => true,
            _ => {
                error!(
                    "request type {} is not supported for block",
                    self.request_type
                );
                false
            }
        }
    }
}

impl ByteCode for RequestOutHeader {}

/// The aio control block.
#[derive(Clone)]
pub struct AioCompleteCb {
    /// The virtqueue to which this aiocb belongs.
    pub queue: Arc<Mutex<Queue>>,
    /// The address space to which this aiocb belongs.
    pub mem_space: Arc<AddressSpace>,
    /// Index of the descriptor.
    pub desc_index: u16,
    /// Total length of the descriptor chain.
    pub rw_len: u32,
    /// The memory address where stores the result of handling the request.
    pub req_status_addr: GuestAddress,
    /// Callback for triggering an interrupt.
    pub interrupt_cb: Option<Arc<VirtioBlockInterrupt>>,
    /// Bit mask of features negotiated by the backend and the frontend.
    pub driver_features: u64,
}

impl AioCompleteCb {
    /// Create an aio control block.
    ///
    /// # Arguments
    ///
    /// * `queue` - Virtqueue.
    /// * `mem_space` - Address Space to which the aio belongs.
    /// * `desc_index` - Index of the descriptor.
    /// * `req_status_addr` - The memory address where stores the result of handling the request.
    /// * `interrupt_cb` - Callback for triggering an interrupt.
    /// * `driver_features` - Bit mask of features negotiated by the backend and the frontend.
    pub fn new(
        queue: Arc<Mutex<Queue>>,
        mem_space: Arc<AddressSpace>,
        desc_index: u16,
        rw_len: u32,
        req_status_addr: GuestAddress,
        interrupt_cb: Option<Arc<VirtioBlockInterrupt>>,
        driver_features: u64,
    ) -> Self {
        AioCompleteCb {
            queue,
            mem_space,
            desc_index,
            rw_len,
            req_status_addr,
            interrupt_cb,
            driver_features,
        }
    }
}

/// Virtio block IO request.
struct Request {
    /// The index of descriptor for the request.
    desc_index: u16,
    /// The header(out_header) which is read-only.
    out_header: RequestOutHeader,
    /// The IO vector which is both readable and writable.
    iovec: Vec<Iovec>,
    /// The total length of data.
    data_len: u64,
    /// The address of header(in_header) which is writable, and this header
    /// should be written with the result of handling the request.
    in_header: GuestAddress,
}

impl Request {
    /// Create a block IO request.
    ///
    /// # Arguments
    ///
    /// * `mem_space`: Address space to which the request belongs.
    /// * `elem`: IO request element.
    fn new(mem_space: &Arc<AddressSpace>, elem: &Element) -> Result<Self> {
        if elem.out_iovec.is_empty() || elem.in_iovec.is_empty() || elem.desc_num < 2 {
            bail!(
                "Missed header for block request: out {} in {} desc num {}",
                elem.out_iovec.len(),
                elem.in_iovec.len(),
                elem.desc_num
            );
        }

        let out_iov_elem = elem.out_iovec.get(0).unwrap();
        if out_iov_elem.len < size_of::<RequestOutHeader>() as u32 {
            bail!(
                "Invalid out header for block request: length {}",
                out_iov_elem.len
            );
        }

        let out_header = mem_space
            .read_object::<RequestOutHeader>(out_iov_elem.addr)
            .chain_err(|| {
                format!(
                    "Failed to read header from memory for block request, addr {}",
                    out_iov_elem.addr.0,
                )
            })?;

        if !out_header.is_valid() {
            bail!("Unsupported block request type");
        }

        let pos = elem.in_iovec.len() - 1;
        let in_iov_elem = elem.in_iovec.get(pos).unwrap();
        if in_iov_elem.len < 1 {
            bail!(
                "Invalid out header for block request: length {}",
                in_iov_elem.len
            );
        }

        let mut request = Request {
            desc_index: elem.index,
            out_header,
            iovec: Vec::with_capacity(elem.desc_num as usize),
            data_len: 0,
            in_header: in_iov_elem.addr,
        };

        match out_header.request_type {
            VIRTIO_BLK_T_IN | VIRTIO_BLK_T_GET_ID => {
                for (index, elem_iov) in elem.in_iovec.iter().enumerate() {
                    if index == elem.in_iovec.len() - 1 {
                        break;
                    }
                    if let Some(hva) = mem_space.get_host_address(elem_iov.addr) {
                        let iov = Iovec {
                            iov_base: hva,
                            iov_len: u64::from(elem_iov.len),
                        };
                        request.iovec.push(iov);
                        request.data_len += u64::from(elem_iov.len);
                    }
                }
            }
            VIRTIO_BLK_T_OUT => {
                for (index, elem_iov) in elem.out_iovec.iter().enumerate() {
                    if index == 0 {
                        continue;
                    }
                    if let Some(hva) = mem_space.get_host_address(elem_iov.addr) {
                        let iov = Iovec {
                            iov_base: hva,
                            iov_len: u64::from(elem_iov.len),
                        };
                        request.iovec.push(iov);
                        request.data_len += u64::from(elem_iov.len);
                    }
                }
            }
            _ => (),
        }

        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::borrowed_box)]
    fn execute(
        &self,
        aio: &mut Box<Aio<AioCompleteCb>>,
        disk: &mut File,
        disk_sectors: u64,
        serial_num: &Option<String>,
        direct: bool,
        last_aio: bool,
        iocompletecb: AioCompleteCb,
    ) -> Result<u32> {
        let mut top: u64 = self.data_len / SECTOR_SIZE;
        if self.data_len % SECTOR_SIZE != 0 {
            top += 1;
        }
        top.checked_add(self.out_header.sector)
            .filter(|off| off <= &disk_sectors)
            .chain_err(|| {
                format!(
                    "offset {} invalid, disk sector {}",
                    self.out_header.sector, disk_sectors
                )
            })?;

        let mut aiocb = AioCb {
            last_aio,
            file_fd: disk.as_raw_fd(),
            opcode: IoCmd::NOOP,
            iovec: Vec::new(),
            offset: (self.out_header.sector << SECTOR_SHIFT) as usize,
            process: true,
            iocb: None,
            iocompletecb,
        };

        for iov in self.iovec.iter() {
            let iovec = Iovec {
                iov_base: iov.iov_base,
                iov_len: iov.iov_len,
            };
            aiocb.iovec.push(iovec);
        }

        match self.out_header.request_type {
            VIRTIO_BLK_T_IN => {
                aiocb.opcode = IoCmd::PREADV;
                if direct {
                    (*aio).as_mut().rw_aio(aiocb).chain_err(|| {
                        "Failed to process block request for reading asynchronously"
                    })?;
                } else {
                    (*aio).as_mut().rw_sync(aiocb).chain_err(|| {
                        "Failed to process block request for reading synchronously"
                    })?;
                }
            }
            VIRTIO_BLK_T_OUT => {
                aiocb.opcode = IoCmd::PWRITEV;
                if direct {
                    (*aio).as_mut().rw_aio(aiocb).chain_err(|| {
                        "Failed to process block request for writing asynchronously"
                    })?;
                } else {
                    (*aio).as_mut().rw_sync(aiocb).chain_err(|| {
                        "Failed to process block request for writing synchronously"
                    })?;
                }
            }
            VIRTIO_BLK_T_FLUSH => {
                aiocb.opcode = IoCmd::FDSYNC;
                (*aio)
                    .as_mut()
                    .rw_sync(aiocb)
                    .chain_err(|| "Failed to process block request for flushing")?;
            }
            VIRTIO_BLK_T_GET_ID => {
                if let Some(serial) = serial_num {
                    let serial_vec = get_serial_num_config(&serial);

                    for iov in self.iovec.iter() {
                        if (iov.iov_len as usize) < serial_vec.len() {
                            bail!(
                                "The buffer length {} is less than the length {} of serial num",
                                iov.iov_len,
                                serial_vec.len()
                            );
                        }
                        write_buf_mem(&serial_vec, iov.iov_base)
                            .chain_err(|| "Failed to write buf for virtio block id")?;
                    }
                }

                return Ok(1);
            }
            _ => bail!(
                "The type {} of block request is not supported",
                self.out_header.request_type
            ),
        };
        Ok(0)
    }
}

/// Control block of Block IO.
pub struct BlockIoHandler {
    /// The virtqueue.
    pub queue: Arc<Mutex<Queue>>,
    /// Eventfd of the virtqueue for IO event.
    pub queue_evt: EventFd,
    /// The address space to which the block device belongs.
    pub mem_space: Arc<AddressSpace>,
    /// The image file opened by the block device.
    pub disk_image: Option<File>,
    /// The number of sectors of the disk image.
    pub disk_sectors: u64,
    /// Serial number of the block device.
    pub serial_num: Option<String>,
    /// if use direct access io.
    pub direct: bool,
    /// Aio context.
    pub aio: Option<Box<Aio<AioCompleteCb>>>,
    /// Bit mask of features negotiated by the backend and the frontend.
    pub driver_features: u64,
    /// The receiving half of Rust's channel to receive the image file.
    receiver: Receiver<SenderConfig>,
    /// Eventfd for config space update.
    update_evt: RawFd,
    /// Callback to trigger an interrupt.
    pub interrupt_cb: Arc<VirtioBlockInterrupt>,
}

impl BlockIoHandler {
    /// Build IO requests if there are elements in virtqueue needed to be finished,
    /// and execute them. If required, an interrupt is sent to the guest.
    pub fn process_queue(&mut self) -> Result<()> {
        let mut req_queue = Vec::new();
        let mut req_index = 0;
        let mut last_aio_req_index = 0;
        let mut need_interrupt = false;

        while let Ok(elem) = self
            .queue
            .lock()
            .unwrap()
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
        {
            match Request::new(&self.mem_space, &elem) {
                Ok(req) => {
                    match req.out_header.request_type {
                        VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT => {
                            last_aio_req_index = req_index;
                        }
                        _ => {}
                    }
                    req_queue.push(req);
                    req_index += 1;
                }
                Err(ref e) => {
                    error!(
                        "failed to create block request, {}",
                        error_chain::ChainedError::display_chain(e)
                    );
                    break;
                }
            };
        }

        if let Some(disk_img) = self.disk_image.as_mut() {
            req_index = 0;
            for req in req_queue.iter() {
                if let Some(ref mut aio) = self.aio {
                    let rw_len = match req.out_header.request_type {
                        VIRTIO_BLK_T_IN => u32::try_from(req.data_len)
                            .chain_err(|| "Convert block request len to u32 with overflow.")?,
                        _ => 0u32,
                    };

                    let aiocompletecb = AioCompleteCb::new(
                        self.queue.clone(),
                        self.mem_space.clone(),
                        req.desc_index,
                        rw_len,
                        req.in_header,
                        Some(self.interrupt_cb.clone()),
                        self.driver_features,
                    );

                    match req.execute(
                        aio,
                        disk_img,
                        self.disk_sectors,
                        &self.serial_num,
                        self.direct,
                        last_aio_req_index == req_index,
                        aiocompletecb,
                    ) {
                        Ok(v) => {
                            if v == 1 {
                                // get device id
                                self.mem_space
                                    .write_object(&VIRTIO_BLK_S_OK, req.in_header)
                                    .chain_err(|| "Failed to write result for the request for block with device id")?;
                                self.queue.lock().unwrap().vring.add_used(
                                    &self.mem_space,
                                    req.desc_index,
                                    1,
                                ).chain_err(|| "Failed to add the request for block with device id to used ring")?;

                                if self
                                    .queue
                                    .lock()
                                    .unwrap()
                                    .vring
                                    .should_notify(&self.mem_space, self.driver_features)
                                {
                                    need_interrupt = true;
                                }
                            }
                        }
                        Err(ref e) => {
                            error!(
                                "Failed to execute block request, {}",
                                error_chain::ChainedError::display_chain(e)
                            );
                        }
                    }
                    req_index += 1;
                }
            }
        } else if !req_queue.is_empty() {
            for req in req_queue.iter() {
                self.queue
                    .lock()
                    .unwrap()
                    .vring
                    .add_used(&self.mem_space, req.desc_index, 1)
                    .chain_err(|| {
                        "Failed to add used ring, when block request queue isn't empty"
                    })?;
            }
            need_interrupt = true
        }

        if !req_queue.is_empty() || need_interrupt {
            (self.interrupt_cb)(VIRTIO_MMIO_INT_VRING)
                .chain_err(|| "Failed to send an interrupt for block")?;
        }

        Ok(())
    }

    /// Build an aio context.
    pub fn build_aio(&self) -> Result<Box<Aio<AioCompleteCb>>> {
        let complete_func = Arc::new(Box::new(move |aiocb: &AioCb<AioCompleteCb>, ret: i64| {
            let status = if ret < 0 {
                ret
            } else {
                i64::from(VIRTIO_BLK_S_OK)
            };

            let complete_cb = &aiocb.iocompletecb;
            if let Err(ref e) = complete_cb
                .mem_space
                .write_object(&status, complete_cb.req_status_addr)
            {
                error!(
                    "Failed to write the status (aio completion) {}",
                    error_chain::ChainedError::display_chain(e)
                );
                return;
            }

            let mut queue_lock = complete_cb.queue.lock().unwrap();
            if let Err(ref e) = queue_lock.vring.add_used(
                &complete_cb.mem_space,
                complete_cb.desc_index,
                complete_cb.rw_len,
            ) {
                error!(
                    "Failed to add used ring(aio completion), index {}, len {} {}",
                    complete_cb.desc_index,
                    complete_cb.rw_len,
                    error_chain::ChainedError::display_chain(e),
                );
                return;
            }

            let trigger_interrupt_status = queue_lock
                .vring
                .should_notify(&complete_cb.mem_space, complete_cb.driver_features);
            if trigger_interrupt_status
                && (*complete_cb.interrupt_cb.as_ref().unwrap())(VIRTIO_MMIO_INT_VRING).is_err()
            {
                error!("Failed to trigger interrupt(aio completion)");
            }
        }) as AioCompleteFunc<AioCompleteCb>);

        Ok(Box::new(Aio::new(complete_func)?))
    }

    fn update_evt_handler(&mut self) {
        match self.receiver.recv() {
            Ok((image, disk_sectors, serial_num, direct)) => {
                self.disk_sectors = disk_sectors;
                self.disk_image = image;
                self.serial_num = serial_num;
                self.direct = direct;
            }
            Err(_) => {
                self.disk_sectors = 0;
                self.disk_image = None;
                self.serial_num = None;
                self.direct = true;
            }
        };

        if let Err(ref e) = self.process_queue() {
            error!(
                "Failed to handle block IO for updating handler {}",
                error_chain::ChainedError::display_chain(e)
            );
        }
    }
}

fn build_event_notifier(fd: RawFd, handler: Box<NotifierCallback>) -> EventNotifier {
    let mut handlers = Vec::new();
    handlers.push(Arc::new(Mutex::new(handler)));
    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        handlers,
    )
}

impl EventNotifierHelper for BlockIoHandler {
    fn internal_notifiers(block_io: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        let locked_block_io = block_io.lock().unwrap();

        // Register event notifier for update_evt.
        let cloned_block_io = block_io.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            cloned_block_io.lock().unwrap().update_evt_handler();
            None
        });
        notifiers.push(build_event_notifier(locked_block_io.update_evt, handler));

        // Register event notifier for queue_evt.
        let cloned_block_io = block_io.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);

            let mut locked_block_io = cloned_block_io.lock().unwrap();
            if let Err(ref e) = locked_block_io.process_queue() {
                error!(
                    "Failed to handle block IO {}",
                    error_chain::ChainedError::display_chain(e)
                );
            }
            None
        });
        notifiers.push(build_event_notifier(
            locked_block_io.queue_evt.as_raw_fd(),
            handler,
        ));

        // Register event notifier for aio.
        let cloned_block_io = block_io.clone();
        if let Some(ref aio) = locked_block_io.aio {
            let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
                read_fd(fd);

                if let Some(aio) = &mut cloned_block_io.lock().unwrap().aio {
                    if let Err(ref e) = aio.handle() {
                        error!(
                            "Failed to handle aio, {}",
                            error_chain::ChainedError::display_chain(e)
                        );
                    }
                }
                None
            });
            notifiers.push(build_event_notifier(aio.fd.as_raw_fd(), handler));
        }

        notifiers
    }
}

/// Block device structure.
pub struct Block {
    /// Configuration of the block device.
    blk_cfg: DriveConfig,
    /// Image file opened.
    disk_image: Option<File>,
    /// Number of sectors of the image file.
    disk_sectors: u64,
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Config space of the block device.
    config_space: Vec<u8>,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioBlockInterrupt>>,
    /// The sending half of Rust's channel to send the image file.
    sender: Option<Sender<SenderConfig>>,
    /// Eventfd for config space update.
    update_evt: EventFd,
}

impl Block {
    /// Create a block device.
    ///
    /// # Arguments
    ///
    /// * `blk_cfg` - Configuration of the block device.
    pub fn new() -> Block {
        Block {
            blk_cfg: Default::default(),
            disk_image: None,
            disk_sectors: 0,
            device_features: 0,
            driver_features: 0,
            config_space: Vec::with_capacity(CONFIG_SPACE_SIZE),
            interrupt_cb: None,
            sender: None,
            update_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }

    fn build_device_config_space(&mut self) -> Result<()> {
        // capacity: 64bits
        let num_sectors = DUMMY_IMG_SIZE >> SECTOR_SHIFT;
        for i in 0..8 {
            self.config_space.push((num_sectors >> (8 * i)) as u8);
        }

        // size_max=0: 32bits
        for _ in 0..4 {
            self.config_space.push(0_u8);
        }

        // seg_max=128-2: 32bits
        for i in 0..4 {
            self.config_space.push((126 >> (8 * i)) as u8);
        }

        Ok(())
    }
}

impl VirtioDevice for Block {
    /// Realize vhost virtio network device.
    fn realize(&mut self) -> Result<()> {
        self.device_features = (1_u64 << VIRTIO_F_VERSION_1) | (1_u64 << VIRTIO_BLK_F_FLUSH);
        if self.blk_cfg.read_only {
            self.device_features |= 1_u64 << VIRTIO_BLK_F_RO;
        };
        self.device_features |= 1_u64 << VIRTIO_F_RING_INDIRECT_DESC;
        self.device_features |= 1_u64 << VIRTIO_BLK_F_SIZE_MAX;
        self.device_features |= 1_u64 << VIRTIO_BLK_F_SEG_MAX;
        self.device_features |= 1_u64 << VIRTIO_F_RING_EVENT_IDX;

        self.build_device_config_space()
            .chain_err(|| "Failed to build config space for block")?;

        let mut disk_size = DUMMY_IMG_SIZE;

        if self.blk_cfg.path_on_host != "" {
            self.disk_image = None;

            let mut file = if self.blk_cfg.direct {
                OpenOptions::new()
                    .read(true)
                    .write(!self.blk_cfg.read_only)
                    .custom_flags(libc::O_DIRECT)
                    .open(&self.blk_cfg.path_on_host)
                    .chain_err(|| {
                        format!(
                            "failed to open the file by O_DIRECT for block {}",
                            self.blk_cfg.path_on_host
                        )
                    })?
            } else {
                OpenOptions::new()
                    .read(true)
                    .write(!self.blk_cfg.read_only)
                    .open(&self.blk_cfg.path_on_host)
                    .chain_err(|| {
                        format!(
                            "failed to open the file for block {}",
                            self.blk_cfg.path_on_host
                        )
                    })?
            };

            disk_size = file
                .seek(SeekFrom::End(0))
                .chain_err(|| "Failed to seek the end for block")? as u64;

            self.disk_image = Some(file);
        } else {
            self.disk_image = None;
        }

        self.disk_sectors = disk_size >> SECTOR_SHIFT;
        for i in 0..8 {
            self.config_space[i] = (self.disk_sectors >> (8 * i)) as u8;
        }

        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_BLOCK
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_BLK
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_BLK
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
            v &= !unrequested_features;
        }
        self.driver_features |= v;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len).into());
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(
                &self.config_space[offset as usize..cmp::min(end, config_len) as usize],
            )?;
        }

        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_len = self.config_space.len();
        if offset as usize + data_len > config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
        }

        self.config_space[(offset as usize)..(offset as usize + data_len)]
            .copy_from_slice(&data[..]);

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
        let interrupt_evt = interrupt_evt.try_clone()?;
        let interrupt_status = interrupt_status;
        let cb = Arc::new(Box::new(move |status: u32| {
            interrupt_status.fetch_or(status, Ordering::SeqCst);
            interrupt_evt.write(1).chain_err(|| ErrorKind::EventFdWrite)
        }) as VirtioBlockInterrupt);

        self.interrupt_cb = Some(cb.clone());
        let (sender, receiver) = channel();
        self.sender = Some(sender);

        let mut handler = BlockIoHandler {
            queue: queues.remove(0),
            queue_evt: queue_evts.remove(0),
            mem_space,
            disk_image: self.disk_image.take(),
            disk_sectors: self.disk_sectors,
            direct: self.blk_cfg.direct,
            serial_num: self.blk_cfg.serial_num.clone(),
            aio: None,
            driver_features: self.driver_features,
            receiver,
            update_evt: self.update_evt.as_raw_fd(),
            interrupt_cb: cb,
        };

        handler.aio = Some(handler.build_aio()?);

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
            self.blk_cfg.iothread.as_ref(),
        )?;

        Ok(())
    }

    fn update_config(&mut self, dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        if let Some(conf) = dev_config {
            self.blk_cfg = conf.as_any().downcast_ref::<DriveConfig>().unwrap().clone();
        } else {
            self.blk_cfg = Default::default();
        }

        self.realize()?;

        if let Some(sender) = &self.sender {
            sender
                .send((
                    self.disk_image.take(),
                    self.disk_sectors,
                    self.blk_cfg.serial_num.clone(),
                    self.blk_cfg.direct,
                ))
                .chain_err(|| ErrorKind::ChannelSend("image fd".to_string()))?;

            self.update_evt
                .write(1)
                .chain_err(|| ErrorKind::EventFdWrite)?;
        }

        if let Some(interrupt_cb) = &self.interrupt_cb {
            interrupt_cb(VIRTIO_MMIO_INT_CONFIG).chain_err(|| ErrorKind::EventFdWrite)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    pub use super::super::*;
    pub use super::*;

    #[test]
    fn test_block_init() {
        // test block new method
        let mut block = Block::new();
        assert_eq!(block.disk_sectors, 0);
        assert_eq!(block.device_features, 0);
        assert_eq!(block.driver_features, 0);

        assert_eq!(block.disk_image.is_none(), true);
        assert_eq!(block.config_space.len(), 0);
        assert_eq!(block.interrupt_cb.is_none(), true);
        assert_eq!(block.sender.is_none(), true);

        // test block realize method
        block.realize().unwrap();
        assert_eq!(block.device_type(), 2);
        assert_eq!(block.queue_num(), 1);
        assert_eq!(block.queue_size(), 256);

        // test block device features
        let device_features = (1_u64 << VIRTIO_F_VERSION_1)
            | (1_u64 << VIRTIO_BLK_F_FLUSH)
            | (1_u64 << VIRTIO_F_RING_INDIRECT_DESC)
            | (1_u64 << VIRTIO_BLK_F_SIZE_MAX)
            | (1_u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1_u64 << VIRTIO_F_RING_EVENT_IDX);
        assert_eq!(block.device_features, device_features);

        // test read_config and write_config method
        let write_data: Vec<u8> = vec![7; 4];
        let mut random_data: Vec<u8> = vec![0; 4];
        let mut origin_data: Vec<u8> = vec![0; 4];
        block.read_config(0x00, &mut origin_data).unwrap();

        block.write_config(0x00, &write_data).unwrap();
        block.read_config(0x00, &mut random_data).unwrap();
        assert_eq!(random_data, write_data);

        block.write_config(0x00, &origin_data).unwrap();

        // test boundary value of offset parameter
        let mut data: Vec<u8> = vec![0; 10];
        let offset: u64 = 17;
        assert_eq!(block.read_config(offset, &mut data).is_ok(), false);

        let offset: u64 = 16;
        assert_eq!(block.read_config(offset, &mut data).is_ok(), false);

        let offset: u64 = 15;
        assert_eq!(block.read_config(offset, &mut data).is_ok(), true);

        let offset: u64 = 0;
        assert_eq!(block.read_config(offset, &mut data).is_ok(), true);

        let mut data: Vec<u8> = vec![0; 65535];
        assert_eq!(block.read_config(offset, &mut data).is_ok(), true);

        let offset: u64 = 0;
        let mut data: Vec<u8> = vec![0; 17];
        assert_eq!(block.write_config(offset, &mut data).is_ok(), false);

        let offset: u64 = 0;
        let mut data: Vec<u8> = vec![0; 16];
        assert_eq!(block.write_config(offset, &mut data).is_ok(), true);

        let offset: u64 = 16;
        let mut data: Vec<u8> = vec![0; 1];
        assert_eq!(block.write_config(offset, &mut data).is_ok(), false);

        let offset: u64 = 2;
        let mut data: Vec<u8> = vec![0; 10];
        assert_eq!(block.write_config(offset, &mut data).is_ok(), true);
    }

    #[test]
    fn test_serial_num_config() {
        // test get_serial_num_config method
        let serial_num = "qwertyuiopasdfghjklzxcvbnm";
        let serial_num_arr = serial_num.as_bytes();
        let id_bytes = get_serial_num_config(&serial_num);
        assert_eq!(id_bytes[..], serial_num_arr[..20]);
        assert_eq!(id_bytes.len(), 20);

        let serial_num = "1234567890";
        let serial_num_arr = serial_num.as_bytes();
        let id_bytes = get_serial_num_config(&serial_num);
        assert_eq!(id_bytes[..10], serial_num_arr[..]);
        assert_eq!(id_bytes.len(), 20);

        let serial_num = "";
        let id_bytes = get_serial_num_config(&serial_num);
        assert_eq!(id_bytes.len(), 20);
    }

    #[test]
    fn test_set_driver_features() {
        let mut block = Block::new();

        //If the device feature is 0, all driver features are not supported.
        block.device_features = 0;
        let driver_feature: u32 = 0xFF;
        let page = 0_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(block.driver_features, 0_u64);
        assert_eq!(block.get_device_features(0_u32), 0_u32);

        let driver_feature: u32 = 0xFF;
        let page = 1_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(block.driver_features, 0_u64);
        assert_eq!(block.get_device_features(1_u32), 0_u32);

        //If both the device feature bit and the front-end driver feature bit are
        //supported at the same time,  this driver feature bit is supported.
        block.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_F_RING_INDIRECT_DESC;
        let driver_feature: u32 = (1_u64 << VIRTIO_F_RING_INDIRECT_DESC) as u32;
        let page = 0_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(
            block.driver_features,
            (1_u64 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        assert_eq!(
            block.get_device_features(page),
            (1_u32 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        block.driver_features = 0;

        block.device_features = 1_u64 << VIRTIO_F_VERSION_1;
        let driver_feature: u32 = (1_u64 << VIRTIO_F_RING_INDIRECT_DESC) as u32;
        let page = 0_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(block.driver_features, 0);
        assert_eq!(block.get_device_features(page), 0_u32);
        block.driver_features = 0;

        block.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_F_RING_INDIRECT_DESC;
        let driver_feature: u32 = (1_u64 << VIRTIO_F_RING_INDIRECT_DESC) as u32;
        let page = 0_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(
            block.driver_features,
            (1_u64 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        assert_eq!(
            block.get_device_features(page),
            (1_u32 << VIRTIO_F_RING_INDIRECT_DESC)
        );

        block.device_features = 1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_F_RING_INDIRECT_DESC;
        let driver_feature: u32 = (1_u64 << VIRTIO_F_RING_INDIRECT_DESC) as u32;
        let page = 0_u32;
        block.set_driver_features(page, driver_feature);
        let driver_feature: u32 = ((1_u64 << VIRTIO_F_VERSION_1) >> 32) as u32;
        let page = 1_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(
            block.driver_features,
            (1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        let page = 0_u32;
        assert_eq!(
            block.get_device_features(page),
            (1_u32 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        let page = 1_u32;
        assert_eq!(
            block.get_device_features(page),
            ((1_u64 << VIRTIO_F_VERSION_1) >> 32) as u32
        );
    }
}
