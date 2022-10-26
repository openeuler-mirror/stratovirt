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
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use super::{
    Element, Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VirtioTrace,
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN,
    VIRTIO_BLK_T_OUT, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1,
    VIRTIO_TYPE_BLOCK,
};
use crate::VirtioError;
use address_space::{AddressSpace, GuestAddress};
use anyhow::{anyhow, bail, Context, Result};
use log::error;
use machine_manager::{
    config::{BlkDevConfig, ConfigCheck},
    event_loop::EventLoop,
};
use migration::{
    migration::Migratable, DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager,
    StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::aio::{Aio, AioCb, AioCompleteFunc, IoCmd, Iovec};
use util::byte_code::ByteCode;
use util::leak_bucket::LeakBucket;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::{read_u32, write_u32};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};
/// Number of virtqueues.
const QUEUE_NUM_BLK: usize = 1;
/// Size of each virtqueue.
const QUEUE_SIZE_BLK: u16 = 256;
/// Used to compute the number of sectors.
const SECTOR_SHIFT: u8 = 9;
/// Size of a sector of the block device.
const SECTOR_SIZE: u64 = (0x01_u64) << SECTOR_SHIFT;
/// Size of the dummy block device.
const DUMMY_IMG_SIZE: u64 = 0;

type SenderConfig = (Option<Arc<File>>, u64, Option<String>, bool);

fn get_serial_num_config(serial_num: &str) -> Vec<u8> {
    let mut id_bytes = vec![0; VIRTIO_BLK_ID_BYTES as usize];
    let bytes_to_copy = cmp::min(serial_num.len(), VIRTIO_BLK_ID_BYTES as usize);

    let serial_bytes = serial_num.as_bytes();
    id_bytes[..bytes_to_copy].clone_from_slice(&serial_bytes[..bytes_to_copy]);
    id_bytes
}

fn write_buf_mem(buf: &[u8], hva: u64) -> Result<()> {
    let mut slice = unsafe { std::slice::from_raw_parts_mut(hva as *mut u8, buf.len()) };
    (&mut slice)
        .write(buf)
        .with_context(|| format!("Failed to write buf(hva:{})", hva))?;

    Ok(())
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RequestOutHeader {
    request_type: u32,
    io_prio: u32,
    sector: u64,
}

impl RequestOutHeader {
    fn is_valid(&self) -> bool {
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

#[derive(Clone)]
pub struct AioCompleteCb {
    queue: Arc<Mutex<Queue>>,
    mem_space: Arc<AddressSpace>,
    desc_index: u16,
    rw_len: u32,
    req_status_addr: GuestAddress,
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    driver_features: u64,
}

impl AioCompleteCb {
    fn new(
        queue: Arc<Mutex<Queue>>,
        mem_space: Arc<AddressSpace>,
        desc_index: u16,
        rw_len: u32,
        req_status_addr: GuestAddress,
        interrupt_cb: Option<Arc<VirtioInterrupt>>,
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

#[derive(Clone)]
struct Request {
    desc_index: u16,
    out_header: RequestOutHeader,
    iovec: Vec<Iovec>,
    data_len: u64,
    in_header: GuestAddress,
}

impl Request {
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
            .with_context(|| {
                anyhow!(VirtioError::ReadObjectErr(
                    "the block's request header",
                    out_iov_elem.addr.0
                ))
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
    fn execute(
        &self,
        aio: &mut Box<Aio<AioCompleteCb>>,
        disk: &File,
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
            .with_context(|| {
                format!(
                    "offset {} invalid, disk sector {}",
                    self.out_header.sector, disk_sectors
                )
            })?;

        let mut aiocb = AioCb {
            last_aio,
            file_fd: disk.as_raw_fd(),
            opcode: IoCmd::Noop,
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
                aiocb.opcode = IoCmd::Preadv;
                if direct {
                    for iov in self.iovec.iter() {
                        MigrationManager::mark_dirty_log(iov.iov_base, iov.iov_len);
                    }
                    (*aio)
                        .as_mut()
                        .rw_aio(aiocb, SECTOR_SIZE)
                        .with_context(|| {
                            "Failed to process block request for reading asynchronously"
                        })?;
                } else {
                    (*aio).as_mut().rw_sync(aiocb).with_context(|| {
                        "Failed to process block request for reading synchronously"
                    })?;
                }
            }
            VIRTIO_BLK_T_OUT => {
                aiocb.opcode = IoCmd::Pwritev;
                if direct {
                    (*aio)
                        .as_mut()
                        .rw_aio(aiocb, SECTOR_SIZE)
                        .with_context(|| {
                            "Failed to process block request for writing asynchronously"
                        })?;
                } else {
                    (*aio).as_mut().rw_sync(aiocb).with_context(|| {
                        "Failed to process block request for writing synchronously"
                    })?;
                }
            }
            VIRTIO_BLK_T_FLUSH => {
                aiocb.opcode = IoCmd::Fdsync;
                (*aio)
                    .as_mut()
                    .rw_sync(aiocb)
                    .with_context(|| "Failed to process block request for flushing")?;
            }
            VIRTIO_BLK_T_GET_ID => {
                if let Some(serial) = serial_num {
                    let serial_vec = get_serial_num_config(serial);

                    for iov in self.iovec.iter() {
                        if (iov.iov_len as usize) < serial_vec.len() {
                            bail!(
                                "The buffer length {} is less than the length {} of serial num",
                                iov.iov_len,
                                serial_vec.len()
                            );
                        }
                        write_buf_mem(&serial_vec, iov.iov_base)
                            .with_context(|| "Failed to write buf for virtio block id")?;
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

    fn get_req_sector_num(&self) -> u64 {
        self.data_len / SECTOR_SIZE
    }
}

/// Control block of Block IO.
struct BlockIoHandler {
    /// The virtqueue.
    queue: Arc<Mutex<Queue>>,
    /// Eventfd of the virtqueue for IO event.
    queue_evt: EventFd,
    /// The address space to which the block device belongs.
    mem_space: Arc<AddressSpace>,
    /// The image file opened by the block device.
    disk_image: Option<Arc<File>>,
    /// The number of sectors of the disk image.
    disk_sectors: u64,
    /// Serial number of the block device.
    serial_num: Option<String>,
    /// if use direct access io.
    direct: bool,
    /// Aio context.
    aio: Option<Box<Aio<AioCompleteCb>>>,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// The receiving half of Rust's channel to receive the image file.
    receiver: Receiver<SenderConfig>,
    /// Eventfd for config space update.
    update_evt: EventFd,
    /// Eventfd for device deactivate.
    deactivate_evt: EventFd,
    /// Callback to trigger an interrupt.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// thread name of io handler
    iothread: Option<String>,
    /// Using the leak bucket to implement IO limits
    leak_bucket: Option<LeakBucket>,
}

impl BlockIoHandler {
    fn merge_req_queue(&self, mut req_queue: Vec<Request>) -> Vec<Request> {
        if req_queue.len() == 1 {
            return req_queue;
        }

        req_queue.sort_by(|a, b| a.out_header.sector.cmp(&b.out_header.sector));
        let mut merge_req_queue = Vec::<Request>::new();
        let mut continue_merge: bool = false;

        for req in &req_queue {
            if continue_merge {
                if let Some(last_req) = merge_req_queue.last_mut() {
                    if last_req.out_header.sector + last_req.get_req_sector_num()
                        != req.out_header.sector
                    {
                        continue_merge = false;
                        merge_req_queue.push(req.clone());
                    } else {
                        for iov in req.iovec.iter() {
                            let iovec = Iovec {
                                iov_base: iov.iov_base,
                                iov_len: iov.iov_len,
                            };
                            last_req.data_len += iovec.iov_len;
                            last_req.iovec.push(iovec);
                        }
                    }
                }
            } else {
                merge_req_queue.push(req.clone());
            }
        }

        merge_req_queue
    }

    fn process_queue(&mut self) -> Result<bool> {
        self.trace_request("Block".to_string(), "to IO".to_string());
        let mut req_queue = Vec::new();
        let mut req_index = 0;
        let mut last_aio_req_index = 0;
        let mut need_interrupt = false;
        let mut done = false;

        let mut queue = self.queue.lock().unwrap();

        while let Ok(elem) = queue.vring.pop_avail(&self.mem_space, self.driver_features) {
            // limit io operations if iops is configured
            if let Some(lb) = self.leak_bucket.as_mut() {
                if let Some(ctx) = EventLoop::get_ctx(self.iothread.as_ref()) {
                    if lb.throttled(ctx, 1_u64) {
                        queue.vring.push_back();
                        break;
                    }
                } else {
                    bail!(
                        "IOThread {:?} of Block is not found in cmdline.",
                        self.iothread,
                    );
                };
            }

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
                    done = true;
                }
                Err(ref e) => {
                    //  If it fails, also need to free descriptor table entry.
                    queue
                        .vring
                        .add_used(&self.mem_space, elem.index, 0)
                        .with_context(|| "Failed to add used ring")?;
                    need_interrupt = true;

                    error!("failed to create block request, {:?}", e);
                }
            };
        }

        // unlock queue, because it will be hold below.
        drop(queue);

        let merge_req_queue = self.merge_req_queue(req_queue);

        if let Some(disk_img) = self.disk_image.as_mut() {
            req_index = 0;
            for req in merge_req_queue.iter() {
                if let Some(ref mut aio) = self.aio {
                    let rw_len = match req.out_header.request_type {
                        VIRTIO_BLK_T_IN => u32::try_from(req.data_len)
                            .with_context(|| "Convert block request len to u32 with overflow.")?,
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
                                    .with_context(|| "Failed to write result for the request for block with device id")?;
                                self.queue.lock().unwrap().vring.add_used(
                                    &self.mem_space,
                                    req.desc_index,
                                    1,
                                ).with_context(|| "Failed to add the request for block with device id to used ring")?;

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
                            error!("Failed to execute block request, {:?}", e);
                        }
                    }
                    req_index += 1;
                }
            }
        } else if !merge_req_queue.is_empty() {
            for req in merge_req_queue.iter() {
                self.queue
                    .lock()
                    .unwrap()
                    .vring
                    .add_used(&self.mem_space, req.desc_index, 1)
                    .with_context(|| {
                        "Failed to add used ring, when block request queue isn't empty"
                    })?;
            }
            need_interrupt = true
        }

        if need_interrupt {
            (self.interrupt_cb)(
                &VirtioInterruptType::Vring,
                Some(&self.queue.lock().unwrap()),
            )
            .with_context(|| {
                anyhow!(VirtioError::InterruptTrigger(
                    "block",
                    VirtioInterruptType::Vring
                ))
            })?;
            self.trace_send_interrupt("Block".to_string());
        }

        Ok(done)
    }

    fn build_aio(&self, engine: Option<&String>) -> Result<Box<Aio<AioCompleteCb>>> {
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
                error!("Failed to write the status (aio completion) {:?}", e);
                return;
            }

            let mut queue_lock = complete_cb.queue.lock().unwrap();
            if let Err(ref e) = queue_lock.vring.add_used(
                &complete_cb.mem_space,
                complete_cb.desc_index,
                complete_cb.rw_len,
            ) {
                error!(
                    "Failed to add used ring(aio completion), index {}, len {} {:?}",
                    complete_cb.desc_index, complete_cb.rw_len, e,
                );
                return;
            }

            if queue_lock
                .vring
                .should_notify(&complete_cb.mem_space, complete_cb.driver_features)
            {
                if let Err(e) = (*complete_cb.interrupt_cb.as_ref().unwrap())(
                    &VirtioInterruptType::Vring,
                    Some(&queue_lock),
                ) {
                    error!(
                        "Failed to trigger interrupt(aio completion) for block device, error is {:?}",
                        e
                    );
                }
            }
        }) as AioCompleteFunc<AioCompleteCb>);

        Ok(Box::new(Aio::new(complete_func, engine)?))
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
            error!("Failed to handle block IO for updating handler {:?}", e);
        }
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
                self.queue_evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ),
        ];
        if let Some(lb) = self.leak_bucket.as_ref() {
            notifiers.push(EventNotifier::new(
                NotifierOperation::Delete,
                lb.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ));
        }
        if let Some(aio) = &self.aio {
            notifiers.push(EventNotifier::new(
                NotifierOperation::Delete,
                aio.fd.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ));
        }

        notifiers
    }
}

fn build_event_notifier(fd: RawFd, handler: Box<NotifierCallback>) -> EventNotifier {
    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        vec![Arc::new(Mutex::new(handler))],
    )
}

impl EventNotifierHelper for BlockIoHandler {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let handler_raw = handler.lock().unwrap();
        let mut notifiers = Vec::new();

        // Register event notifier for update_evt.
        let h_clone = handler.clone();
        let h: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            h_clone.lock().unwrap().update_evt_handler();
            None
        });
        notifiers.push(build_event_notifier(handler_raw.update_evt.as_raw_fd(), h));

        // Register event notifier for deactivate_evt.
        let h_clone = handler.clone();
        let h: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            Some(h_clone.lock().unwrap().deactivate_evt_handler())
        });
        notifiers.push(build_event_notifier(
            handler_raw.deactivate_evt.as_raw_fd(),
            h,
        ));

        // Register event notifier for queue_evt.
        let h_clone = handler.clone();
        let h: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);

            if let Err(ref e) = h_clone.lock().unwrap().process_queue() {
                error!("Failed to handle block IO {:?}", e);
            }
            None
        });

        let h_clone = handler.clone();
        let handler_iopoll: Box<NotifierCallback> = Box::new(move |_, _fd: RawFd| {
            let done = h_clone
                .lock()
                .unwrap()
                .process_queue()
                .with_context(|| "Failed to handle block IO")
                .ok()?;
            if done {
                Some(Vec::new())
            } else {
                None
            }
        });

        let mut e = EventNotifier::new(
            NotifierOperation::AddShared,
            handler_raw.queue_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![
                Arc::new(Mutex::new(h)),
                Arc::new(Mutex::new(handler_iopoll)),
            ],
        );
        e.io_poll = true;

        notifiers.push(e);

        // Register timer event notifier for IO limits
        if let Some(lb) = handler_raw.leak_bucket.as_ref() {
            let h_clone = handler.clone();
            let h: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
                read_fd(fd);

                if let Some(lb) = h_clone.lock().unwrap().leak_bucket.as_mut() {
                    lb.clear_timer();
                }

                if let Err(ref e) = h_clone.lock().unwrap().process_queue() {
                    error!("Failed to handle block IO {:?}", e);
                }
                None
            });
            notifiers.push(build_event_notifier(lb.as_raw_fd(), h));
        }

        // Register event notifier for aio.
        if let Some(ref aio) = handler_raw.aio {
            let h_clone = handler.clone();
            let h: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
                read_fd(fd);

                if let Some(aio) = &mut h_clone.lock().unwrap().aio {
                    if let Err(ref e) = aio.handle() {
                        error!("Failed to handle aio, {:?}", e);
                    }
                }
                None
            });

            let h_clone = handler.clone();
            let handler_iopoll: Box<NotifierCallback> = Box::new(move |_, _fd: RawFd| {
                let mut done = false;
                if let Some(aio) = &mut h_clone.lock().unwrap().aio {
                    done = aio.handle().with_context(|| "Failed to handle aio").ok()?;
                }
                if done {
                    Some(Vec::new())
                } else {
                    None
                }
            });

            let mut e = EventNotifier::new(
                NotifierOperation::AddShared,
                aio.fd.as_raw_fd(),
                None,
                EventSet::IN,
                vec![
                    Arc::new(Mutex::new(h)),
                    Arc::new(Mutex::new(handler_iopoll)),
                ],
            );
            e.io_poll = true;

            notifiers.push(e);
        }

        notifiers
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioBlkGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

impl ByteCode for VirtioBlkGeometry {}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioBlkConfig {
    /// The capacity in 512 byte sectors.
    capacity: u64,
    /// The maximum segment size.
    size_max: u32,
    /// Tne maximum number of segments.
    seg_max: u32,
    /// Geometry of the block device.
    geometry: VirtioBlkGeometry,
    /// Block size of device.
    blk_size: u32,
    /// Exponent for physical block per logical block.
    physical_block_exp: u8,
    /// Alignment offset in logical blocks.
    alignment_offset: u8,
    /// Minimum I/O size without performance penalty in logical blocks.
    min_io_size: u16,
    /// Optimal sustained I/O size in logical blocks.
    opt_io_size: u32,
    /// Writeback mode.
    wce: u8,
    /// Reserved data.
    unused: u8,
    /// Number of virtio queues, only available when `VIRTIO_BLK_F_MQ` is set.
    pub num_queues: u16,
    /// The maximum discard sectors for one segment.
    max_discard_sectors: u32,
    /// The maximum number of discard segments in a discard command.
    max_discard_seg: u32,
    /// Discard commands must be aligned to this number of sectors.
    discard_sector_alignment: u32,
    /// The maximum number of write zeros sectors.
    max_write_zeroes_sectors: u32,
    /// The maximum number of segments in a write zeroes command.
    max_write_zeroes_seg: u32,
    /// Deallocation of one or more of the sectors.
    write_zeroes_may_unmap: u8,
    /// Reserved data.
    unused1: [u8; 3],
}

impl ByteCode for VirtioBlkConfig {}

/// State of block device.
#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct BlockState {
    /// Bitmask of features supported by the backend.
    pub device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    pub driver_features: u64,
    /// Config space of the block device.
    pub config_space: VirtioBlkConfig,
}

/// Block device structure.
pub struct Block {
    /// Configuration of the block device.
    blk_cfg: BlkDevConfig,
    /// Image file opened.
    disk_image: Option<Arc<File>>,
    /// Number of sectors of the image file.
    disk_sectors: u64,
    /// Status of block device.
    state: BlockState,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// The sending half of Rust's channel to send the image file.
    senders: Option<Vec<Sender<SenderConfig>>>,
    /// Eventfd for config space update.
    update_evt: EventFd,
    /// Eventfd for device deactivate.
    deactivate_evt: EventFd,
}

impl Default for Block {
    fn default() -> Self {
        Block {
            blk_cfg: Default::default(),
            disk_image: None,
            disk_sectors: 0,
            state: BlockState::default(),
            interrupt_cb: None,
            senders: None,
            update_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl Block {
    pub fn new(blk_cfg: BlkDevConfig) -> Block {
        Self {
            blk_cfg,
            disk_image: None,
            disk_sectors: 0,
            state: BlockState::default(),
            interrupt_cb: None,
            senders: None,
            update_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }

    fn build_device_config_space(&mut self) {
        // capacity: 64bits
        let num_sectors = DUMMY_IMG_SIZE >> SECTOR_SHIFT;
        self.state.config_space.capacity = num_sectors;
        // seg_max = queue_size - 2: 32bits
        self.state.config_space.seg_max = self.queue_size() as u32 - 2;
    }
}

impl VirtioDevice for Block {
    /// Realize virtio block device.
    fn realize(&mut self) -> Result<()> {
        // if iothread not found, return err
        if self.blk_cfg.iothread.is_some()
            && EventLoop::get_ctx(self.blk_cfg.iothread.as_ref()).is_none()
        {
            bail!(
                "IOThread {:?} of Block is not configured in params.",
                self.blk_cfg.iothread,
            );
        }

        self.state.device_features = (1_u64 << VIRTIO_F_VERSION_1) | (1_u64 << VIRTIO_BLK_F_FLUSH);
        if self.blk_cfg.read_only {
            self.state.device_features |= 1_u64 << VIRTIO_BLK_F_RO;
        };
        self.state.device_features |= 1_u64 << VIRTIO_F_RING_INDIRECT_DESC;
        self.state.device_features |= 1_u64 << VIRTIO_BLK_F_SEG_MAX;
        self.state.device_features |= 1_u64 << VIRTIO_F_RING_EVENT_IDX;

        self.build_device_config_space();

        if self.blk_cfg.queues > 1 {
            self.state.device_features |= 1_u64 << VIRTIO_BLK_F_MQ;
            self.state.config_space.num_queues = self.blk_cfg.queues;
        }

        let mut disk_size = DUMMY_IMG_SIZE;

        if !self.blk_cfg.path_on_host.is_empty() {
            self.disk_image = None;

            let mut file = if self.blk_cfg.direct {
                OpenOptions::new()
                    .read(true)
                    .write(!self.blk_cfg.read_only)
                    .custom_flags(libc::O_DIRECT)
                    .open(&self.blk_cfg.path_on_host)
                    .with_context(|| {
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
                    .with_context(|| {
                        format!(
                            "failed to open the file for block {}",
                            self.blk_cfg.path_on_host
                        )
                    })?
            };

            disk_size =
                file.seek(SeekFrom::End(0))
                    .with_context(|| "Failed to seek the end for block")? as u64;

            self.disk_image = Some(Arc::new(file));
        } else {
            self.disk_image = None;
        }

        self.disk_sectors = disk_size >> SECTOR_SHIFT;
        self.state.config_space.capacity = self.disk_sectors;

        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        MigrationManager::unregister_device_instance(BlockState::descriptor(), &self.blk_cfg.id);
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_BLOCK
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        self.blk_cfg.queues as usize
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_BLK
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
            v &= !unrequested_features;
        }
        self.state.driver_features |= v;
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.driver_features, features_select)
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.state.config_space.as_bytes();
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
        let config_slice = self.state.config_space.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(
                offset,
                config_len as u64
            )));
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
        self.interrupt_cb = Some(interrupt_cb.clone());
        let mut senders = Vec::new();

        for queue in queues.iter() {
            let (sender, receiver) = channel();
            senders.push(sender);

            let mut handler = BlockIoHandler {
                queue: queue.clone(),
                queue_evt: queue_evts.remove(0),
                mem_space: mem_space.clone(),
                disk_image: self.disk_image.clone(),
                disk_sectors: self.disk_sectors,
                direct: self.blk_cfg.direct,
                serial_num: self.blk_cfg.serial_num.clone(),
                aio: None,
                driver_features: self.state.driver_features,
                receiver,
                update_evt: self.update_evt.try_clone().unwrap(),
                deactivate_evt: self.deactivate_evt.try_clone().unwrap(),
                interrupt_cb: interrupt_cb.clone(),
                iothread: self.blk_cfg.iothread.clone(),
                leak_bucket: self.blk_cfg.iops.map(LeakBucket::new),
            };

            handler.aio = Some(handler.build_aio(self.blk_cfg.aio.as_ref())?);

            EventLoop::update_event(
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
                self.blk_cfg.iothread.as_ref(),
            )?;
        }

        self.senders = Some(senders);

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.deactivate_evt
            .write(1)
            .with_context(|| anyhow!(VirtioError::EventFdWrite))
    }

    fn update_config(&mut self, dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        if let Some(conf) = dev_config {
            self.blk_cfg = conf
                .as_any()
                .downcast_ref::<BlkDevConfig>()
                .unwrap()
                .clone();
            // microvm type block device don't support multiple queue.
            self.blk_cfg.queues = QUEUE_NUM_BLK as u16;
        } else {
            self.blk_cfg = Default::default();
        }

        self.realize()?;

        if let Some(senders) = &self.senders {
            for sender in senders {
                sender
                    .send((
                        self.disk_image.clone(),
                        self.disk_sectors,
                        self.blk_cfg.serial_num.clone(),
                        self.blk_cfg.direct,
                    ))
                    .with_context(|| anyhow!(VirtioError::ChannelSend("image fd".to_string())))?;
            }

            self.update_evt
                .write(1)
                .with_context(|| anyhow!(VirtioError::EventFdWrite))?;
        }

        if let Some(interrupt_cb) = &self.interrupt_cb {
            interrupt_cb(&VirtioInterruptType::Config, None).with_context(|| {
                anyhow!(VirtioError::InterruptTrigger(
                    "block",
                    VirtioInterruptType::Config
                ))
            })?;
        }

        Ok(())
    }
}

// Send and Sync is not auto-implemented for `Sender` type.
// Implementing them is safe because `Sender` field of Block won't change in migration
// workflow.
unsafe impl Sync for Block {}

impl StateTransfer for Block {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        Ok(self.state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::Result<()> {
        self.state = *BlockState::from_bytes(state)
            .ok_or_else(|| anyhow!(migration::error::MigrationError::FromBytesError("BLOCK")))?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        if let Some(alias) = MigrationManager::get_desc_alias(&BlockState::descriptor().name) {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for Block {}

impl VirtioTrace for BlockIoHandler {}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};
    use machine_manager::config::IothreadConfig;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::{thread, time::Duration};
    use vmm_sys_util::tempfile::TempFile;

    const QUEUE_NUM_BLK: usize = 1;
    const CONFIG_SPACE_SIZE: usize = 60;
    const VIRTQ_DESC_F_NEXT: u16 = 0x01;
    const VIRTQ_DESC_F_WRITE: u16 = 0x02;
    const SYSTEM_SPACE_SIZE: u64 = (1024 * 1024) as u64;

    // build dummy address space of vm
    fn address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36);
        let sys_space = AddressSpace::new(root).unwrap();
        let host_mmap = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                None,
                SYSTEM_SPACE_SIZE,
                None,
                false,
                false,
                false,
            )
            .unwrap(),
        );
        sys_space
            .root()
            .add_subregion(
                Region::init_ram_region(host_mmap.clone()),
                host_mmap.start_address().raw_value(),
            )
            .unwrap();
        sys_space
    }

    // Use different input parameters to verify block `new()` and `realize()` functionality.
    #[test]
    fn test_block_init() {
        // New block device
        let mut block = Block::default();
        assert_eq!(block.disk_sectors, 0);
        assert_eq!(block.state.device_features, 0);
        assert_eq!(block.state.driver_features, 0);
        assert_eq!(block.state.config_space.as_bytes().len(), CONFIG_SPACE_SIZE);
        assert!(block.disk_image.is_none());
        assert!(block.interrupt_cb.is_none());
        assert!(block.senders.is_none());

        // Realize block device: create TempFile as backing file.
        block.blk_cfg.read_only = true;
        block.blk_cfg.direct = false;
        let f = TempFile::new().unwrap();
        block.blk_cfg.path_on_host = f.as_path().to_str().unwrap().to_string();
        assert!(block.realize().is_ok());

        assert_eq!(block.device_type(), VIRTIO_TYPE_BLOCK);
        assert_eq!(block.queue_num(), QUEUE_NUM_BLK);
        assert_eq!(block.queue_size(), QUEUE_SIZE_BLK);
    }

    // Test `write_config` and `read_config`. The main contests include: compare expect data and
    // read date are same; Input invalid offset or date length, it will failed.
    #[test]
    fn test_read_write_config() {
        let mut block = Block::default();
        block.realize().unwrap();

        let expect_config_space: [u8; 8] = [0x00, 020, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00];
        let mut read_config_space = [0u8; 8];
        block.write_config(0, &expect_config_space).unwrap();
        block.read_config(0, &mut read_config_space).unwrap();
        assert_eq!(read_config_space, expect_config_space);

        // Invalid write
        assert!(block
            .write_config(CONFIG_SPACE_SIZE as u64 + 1, &expect_config_space)
            .is_err());
        let errlen_config_space = [0u8; CONFIG_SPACE_SIZE + 1];
        assert!(block.write_config(0, &errlen_config_space).is_err());
        // Invalid read
        read_config_space = expect_config_space;
        assert!(block
            .read_config(CONFIG_SPACE_SIZE as u64 + 1, &mut read_config_space)
            .is_err());
    }

    // Test `get_device_features` and `set_driver_features`. The main contests include: If the
    // device feature is 0, all driver features are not supported; If both the device feature bit
    // and the front-end driver feature bit are supported at the same time,  this driver feature
    // bit is supported.
    #[test]
    fn test_block_features() {
        let mut block = Block::default();

        // If the device feature is 0, all driver features are not supported.
        block.state.device_features = 0;
        let driver_feature: u32 = 0xFF;
        let page = 0_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(block.state.driver_features, 0_u64);
        assert_eq!(block.get_driver_features(page) as u64, 0_u64);
        assert_eq!(block.get_device_features(0_u32), 0_u32);

        let driver_feature: u32 = 0xFF;
        let page = 1_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(block.state.driver_features, 0_u64);
        assert_eq!(block.get_driver_features(page) as u64, 0_u64);
        assert_eq!(block.get_device_features(1_u32), 0_u32);

        // If both the device feature bit and the front-end driver feature bit are
        // supported at the same time,  this driver feature bit is supported.
        block.state.device_features =
            1_u64 << VIRTIO_F_VERSION_1 | 1_u64 << VIRTIO_F_RING_INDIRECT_DESC;
        let driver_feature: u32 = (1_u64 << VIRTIO_F_RING_INDIRECT_DESC) as u32;
        let page = 0_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(
            block.state.driver_features,
            (1_u64 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        assert_eq!(
            block.get_driver_features(page) as u64,
            (1_u64 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        assert_eq!(
            block.get_device_features(page),
            (1_u32 << VIRTIO_F_RING_INDIRECT_DESC)
        );
        block.state.driver_features = 0;

        block.state.device_features = 1_u64 << VIRTIO_F_VERSION_1;
        let driver_feature: u32 = (1_u64 << VIRTIO_F_RING_INDIRECT_DESC) as u32;
        let page = 0_u32;
        block.set_driver_features(page, driver_feature);
        assert_eq!(block.state.driver_features, 0);
        assert_eq!(block.get_driver_features(page), 0);
        assert_eq!(block.get_device_features(page), 0_u32);
        block.state.driver_features = 0;
    }

    // Test `get_serial_num_config`. The function will output the shorter length between 20
    // with serial_num length.
    #[test]
    fn test_serial_num_config() {
        let serial_num = "fldXlNNdCeqMvoIfEFogBxlL";
        let serial_num_arr = serial_num.as_bytes();
        let id_bytes = get_serial_num_config(&serial_num);
        assert_eq!(id_bytes[..], serial_num_arr[..20]);
        assert_eq!(id_bytes.len(), 20);

        let serial_num = "7681194149";
        let serial_num_arr = serial_num.as_bytes();
        let id_bytes = get_serial_num_config(&serial_num);
        assert_eq!(id_bytes[..10], serial_num_arr[..]);
        assert_eq!(id_bytes.len(), 20);

        let serial_num = "";
        let id_bytes_temp = get_serial_num_config(&serial_num);
        assert_eq!(id_bytes_temp[..], [0; 20]);
        assert_eq!(id_bytes_temp.len(), 20);
    }

    // Test iothread and qos capability. The function will spawn a thread called 'iothread', then
    // io request will be handled by this thread.
    #[test]
    fn test_iothread() {
        let thread_name = "io1".to_string();

        // spawn io thread
        let io_conf = IothreadConfig {
            id: thread_name.clone(),
        };
        EventLoop::object_init(&Some(vec![io_conf])).unwrap();

        let mut block = Block::default();
        let file = TempFile::new().unwrap();
        block.blk_cfg.path_on_host = file.as_path().to_str().unwrap().to_string();

        // config iothread and iops
        block.blk_cfg.iothread = Some(thread_name);
        block.blk_cfg.iops = Some(100);

        let mem_space = address_space_init();
        let interrupt_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let interrupt_status = Arc::new(AtomicU32::new(0));
        let interrupt_cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, _queue: Option<&Queue>| {
                let status = match int_type {
                    VirtioInterruptType::Config => VIRTIO_MMIO_INT_CONFIG,
                    VirtioInterruptType::Vring => VIRTIO_MMIO_INT_VRING,
                };
                interrupt_status.fetch_or(status as u32, Ordering::SeqCst);
                interrupt_evt
                    .write(1)
                    .with_context(|| anyhow!(VirtioError::EventFdWrite))?;

                Ok(())
            },
        ) as VirtioInterrupt);

        let mut queue_config = QueueConfig::new(QUEUE_SIZE_BLK);
        queue_config.desc_table = GuestAddress(0);
        queue_config.addr_cache.desc_table_host =
            mem_space.get_host_address(queue_config.desc_table).unwrap();
        queue_config.avail_ring = GuestAddress(16 * QUEUE_SIZE_BLK as u64);
        queue_config.addr_cache.avail_ring_host =
            mem_space.get_host_address(queue_config.avail_ring).unwrap();
        queue_config.used_ring = GuestAddress(32 * QUEUE_SIZE_BLK as u64);
        queue_config.addr_cache.used_ring_host =
            mem_space.get_host_address(queue_config.used_ring).unwrap();
        queue_config.size = QUEUE_SIZE_BLK;
        queue_config.ready = true;

        let queues: Vec<Arc<Mutex<Queue>>> =
            vec![Arc::new(Mutex::new(Queue::new(queue_config, 1).unwrap()))];
        let event = EventFd::new(libc::EFD_NONBLOCK).unwrap();

        // activate block device
        block
            .activate(
                mem_space.clone(),
                interrupt_cb,
                &queues,
                vec![event.try_clone().unwrap()],
            )
            .unwrap();

        // make first descriptor entry
        let desc = SplitVringDesc {
            addr: GuestAddress(0x100),
            len: 16,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        mem_space
            .write_object::<SplitVringDesc>(&desc, GuestAddress(queue_config.desc_table.0))
            .unwrap();

        // write RequestOutHeader to first desc
        let req_head = RequestOutHeader {
            request_type: 0, // read
            io_prio: 0,
            sector: 0,
        };
        mem_space
            .write_object::<RequestOutHeader>(&req_head, GuestAddress(0x100))
            .unwrap();

        // making the second descriptor entry to receive data from device
        let desc = SplitVringDesc {
            addr: GuestAddress(0x200),
            len: 16,
            flags: VIRTQ_DESC_F_WRITE,
            next: 2,
        };
        mem_space
            .write_object::<SplitVringDesc>(
                &desc,
                GuestAddress(queue_config.desc_table.0 + 16 as u64),
            )
            .unwrap();

        // write avail_ring idx
        mem_space
            .write_object::<u16>(&0, GuestAddress(queue_config.avail_ring.0 + 4 as u64))
            .unwrap();

        // write avail_ring id
        mem_space
            .write_object::<u16>(&1, GuestAddress(queue_config.avail_ring.0 + 2 as u64))
            .unwrap();

        // imitating guest OS to send notification.
        event.write(1).unwrap();

        // waiting for io handled
        let mut wait = 10; // wait for 2 seconds
        loop {
            thread::sleep(Duration::from_millis(200));

            wait -= 1;
            if wait == 0 {
                assert_eq!(0, 1); // timeout failed
            }

            // get used_ring data
            let idx = mem_space
                .read_object::<u16>(GuestAddress(queue_config.used_ring.0 + 2 as u64))
                .unwrap();
            if idx == 1 {
                break;
            }
        }
    }
}
