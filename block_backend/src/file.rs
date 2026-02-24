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

use std::{
    cell::RefCell,
    fs::File,
    io::{Seek, SeekFrom},
    os::{
        linux::fs::MetadataExt,
        unix::prelude::{AsRawFd, RawFd},
    },
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{bail, Context, Result};
use log::error;
use vmm_sys_util::epoll::EventSet;

use crate::{qcow2::DEFAULT_SECTOR_SIZE, BlockIoErrorCallback, BlockProperty};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::{
    aio::{Aio, AioCb, AioEngine, Iovec, OpCode},
    loop_context::{
        read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
    },
};

pub struct CombineRequest {
    pub iov: Vec<Iovec>,
    pub offset: u64,
    pub nbytes: u64,
}

impl CombineRequest {
    pub fn new(iov: Vec<Iovec>, offset: u64, nbytes: u64) -> Self {
        Self {
            iov,
            offset,
            nbytes,
        }
    }
}

pub struct FileDriver<T: Clone + 'static> {
    pub file: Arc<File>,
    aio: Rc<RefCell<Aio<T>>>,
    pub incomplete: Arc<AtomicU64>,
    delete_evts: Vec<RawFd>,
    pub block_prop: BlockProperty,
}

impl<T: Clone + 'static> FileDriver<T> {
    pub fn new(file: Arc<File>, aio: Aio<T>, block_prop: BlockProperty) -> Self {
        Self {
            file,
            incomplete: aio.incomplete_cnt.clone(),
            aio: Rc::new(RefCell::new(aio)),
            delete_evts: Vec::new(),
            block_prop,
        }
    }

    fn package_aiocb(
        &self,
        opcode: OpCode,
        iovec: Vec<Iovec>,
        offset: usize,
        nbytes: u64,
        iocompletecb: T,
    ) -> AioCb<T> {
        AioCb {
            direct: self.block_prop.direct,
            req_align: self.block_prop.req_align,
            buf_align: self.block_prop.buf_align,
            file: self.file.clone(),
            opcode,
            iovec,
            offset,
            nbytes,
            user_data: 0,
            iocompletecb,
            discard: self.block_prop.discard,
            write_zeroes: self.block_prop.write_zeroes,
            combine_req: None,
        }
    }

    fn process_request(
        &mut self,
        opcode: OpCode,
        req_list: Vec<CombineRequest>,
        completecb: T,
    ) -> Result<()> {
        if req_list.is_empty() {
            return self.complete_request(opcode, 0, completecb);
        }
        let single_req = req_list.len() == 1;
        let cnt = Arc::new(AtomicU32::new(req_list.len() as u32));
        let res = Arc::new(AtomicI64::new(0));
        for req in req_list {
            let mut aiocb = self.package_aiocb(
                opcode,
                req.iov,
                req.offset as usize,
                req.nbytes,
                completecb.clone(),
            );
            if !single_req {
                aiocb.combine_req = Some((cnt.clone(), res.clone()));
            }
            self.aio.borrow_mut().submit_request(aiocb)?;
        }
        Ok(())
    }

    pub fn read_vectored(&mut self, req_list: Vec<CombineRequest>, completecb: T) -> Result<()> {
        self.process_request(OpCode::Preadv, req_list, completecb)
    }

    pub fn complete_request(&mut self, opcode: OpCode, res: i64, completecb: T) -> Result<()> {
        let iovec: Vec<Iovec> = Vec::new();
        let aiocb = self.package_aiocb(opcode, iovec.to_vec(), 0, 0, completecb);
        (self.aio.borrow_mut().complete_func)(&aiocb, res)
    }

    pub fn write_vectored(&mut self, req_list: Vec<CombineRequest>, completecb: T) -> Result<()> {
        self.process_request(OpCode::Pwritev, req_list, completecb)
    }

    pub fn write_zeroes(
        &mut self,
        req_list: Vec<CombineRequest>,
        completecb: T,
        unmap: bool,
    ) -> Result<()> {
        let opcode = if unmap {
            OpCode::WriteZeroesUnmap
        } else {
            OpCode::WriteZeroes
        };
        self.process_request(opcode, req_list, completecb)
    }

    pub fn discard(&mut self, req_list: Vec<CombineRequest>, completecb: T) -> Result<()> {
        self.process_request(OpCode::Discard, req_list, completecb)
    }

    pub fn datasync(&mut self, completecb: T) -> Result<()> {
        let aiocb = self.package_aiocb(OpCode::Fdsync, Vec::new(), 0, 0, completecb);
        self.aio.borrow_mut().submit_request(aiocb)
    }

    pub fn flush_request(&mut self) -> Result<()> {
        self.aio.borrow_mut().flush_request()
    }

    pub fn drain_request(&self) {
        while self.incomplete.load(Ordering::Acquire) != 0 {
            continue;
        }
    }

    pub fn register_io_event(
        &mut self,
        broken: Arc<AtomicBool>,
        error_cb: BlockIoErrorCallback,
    ) -> Result<()> {
        let handler = FileIoHandler::new(self.aio.clone(), broken, error_cb);
        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
        register_event_helper(
            notifiers,
            self.block_prop.iothread.as_ref(),
            &mut self.delete_evts,
        )
    }

    pub fn unregister_io_event(&mut self) -> Result<()> {
        unregister_event_helper(self.block_prop.iothread.as_ref(), &mut self.delete_evts)
    }

    pub fn actual_size(&mut self) -> Result<u64> {
        let meta_data = self.file.metadata()?;
        Ok(meta_data.st_blocks() * DEFAULT_SECTOR_SIZE)
    }

    pub fn disk_size(&mut self) -> Result<u64> {
        let disk_size = self
            .file
            .as_ref()
            .seek(SeekFrom::End(0))
            .with_context(|| "Failed to seek the end for file")?;
        Ok(disk_size)
    }

    pub fn extend_to_len(&mut self, len: u64) -> Result<()> {
        let file_end = self.file.as_ref().seek(SeekFrom::End(0))?;
        if len > file_end {
            self.file.set_len(len)?;
        }
        Ok(())
    }

    // Find the data / hole range around offset `start`.
    // According to linux man-pages:
    //
    // off_t lseek(int fd, off_t offset, int whence);
    //
    // SEEK_DATA:
    // Adjust the file offset to the next location in the file greater than or equal to `offset`
    // containing data. If offset points to data, then the file offset is set to `offset`.
    // SEEK_HOLE:
    // Adjust the file offset to the next hole in the file greater than or equal to offset. If offset points into the
    // middle of a hole, then the file offset is set to offset. If there is no hole past offset, then the file offset is
    // adjusted to the end of the file (i.e., there is an implicit hole at the end of any file).
    //
    // Return Value:
    // Upon successful completion, lseek() returns the resulting offset location as measured in bytes from the beginning of the file.
    // On error, the value (off_t) -1 is returned and errno is set to indicate the error.
    //
    // Common error codes:
    // EBADF: fd is not an open file descriptor.
    // EINVAL: whence is not valid. Or: the resulting file offset would be negative, or beyond the end of a seekable device.
    // EOVERFLOW: The resulting file offset cannot be represented in an off_t.
    // ESPIPE: fd is associated with a pipe, socket, or FIFO.
    // ENXIO: whence is SEEK_DATA or SEEK_HOLE, and the current file offset is beyond the end of the file.
    //
    // So, SEEK_DATA has these cases:
    // D1. doff == start: start is in data.
    // D2. doff > start: start is in a hole, next data at doff.
    // D3. doff < 0 && errno == ENXIO: either start is in a trailing hole or start is beyond EOF.
    // D4. doff < 0 && errno != ENXIO: error.
    //
    // SEEK_HOLE has these cases:
    // H1: hoff == start: start is in a hole.
    // H2: hoff > start: start is in data, next hole at hoff.
    // H3: hoff < 0, errno = ENXIO: start is beyond EOF.
    // H4: hoff < 0, errno != ENXIO: error.
    pub fn find_range_start(&mut self, start: u64, data_range: bool) -> Result<i64> {
        if start > i64::MAX as u64 {
            bail!("Too large offset {}", start);
        }

        let file_fd = self.file.as_raw_fd();
        let whence = if data_range {
            libc::SEEK_DATA
        } else {
            libc::SEEK_HOLE
        };

        // SAFETY: validated `start`.
        let off = unsafe { libc::lseek(file_fd, start as i64, whence) };

        if off < 0 {
            let errno = nix::errno::errno();
            // D4 or H4: error.
            if errno != libc::ENXIO {
                bail!("lseek() whence {} error {}", whence, errno);
            }
            // D3 or H3.
            return Ok(-1);
        }

        // Invalid return by lseek().
        if off < start as i64 {
            bail!(
                "lseek() whence {} return invalid value {} around offset {}",
                whence,
                off,
                start
            );
        }

        // D1 or H1: off == start: start(off) is in a data(D1) / hole(H1).
        // D2 or H2: off > start: start is in hole(D2) / data(H2), next data(D2) / hole(H2) at off.
        Ok(off)
    }
}

struct FileIoHandler<T: Clone + 'static> {
    aio: Rc<RefCell<Aio<T>>>,
    broken: Arc<AtomicBool>,
    error_cb: BlockIoErrorCallback,
}

impl<T: Clone + 'static> FileIoHandler<T> {
    pub fn new(
        aio: Rc<RefCell<Aio<T>>>,
        broken: Arc<AtomicBool>,
        error_cb: BlockIoErrorCallback,
    ) -> Self {
        Self {
            aio,
            broken,
            error_cb,
        }
    }

    fn aio_complete_handler(&mut self) -> Result<bool> {
        let error_cb = self.error_cb.clone();
        self.aio.borrow_mut().handle_complete().inspect_err(|_e| {
            error_cb();
        })
    }
}

impl<T: Clone + 'static> EventNotifierHelper for FileIoHandler<T> {
    fn internal_notifiers(handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let handler_raw = handler.lock().unwrap();
        let mut notifiers = Vec::new();

        // Register event notifier for aio.
        let h_clone = handler.clone();
        let h: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut h_lock = h_clone.lock().unwrap();
            if h_lock.broken.load(Ordering::SeqCst) {
                return None;
            }
            if let Err(ref e) = h_lock.aio_complete_handler() {
                error!("Failed to handle aio {:?}", e);
            }
            None
        });
        let h_clone = handler.clone();
        let handler_iopoll: Box<NotifierCallback> = Box::new(move |_, _fd: RawFd| {
            let mut h_lock = h_clone.lock().unwrap();
            if h_lock.broken.load(Ordering::SeqCst) {
                return None;
            }
            if h_lock.aio.borrow_mut().get_engine() == AioEngine::Off {
                return None;
            }
            match h_lock.aio_complete_handler() {
                Ok(done) => {
                    if done {
                        Some(Vec::new())
                    } else {
                        None
                    }
                }
                Err(e) => {
                    error!("Failed to handle aio {:?}", e);
                    None
                }
            }
        });
        notifiers.push(build_event_notifier(
            handler_raw.aio.borrow_mut().fd.as_raw_fd(),
            vec![h],
            Some(handler_iopoll),
        ));

        notifiers
    }
}

fn build_event_notifier(
    fd: RawFd,
    handlers: Vec<Rc<NotifierCallback>>,
    handler_poll: Option<Box<NotifierCallback>>,
) -> EventNotifier {
    let mut notifier = EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        handlers,
    );
    notifier.handler_poll = handler_poll;
    notifier
}

#[cfg(test)]
mod test {
    use std::fs::{remove_file, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;

    use super::*;
    use crate::qcow2::SyncAioInfo;
    use crate::*;
    use util::aio::AioEngine;

    #[test]
    fn test_find_range_start() {
        let path = "/tmp/test_find_range_start_file";
        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR)
                .mode(0o660)
                .open(path)
                .unwrap(),
        );

        let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();
        let mut file_driver = FileDriver::new(file, aio, BlockProperty::default());
        // End of file.
        let off = file_driver.find_range_start(0, false).unwrap();
        assert_eq!(off, -1);
        let off = file_driver.find_range_start(0, true).unwrap();
        assert_eq!(off, -1);

        // Write 4096 bytes in offset 4096 bytes.
        // Note: We are using cache IO. Different file systems may have differences in cache IO alignment.
        // So we tested all by using 4K alignment IO, which can already meet the needs of the vast majority of file systems.
        let buf = [1_u8; 4094];
        let iov = Iovec::new(buf.as_ptr() as u64, buf.len() as u64);
        let req = CombineRequest::new(vec![iov], 4096, buf.len() as u64);
        assert!(file_driver.write_vectored(vec![req], ()).is_ok());
        let off = file_driver.find_range_start(0, true).unwrap();
        assert_eq!(off, 4096);
        let off = file_driver.find_range_start(0, false).unwrap();
        assert_eq!(off, 0);

        remove_file(path).unwrap();
    }
}
