// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use log::error;
use machine_manager::temp_cleaner::TempCleaner;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::slice;
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use util::unix::limit_permission;
use virtio::vhost::user::{
    RegionMemInfo, VhostUserHdrFlag, VhostUserMemHdr, VhostUserMsgHdr, VhostUserMsgReq,
    VhostUserVringAddr, VhostUserVringState, MAX_ATTACHED_FD_ENTRIES,
};
use virtio::VhostUser::VhostUserSock;

use anyhow::{bail, Context, Result};

/// The trait for dealing with vhost-user request in the server.
pub trait VhostUserReqHandler: Send + Sync {
    /// Set the current process as the owner of this file descriptor.
    fn set_owner(&mut self) -> Result<()>;

    /// Get a bitmask of supported virtio/vhost features.
    fn get_features(&self) -> Result<u64>;

    /// Inform the vhost subsystem which features to enable.
    ///
    /// # Arguments
    ///
    /// * `features` - The features from the vhost-user client in StratoVirt.
    fn set_features(&mut self, features: u64) -> Result<()>;

    /// Set the guest memory mappings for vhost to use.
    ///
    /// # Arguments
    ///
    /// * `regions` - The slice of memory region information for the message of memory table.
    /// * `fds` - The files descriptors are used to map shared memory for the process and
    /// StratoVirt.
    fn set_mem_table(&mut self, regions: &[RegionMemInfo], fds: &[RawFd]) -> Result<()>;

    /// Set the size of descriptors in the virtio queue.
    ///
    /// # Arguments
    ///
    /// * `queue_index` - The index of virtio queue.
    /// * `num` - The total size of virtio queue.
    fn set_vring_num(&mut self, queue_index: usize, num: u16) -> Result<()>;

    /// Set the addresses for a given virtio queue.
    ///
    /// # Arguments
    ///
    /// * `queue_index` - The index of virtio queue.
    /// * `flags` - Option flags.
    /// * `desc_table` - The start address of descriptor table.
    /// * `used_ring` - The start address of used ring.
    /// * `avail_ring` - The start address of avail ring.
    /// * `log` - The start address of log.
    fn set_vring_addr(
        &mut self,
        queue_index: usize,
        flags: u32,
        desc_table: u64,
        used_ring: u64,
        avail_ring: u64,
        log: u64,
    ) -> Result<()>;

    /// Set the first index to look for available descriptors.
    ///
    /// # Arguments
    ///
    /// * `queue_index` - The index of virtio queue.
    /// * `num` - the first index to look for available descriptors.
    fn set_vring_base(&mut self, queue_index: usize, num: u16) -> Result<()>;

    /// Set the eventfd to trigger when buffers need to be processed
    /// by the guest.
    ///
    /// # Arguments
    ///
    /// * `queue_index` - The index of virtio queue.
    /// * `fd` - The files descriptor used to notify the guest.
    fn set_vring_call(&mut self, queue_index: usize, fd: RawFd) -> Result<()>;

    /// Set the eventfd that will be signaled by the guest when buffers
    /// need to be processed by the host.
    ///
    /// # Arguments
    ///
    /// * `queue_index` - The index of virtio queue.
    /// * `fd` - The files descriptor used to notify the host.
    fn set_vring_kick(&mut self, queue_index: usize, fd: RawFd) -> Result<()>;

    /// set the status of virtio queue.
    ///
    /// # Arguments
    ///
    /// * `queue_index` - The index of virtio queue.
    /// * `status` - The status of virtio queue.
    fn set_vring_enable(&mut self, queue_index: usize, status: u32) -> Result<()>;
}

/// The vhost-user server handler can communicate with StratoVirt and set the data of requests
/// to the backend.
#[derive(Clone)]
pub struct VhostUserServerHandler {
    /// The information of socket used to communicate with StratoVirt.
    pub sock: VhostUserSock,
    /// The backend used to save the data of requests from StratoVirt.
    backend: Arc<Mutex<dyn VhostUserReqHandler>>,
    /// Used to determine whether the process should be terminated.
    pub should_exit: Arc<AtomicBool>,
}

fn close_fds(fds: Vec<RawFd>) {
    for fd in fds {
        let _ = unsafe { libc::close(fd) };
    }
}

fn is_invalid_fds(hdr: &mut VhostUserMsgHdr, rfds: Option<Vec<RawFd>>) -> Result<()> {
    match VhostUserMsgReq::from(hdr.request) {
        VhostUserMsgReq::SetMemTable => Ok(()),
        VhostUserMsgReq::SetVringCall => Ok(()),
        VhostUserMsgReq::SetVringKick => Ok(()),
        VhostUserMsgReq::SetSlaveReqFd => Ok(()),
        _ => {
            if rfds.is_some() {
                if let Some(fds) = rfds {
                    close_fds(fds);
                }
                bail!("The fds is invalid, request: {}", hdr.request);
            } else {
                Ok(())
            }
        }
    }
}

impl VhostUserServerHandler {
    /// Construct a vhost-user server handler
    ///
    /// # Arguments
    ///
    /// * `path` - The path of unix socket file which communicates with StratoVirt.
    /// * `backend` - The trait of backend used to save the data of requests from StratoVirt.
    pub fn new(
        path: &str,
        backend: Arc<Mutex<dyn VhostUserReqHandler>>,
        should_exit: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut sock = VhostUserSock::new(path);
        sock.domain
            .bind(false)
            .with_context(|| format!("Failed to bind for vhost user server {}", path))?;
        TempCleaner::add_path(path.to_string());
        limit_permission(path).with_context(|| format!("Failed to limit permission {}", path))?;

        Ok(VhostUserServerHandler {
            sock,
            backend,
            should_exit,
        })
    }

    fn recv_hdr_and_fds(&mut self) -> Result<(VhostUserMsgHdr, Option<Vec<RawFd>>)> {
        let mut hdr = VhostUserMsgHdr::default();
        let body_opt: Option<&mut u32> = None;
        let payload_opt: Option<&mut [u8]> = None;
        let mut fds = vec![0; MAX_ATTACHED_FD_ENTRIES];

        let (rcv_len, fds_num) = self
            .sock
            .recv_msg(Some(&mut hdr), body_opt, payload_opt, &mut fds)
            .with_context(|| "Failed to recv hdr and fds")?;

        if rcv_len != size_of::<VhostUserMsgHdr>() {
            bail!(
                "The received length {} is invalid, expect {}",
                rcv_len,
                size_of::<VhostUserMsgHdr>()
            );
        } else if hdr.is_invalid() {
            bail!(
                "The header of vhost user msg is invalid, request: {}, size: {}, flags: {}",
                hdr.request,
                hdr.size,
                hdr.flags
            );
        }

        let rfds = match fds_num {
            0 => None,
            n => {
                let mut fds_temp = Vec::with_capacity(n);
                fds_temp.extend_from_slice(&fds[0..n]);
                Some(fds_temp)
            }
        };

        is_invalid_fds(&mut hdr, rfds.clone())?;

        Ok((hdr, rfds))
    }

    fn recv_body(&mut self, len: usize) -> Result<(usize, Vec<u8>)> {
        let mut rbuf = vec![0u8; len];
        let body_opt: Option<&mut u32> = None;
        let hdr_opt: Option<&mut VhostUserMsgHdr> = None;

        let (rcv_len, _) = self
            .sock
            .recv_msg(hdr_opt, body_opt, Some(&mut rbuf), &mut [])
            .with_context(|| "Failed to recv msg body")?;

        if rcv_len != len {
            bail!(
                "The length of msg body {} is invalid, expected {}",
                rcv_len,
                len
            );
        }

        Ok((rcv_len, rbuf))
    }

    fn get_msg_body<'a, D: Sized>(
        &self,
        hdr: &VhostUserMsgHdr,
        buf: &'a [u8],
        len: usize,
    ) -> Result<&'a D> {
        if !self.is_valid_request(hdr, len, size_of::<D>()) {
            bail!(
                "Failed to get msg body for request {}, len {}, payload size {}, hdr.size {}",
                hdr.request,
                len,
                size_of::<D>(),
                hdr.size
            );
        }

        let body = unsafe { &*(buf.as_ptr() as *const D) };
        Ok(body)
    }

    fn send_ack_msg<D: Sized>(&mut self, request: u32, res: D, fds: &[RawFd]) -> Result<()> {
        let hdr = VhostUserMsgHdr::new(
            request,
            VhostUserHdrFlag::Reply as u32,
            size_of::<D>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;

        self.sock
            .send_msg(Some(&hdr), Some(&res), payload_opt, fds)
            .with_context(|| "Failed to send ack msg")?;

        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
    fn set_msg_mem_table(
        &mut self,
        hdr: &VhostUserMsgHdr,
        buf: &[u8],
        len: usize,
        fds_opt: Option<Vec<RawFd>>,
    ) -> Result<()> {
        if len < size_of::<VhostUserMemHdr>() {
            if let Some(fds) = fds_opt {
                close_fds(fds);
            }
            bail!("The header length of mem table is invalid {}", len);
        }

        let memhdrsize = size_of::<VhostUserMemHdr>();
        let memhdr = unsafe { &*(buf.as_ptr() as *const VhostUserMemHdr) };
        let total_size = (memhdr.nregions as usize * size_of::<RegionMemInfo>()) + memhdrsize;
        if (hdr.size as usize) != total_size {
            if let Some(fds) = fds_opt {
                close_fds(fds);
            }
            bail!(
                "The body length of mem table is invalid {}, expected {}",
                total_size,
                hdr.size,
            );
        }

        let regions = unsafe {
            slice::from_raw_parts(
                buf.as_ptr().add(memhdrsize) as *const RegionMemInfo,
                memhdr.nregions as usize,
            )
        };

        if let Some(fds) = fds_opt {
            let fds_len = fds.len();
            if fds_len != (memhdr.nregions as usize) {
                close_fds(fds);
                bail!(
                    "The length of fds {} for mem table is invalid, expected {}",
                    fds_len,
                    memhdr.nregions
                );
            }
            self.backend.lock().unwrap().set_mem_table(regions, &fds)?;
        } else {
            bail!("The fds of mem table is null");
        }

        Ok(())
    }

    fn is_valid_request(&self, hdr: &VhostUserMsgHdr, size: usize, expected: usize) -> bool {
        (hdr.size as usize == expected) && (size == expected) && !hdr.is_reply()
    }

    fn process_request(
        &mut self,
        hdr: &VhostUserMsgHdr,
        buf: &[u8],
        len: usize,
        rfds: Option<Vec<RawFd>>,
    ) -> Result<()> {
        match VhostUserMsgReq::from(hdr.request) {
            VhostUserMsgReq::GetFeatures => {
                if !self.is_valid_request(hdr, len, 0) {
                    bail!("Invalid request size of GetFeatures");
                }

                let features = self.backend.lock().unwrap().get_features()?;
                if hdr.need_reply() {
                    self.send_ack_msg(VhostUserMsgReq::GetFeatures as u32, features, &[])
                        .with_context(|| "Failed to send ack msg for getting features")?;
                }
            }
            VhostUserMsgReq::SetFeatures => {
                let features = self
                    .get_msg_body::<u64>(hdr, buf, len)
                    .with_context(|| "Failed to get msg body for setting features")?;
                self.backend.lock().unwrap().set_features(*features)?;
            }
            VhostUserMsgReq::SetOwner => {
                if !self.is_valid_request(hdr, len, 0) {
                    bail!("Invalid request size of SetOwner");
                }

                self.backend.lock().unwrap().set_owner()?;
            }
            VhostUserMsgReq::SetMemTable => {
                let ret = match self.set_msg_mem_table(hdr, buf, len, rfds) {
                    Err(ref e) => {
                        error!("Failed to set mem table {:?}", e);
                        1u64
                    }
                    Ok(_) => 0u64,
                };
                if hdr.need_reply() {
                    self.send_ack_msg(VhostUserMsgReq::SetMemTable as u32, ret, &[])
                        .with_context(|| "Failed to send ack msg for setting mem table")?;
                }
            }
            VhostUserMsgReq::SetVringNum => {
                let vringstate = self
                    .get_msg_body::<VhostUserVringState>(hdr, buf, len)
                    .with_context(|| "Failed to get msg body for setting vring num")?;
                self.backend
                    .lock()
                    .unwrap()
                    .set_vring_num(vringstate.index as usize, vringstate.value as u16)?;
            }
            VhostUserMsgReq::SetVringAddr => {
                let vringaddr = self
                    .get_msg_body::<VhostUserVringAddr>(hdr, buf, len)
                    .with_context(|| "Failed to get msg body for setting vring addr")?;
                self.backend.lock().unwrap().set_vring_addr(
                    vringaddr.index as usize,
                    vringaddr.flags,
                    vringaddr.desc_user_addr,
                    vringaddr.used_user_addr,
                    vringaddr.avail_user_addr,
                    vringaddr.log_guest_addr,
                )?;
            }
            VhostUserMsgReq::SetVringBase => {
                let vringstate = self
                    .get_msg_body::<VhostUserVringState>(hdr, buf, len)
                    .with_context(|| "Failed to get msg body for setting vring base")?;
                self.backend
                    .lock()
                    .unwrap()
                    .set_vring_base(vringstate.index as usize, vringstate.value as u16)?;
            }
            VhostUserMsgReq::SetVringEnable => {
                let vringstate = self
                    .get_msg_body::<VhostUserVringState>(hdr, buf, len)
                    .with_context(|| "Failed to get msg body for setting vring enable")?;
                self.backend
                    .lock()
                    .unwrap()
                    .set_vring_enable(vringstate.index as usize, vringstate.value)?;
            }
            VhostUserMsgReq::SetVringKick => {
                let index = self
                    .get_msg_body::<u64>(hdr, buf, len)
                    .with_context(|| "Failed to get msg body for setting vring kick")?;
                if let Some(fds) = rfds {
                    let fds_len = fds.len();
                    if fds_len != 1 {
                        close_fds(fds);
                        bail!("The length {} of fds for kicking is invalid", fds_len);
                    }
                    self.backend
                        .lock()
                        .unwrap()
                        .set_vring_kick(*index as usize, fds[0])?;
                } else {
                    bail!("The length of fds for kicking is null");
                }
            }
            VhostUserMsgReq::SetVringCall => {
                let index = self
                    .get_msg_body::<u64>(hdr, buf, len)
                    .with_context(|| "Failed to get msg body for setting vring call")?;
                if let Some(fds) = rfds {
                    let fds_len = fds.len();
                    if fds_len != 1 {
                        close_fds(fds);
                        bail!("The length {} of fds for calling is invalid", fds_len);
                    }
                    self.backend
                        .lock()
                        .unwrap()
                        .set_vring_call(*index as usize, fds[0])?;
                } else {
                    bail!("The length of fds for calling is null");
                }
            }
            _ => {
                bail!("The request {} is unknown", hdr.request);
            }
        };

        Ok(())
    }

    /// The function used to process requests from StratoVirt.
    pub fn handle_request(&mut self) -> Result<()> {
        let (hdr, rfds) = self
            .recv_hdr_and_fds()
            .with_context(|| "Failed to recv header and fds")?;

        let (len, buf) = match hdr.size {
            0 => (0, vec![0u8; 0]),
            _ => {
                let (rcv_len, rbuf) = self
                    .recv_body(hdr.size as usize)
                    .with_context(|| "Failed to recv msg body")?;
                (rcv_len, rbuf)
            }
        };

        self.process_request(&hdr, &buf, len, rfds)
            .with_context(|| format!("Failed to process the request {}", hdr.request))?;
        Ok(())
    }
}
