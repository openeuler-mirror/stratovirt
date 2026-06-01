// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

pub mod socket;

use anyhow::anyhow;
use thiserror::Error;

pub const TPM_CRB_BUFFER_MAX: usize = 3968; // 0x1000 - 0x80 TPM_CRB_ADDR_SIZE - A_CRB_DATA_BUFFER
pub const TPM_TIS_BUFFER_MAX: usize = 4096;
pub const TPM_SUCCESS: u32 = 0x0;

/*
 * Structures required to process Request and Responses of Control commands
 * used by control channel over UNIX socket interface
 *
 * All messages contain big-endian data.
 *
 * Reference: https://github.com/stefanberger/swtpm/blob/master/man/man3/swtpm_ioctls.pod
 */
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CtrlCmdCode {
    GetCapability = 1,
    Init,
    Shutdown,
    GetTpmEstablished,
    SetLocality,
    HashStart,
    HashData,
    HashEnd,
    CancelTpmCmd,
    StoreVolatile,
    ResetTpmEstablished,
    GetStateBlob,
    SetStateBlob,
    Stop,
    GetConfig,
    SetDatafd,
    SetBufferSize,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed converting buf to PTM ")]
    ConvertToPtm(#[source] anyhow::Error),
}

type Result<T> = anyhow::Result<T, Error>;

pub trait Ptm {
    // Convert PTM Request to bytes to be sent to tpm
    fn to_req_buf(&self) -> Vec<u8>;

    // Update PTM from tpm's response
    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()>;

    // Get tpm result
    fn get_result_code(&self) -> u32;

    // Get request size
    fn get_req_size(&self) -> usize;

    // Get response size
    fn get_resp_size(&self) -> usize;
}

/*
 * Every response for a tpm Control Command execution must hold tpm return
 * code (PtmResult) as its first element.
 * Based on the type of input Control Command additional data could be
 * appended to the response.
 */
pub type PtmResult = u32;

impl Ptm for PtmResult {
    fn to_req_buf(&self) -> Vec<u8> {
        Vec::new()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        const EXPECT_LEN: usize = 4;

        let len = buf.len();
        if len != EXPECT_LEN {
            return Err(Error::ConvertToPtm(anyhow!(
                "PtmRes buffer is of incorrect length. Got {len} expected {EXPECT_LEN}."
            )));
        }

        *self = u32::from_be_bytes(buf.try_into().unwrap());
        Ok(())
    }

    fn get_result_code(&self) -> u32 {
        *self
    }

    fn get_req_size(&self) -> usize {
        0
    }

    fn get_resp_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }
}

/* GET_CAPABILITY Response */
pub type PtmCap = u64;

impl Ptm for PtmCap {
    fn to_req_buf(&self) -> Vec<u8> {
        // tpm's GetCapability call doesn't need any supporting message
        // return an empty Buffer
        Vec::new()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        let expected_len = 8;
        let len = buf.len();
        if len != self.get_resp_size() {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for GetCapability cmd is of incorrect length. Got {len} expected {expected_len}."
            )));
        }
        *self = u64::from_be_bytes(buf[..].try_into().unwrap());
        Ok(())
    }

    fn get_result_code(&self) -> u32 {
        ((*self) >> 32) as u32
    }

    fn get_req_size(&self) -> usize {
        0
    }

    fn get_resp_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }
}

/* GET_TPMESTABLISHED Response */
#[derive(Debug)]
pub struct PtmEstResp {
    pub bit: u8,
}

#[derive(Debug)]
pub struct PtmEst {
    pub resp: PtmEstResp,
    pub result_code: PtmResult,
}

impl PtmEst {
    pub fn new() -> Self {
        Self {
            result_code: 0,
            resp: PtmEstResp { bit: 0 },
        }
    }
}

impl Default for PtmEst {
    fn default() -> Self {
        Self::new()
    }
}

impl Ptm for PtmEst {
    fn to_req_buf(&self) -> Vec<u8> {
        // tpm's GetTpmEstablished call doesn't need any supporting message
        // return an empty Buffer
        Vec::new()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        let expected_len = 8;
        let len = buf.len();
        if len != expected_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for GetTpmEstablished cmd is of incorrect length. Got {len} expected {expected_len}."
            )));
        }
        self.result_code = u32::from_be_bytes(buf[..4].try_into().unwrap());
        self.resp.bit = buf[4];
        Ok(())
    }

    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    fn get_req_size(&self) -> usize {
        0
    }

    fn get_resp_size(&self) -> usize {
        2 * std::mem::size_of::<u32>()
    }
}

/* INIT Response */
#[derive(Debug)]
pub struct PtmInit {
    /* request */
    pub init_flags: u32,
    /* response */
    pub result_code: PtmResult,
}

impl Default for PtmInit {
    fn default() -> Self {
        Self::new()
    }
}

impl PtmInit {
    pub fn new() -> Self {
        Self {
            init_flags: 0,
            result_code: 0,
        }
    }
}

impl Ptm for PtmInit {
    fn to_req_buf(&self) -> Vec<u8> {
        self.init_flags.to_be_bytes().to_vec()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        let expected_len = 4;
        let len = buf.len();
        if len != expected_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for Init cmd is of incorrect length. Got {len} expected {expected_len}."
            )));
        }
        self.result_code = u32::from_be_bytes(buf[..].try_into().unwrap());
        Ok(())
    }

    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    fn get_req_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    fn get_resp_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }
}

/*
 * PTM_SET_BUFFERSIZE: Set the buffer size to be used by the tpm.
 * A 0 on input queries for the current buffer size. Any other
 * number will try to set the buffer size. The returned number is
 * the buffer size that will be used, which can be larger than the
 * requested one, if it was below the minimum, or smaller than the
 * requested one, if it was above the maximum.
 *
 * SET_BUFFERSIZE Response
 */
#[derive(Debug)]
pub struct PtmSBSReq {
    buffersize: u32,
}

#[derive(Debug)]
pub struct PtmSBSResp {
    bufsize: u32,
    minsize: u32,
    maxsize: u32,
}

#[derive(Debug)]
pub struct PtmSetBufferSize {
    /* request */
    pub req: PtmSBSReq,
    /* response */
    pub resp: PtmSBSResp,
    pub result_code: PtmResult,
}

impl PtmSetBufferSize {
    pub fn new(req_buffsize: u32) -> Self {
        Self {
            req: PtmSBSReq {
                buffersize: req_buffsize,
            },
            resp: PtmSBSResp {
                bufsize: 0,
                minsize: 0,
                maxsize: 0,
            },
            result_code: 0,
        }
    }
    pub fn get_bufsize(&self) -> u32 {
        self.resp.bufsize
    }
}

impl Ptm for PtmSetBufferSize {
    fn to_req_buf(&self) -> Vec<u8> {
        self.req.buffersize.to_be_bytes().to_vec()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        let expected_len = 16;
        let len = buf.len();
        if len != expected_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for CmdSetBufferSize cmd is of incorrect length. Got {len} expected {expected_len}."
            )));
        }
        self.result_code = u32::from_be_bytes(buf[0..4].try_into().unwrap());

        let bufsize = &buf[4..8];
        self.resp.bufsize = u32::from_be_bytes(bufsize.try_into().unwrap());

        let minsize = &buf[8..12];
        self.resp.minsize = u32::from_be_bytes(minsize.try_into().unwrap());

        let maxsize = &buf[12..16];
        self.resp.maxsize = u32::from_be_bytes(maxsize.try_into().unwrap());

        Ok(())
    }

    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    fn get_req_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    fn get_resp_size(&self) -> usize {
        4 * std::mem::size_of::<u32>()
    }
}

#[derive(Debug)]
pub struct PtmSetLoc {
    /* request */
    pub loc: u32,
    /* response */
    pub result_code: PtmResult,
}

impl Default for PtmSetLoc {
    fn default() -> Self {
        Self::new()
    }
}

impl PtmSetLoc {
    pub fn new() -> Self {
        Self {
            loc: 0xff,
            result_code: 0,
        }
    }
}

impl Ptm for PtmSetLoc {
    fn to_req_buf(&self) -> Vec<u8> {
        self.loc.to_be_bytes().to_vec()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        let expected_len = 4;
        let len = buf.len();
        if len != expected_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for SetLocality cmd is of incorrect length. Got {len} expected {expected_len}."
            )));
        }
        self.result_code = u32::from_be_bytes(buf[..].try_into().unwrap());
        Ok(())
    }

    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    fn get_req_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    fn get_resp_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }
}

#[derive(Debug)]
pub struct PtmResetEst {
    /* request */
    pub loc: u32,
    /* response */
    pub result_code: PtmResult,
}

impl Default for PtmResetEst {
    fn default() -> Self {
        Self::new()
    }
}

impl PtmResetEst {
    pub fn new() -> Self {
        Self {
            loc: 0xff,
            result_code: 0,
        }
    }
}

impl Ptm for PtmResetEst {
    fn to_req_buf(&self) -> Vec<u8> {
        self.loc.to_be_bytes().to_vec()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        let expected_len = 4;
        let len = buf.len();
        if len != expected_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for ResetEstablishedBit cmd is of incorrect length. Got {len} expected {expected_len}."
            )));
        }
        self.result_code = u32::from_be_bytes(buf[..].try_into().unwrap());
        Ok(())
    }

    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    fn get_req_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    fn get_resp_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }
}
