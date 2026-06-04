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

pub mod aio;
pub mod emulator;
pub mod socket;

use anyhow::anyhow;
use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

pub const TPM_CRB_BUFFER_MAX: usize = 3968; // 0x1000 - 0x80 TPM_CRB_ADDR_SIZE - A_CRB_DATA_BUFFER
pub const TPM_TIS_BUFFER_MAX: usize = 4096;
pub const TPM_SUCCESS: u32 = 0x0;

const PTM_BLOB_TYPE_PERMANENT: u32 = 1;
const PTM_BLOB_TYPE_VOLATILE: u32 = 2;
const PTM_BLOB_TYPE_SAVESTATE: u32 = 3;

const PTM_STATE_FLAG_DECRYPTED: u32 = 1;

const PTM_INIT_FLAG_DELETE_VOLATILE: u32 = 1;

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
        let len = buf.len();
        let expect_len = self.get_resp_size();

        if len != expect_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "PtmRes buffer is of incorrect length. Got {len} expected {expect_len}."
            )));
        }

        *self = BigEndian::read_u32(&buf[..size_of::<PtmResult>()]);
        Ok(())
    }

    #[inline]
    fn get_result_code(&self) -> u32 {
        *self
    }

    #[inline]
    fn get_req_size(&self) -> usize {
        0
    }

    #[inline]
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
        let len = buf.len();
        let expect_len = self.get_resp_size();

        if len != self.get_resp_size() {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for GetCapability cmd is of incorrect length. Got {len} expected {expect_len}."
            )));
        }
        *self = BigEndian::read_u64(&buf[..size_of::<u64>()]);

        Ok(())
    }

    #[inline]
    fn get_result_code(&self) -> u32 {
        ((*self) >> 32) as u32
    }

    #[inline]
    fn get_req_size(&self) -> usize {
        0
    }

    #[inline]
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

impl Ptm for PtmEst {
    fn to_req_buf(&self) -> Vec<u8> {
        // tpm's GetTpmEstablished call doesn't need any supporting message
        // return an empty Buffer
        Vec::new()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        let len = buf.len();
        let expect_len = self.get_resp_size();

        if len != expect_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for GetTpmEstablished cmd is of incorrect length. Got {len} expected {expect_len}."
            )));
        }
        self.result_code = BigEndian::read_u32(&buf[..size_of::<u32>()]);
        self.resp.bit = buf[4];
        Ok(())
    }

    #[inline]
    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    #[inline]
    fn get_req_size(&self) -> usize {
        0
    }

    #[inline]
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
        let len = buf.len();
        let expect_len = self.get_resp_size();

        if len != expect_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for Init cmd is of incorrect length. Got {len} expected {expect_len}."
            )));
        }
        self.result_code = BigEndian::read_u32(buf);
        Ok(())
    }

    #[inline]
    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    #[inline]
    fn get_req_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    #[inline]
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

    #[inline]
    pub fn get_bufsize(&self) -> u32 {
        self.resp.bufsize
    }
}

impl Ptm for PtmSetBufferSize {
    fn to_req_buf(&self) -> Vec<u8> {
        self.req.buffersize.to_be_bytes().to_vec()
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        let len = buf.len();
        let expect_len = self.get_resp_size();

        if len != expect_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for CmdSetBufferSize cmd is of incorrect length. Got {len} expected {expect_len}."
            )));
        }
        self.result_code = BigEndian::read_u32(&buf[0..4]);
        self.resp.bufsize = BigEndian::read_u32(&buf[4..8]);
        self.resp.minsize = BigEndian::read_u32(&buf[8..12]);
        self.resp.maxsize = BigEndian::read_u32(&buf[12..16]);

        Ok(())
    }

    #[inline]
    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    #[inline]
    fn get_req_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    #[inline]
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
        let len = buf.len();
        let expect_len = self.get_resp_size();

        if len != expect_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for SetLocality cmd is of incorrect length. Got {len} expected {expect_len}."
            )));
        }
        self.result_code = BigEndian::read_u32(buf);
        Ok(())
    }

    #[inline]
    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    #[inline]
    fn get_req_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    #[inline]
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
        let len = buf.len();
        let expect_len = self.get_resp_size();

        if len != expect_len {
            return Err(Error::ConvertToPtm(anyhow!(
                "Response for ResetEstablishedBit cmd is of incorrect length. Got {len} expected {expect_len}."
            )));
        }
        self.result_code = BigEndian::read_u32(buf);
        Ok(())
    }

    #[inline]
    fn get_result_code(&self) -> u32 {
        self.result_code
    }

    #[inline]
    fn get_req_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    #[inline]
    fn get_resp_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }
}

#[derive(Debug, Default)]
pub struct PtmGetState {
    pub req_state_flags: u32,
    pub req_type: u32,
    pub req_offset: u32,
    pub tpm_result: u32,
    pub resp_state_flags: u32,
    pub totlength: u32,
    pub length: u32,
}

impl Ptm for PtmGetState {
    fn to_req_buf(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.req_state_flags.to_be_bytes());
        buf.extend_from_slice(&self.req_type.to_be_bytes());
        buf.extend_from_slice(&self.req_offset.to_be_bytes());
        buf
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        if buf.len() < self.get_resp_size() {
            return Err(Error::ConvertToPtm(anyhow::anyhow!(
                "PtmGetState response too short"
            )));
        }

        self.tpm_result = BigEndian::read_u32(&buf[0..4]);
        self.resp_state_flags = BigEndian::read_u32(&buf[4..8]);
        self.totlength = BigEndian::read_u32(&buf[8..12]);
        self.length = BigEndian::read_u32(&buf[12..16]);

        Ok(())
    }

    fn get_result_code(&self) -> u32 {
        if self.tpm_result != TPM_SUCCESS && (self.tpm_result & 0x800) == 0 {
            self.tpm_result
        } else {
            TPM_SUCCESS
        }
    }

    #[inline]
    fn get_req_size(&self) -> usize {
        3 * std::mem::size_of::<u32>()
    }

    #[inline]
    fn get_resp_size(&self) -> usize {
        4 * std::mem::size_of::<u32>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptmresult() -> Result<()> {
        let mut result_code: PtmResult = 0;

        assert_eq!(result_code.get_req_size(), 0);
        assert_eq!(result_code.get_resp_size(), 4);
        assert!(result_code.to_req_buf().is_empty());

        let buf: &[u8] = &[0, 0, 0, 1];
        result_code.update_ptm_with_response(buf)?;
        assert_eq!(result_code.get_result_code(), 0x1);
        Ok(())
    }

    #[test]
    fn test_ptmcap() -> Result<()> {
        let mut cap: PtmCap = 0x0;

        assert_eq!(cap.get_req_size(), 0);
        assert_eq!(cap.get_resp_size(), 8);
        assert!(cap.to_req_buf().is_empty());

        let buf: &[u8] = &[0, 0, 0, 0xE, 0, 0, 0xFF, 0xFF];
        cap.update_ptm_with_response(buf)?;
        assert_eq!(cap.get_result_code(), 0xE);
        Ok(())
    }

    #[test]
    fn test_ptmest() -> Result<()> {
        let mut est: PtmEst = PtmEst::new();

        assert_eq!(est.get_req_size(), 0);
        assert_eq!(est.get_resp_size(), 8);
        assert!(est.to_req_buf().is_empty());

        let buf: &[u8] = &[0, 0, 0xE, 0, 0xC, 0, 1, 1];
        est.update_ptm_with_response(buf)?;
        assert_eq!(est.get_result_code(), 0xE00);
        assert_eq!(est.resp.bit, 0xC);
        Ok(())
    }

    #[test]
    fn test_ptminit() -> Result<()> {
        let mut init: PtmInit = PtmInit::new();
        init.init_flags = 0x1;

        assert_eq!(init.get_req_size(), 4);
        assert_eq!(init.get_resp_size(), 4);

        let buf = init.to_req_buf();
        assert_eq!(buf, [0x0, 0x0, 0x0, 0x1]);

        let response_buf: &[u8] = &[0, 0, 0xE, 0];
        init.update_ptm_with_response(response_buf)?;
        assert_eq!(init.get_result_code(), 0xE00);
        Ok(())
    }

    #[test]
    fn test_ptmsetbuffersize() -> Result<()> {
        let mut psbs: PtmSetBufferSize = PtmSetBufferSize::new(1024);

        assert_eq!(psbs.get_req_size(), 4);
        assert_eq!(psbs.get_resp_size(), 16);

        let req_buf = psbs.to_req_buf();
        assert_eq!(req_buf, 1024u32.to_be_bytes());

        let buf: &[u8] = &[
            0, 0x12, 0x34, 0x56, 0, 0, 0, 0xA, 0, 0, 0, 0xB, 0, 0, 0, 0xC,
        ];
        psbs.update_ptm_with_response(buf)?;
        assert_eq!(psbs.get_result_code(), 0x123456);
        assert_eq!(psbs.get_bufsize(), 0xA);
        assert_eq!(psbs.resp.minsize, 0xB);
        assert_eq!(psbs.resp.maxsize, 0xC);
        Ok(())
    }

    #[test]
    fn test_ptmsetloc() -> Result<()> {
        let mut psl = PtmSetLoc::new();
        psl.loc = 0x3;

        assert_eq!(psl.get_req_size(), 4);
        assert_eq!(psl.get_resp_size(), 4);

        let req_buf = psl.to_req_buf();
        assert_eq!(req_buf, [0x0, 0x0, 0x0, 0x3]);

        let resp_buf: &[u8] = &[0x0, 0x0, 0x0, 0x1];
        psl.update_ptm_with_response(resp_buf)?;
        assert_eq!(psl.get_result_code(), 0x1);
        Ok(())
    }

    #[test]
    fn test_ptmresetest() -> Result<()> {
        let mut pre = PtmResetEst::new();
        pre.loc = 0x2;

        assert_eq!(pre.get_req_size(), 4);
        assert_eq!(pre.get_resp_size(), 4);

        let req_buf = pre.to_req_buf();
        assert_eq!(req_buf, [0x0, 0x0, 0x0, 0x2]);

        let resp_buf: &[u8] = &[0x0, 0x0, 0x0, 0x0];
        pre.update_ptm_with_response(resp_buf)?;

        assert_eq!(pre.get_result_code(), 0x0);
        Ok(())
    }

    #[test]
    fn test_ptmgetstate() -> Result<()> {
        let mut pgs = PtmGetState::default();
        pgs.req_state_flags = 0x1;
        pgs.req_type = 0x2;
        pgs.req_offset = 0x3;

        assert_eq!(pgs.get_req_size(), 12);
        assert_eq!(pgs.get_resp_size(), 16);

        let req_buf = pgs.to_req_buf();
        assert_eq!(req_buf.len(), 12);
        assert_eq!(req_buf[0..4], [0x0, 0x0, 0x0, 0x1]);
        assert_eq!(req_buf[4..8], [0x0, 0x0, 0x0, 0x2]);
        assert_eq!(req_buf[8..12], [0x0, 0x0, 0x0, 0x3]);

        let resp_buf_err: &[u8] = &[
            0x0, 0x0, 0x0, 0x5, // tpm_result = 5
            0x0, 0x0, 0x0, 0x1, // resp_state_flags = 1
            0x0, 0x0, 0x4, 0x0, // totlength = 1024
            0x0, 0x0, 0x2, 0x0, // length = 512
        ];
        pgs.update_ptm_with_response(resp_buf_err)?;
        assert_eq!(pgs.get_result_code(), 0x5);
        assert_eq!(pgs.resp_state_flags, 0x1);
        assert_eq!(pgs.totlength, 1024);
        assert_eq!(pgs.length, 512);

        let resp_buf_masked: &[u8] = &[
            0x0, 0x0, 0x08, 0x05, // tpm_result = 0x805 (0x805 & 0x800 != 0)
            0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x2, 0x0,
        ];
        pgs.update_ptm_with_response(resp_buf_masked)?;
        assert_eq!(pgs.get_result_code(), TPM_SUCCESS);

        Ok(())
    }

    #[test]
    fn test_update_with_invalid_length() {
        let mut result_code: PtmResult = 0;
        let invalid_buf: &[u8] = &[0, 0, 1];

        let res = result_code.update_ptm_with_response(invalid_buf);
        assert!(res.is_err());

        if let Err(Error::ConvertToPtm(_)) = res {
            // pass
        } else {
            panic!("Expected Error::ConvertToPtm, got {:?}", res);
        }
    }
}
