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

use std::io::{self, ErrorKind};
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use log::{error, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

use crate::aio::{self, AioError, AsyncMsg, AsyncMsgHandle};
use crate::socket::{self, SocketDev};
use crate::{
    BackendError, CtrlCmdCode, Ptm, PtmCap, PtmEst, PtmGetState, PtmInit, PtmResetEst, PtmResult,
    PtmSetBufferSize, PtmSetLoc, TpmBackend, TpmMigration, PTM_BLOB_TYPE_PERMANENT,
    PTM_BLOB_TYPE_SAVESTATE, PTM_BLOB_TYPE_VOLATILE, PTM_INIT_FLAG_DELETE_VOLATILE,
    PTM_STATE_FLAG_DECRYPTED, TPM_SUCCESS, TPM_TIS_BUFFER_MAX,
};

const TPM_INVALID_LOC: u32 = 0xff;

const TPM_REQ_HDR_SIZE: usize = 10;
const TPM_REQ_CC_OFFSET: usize = 6; // command code

pub const TPM_RSP_HDR_SIZE: usize = 10;
pub const TPM_RSP_PS_OFFSET: usize = 2; // param size
pub const TPM_RSP_RC_OFFSET: usize = 6; // response code

/* capability flags returned by PTM_GET_CAPABILITY */
const PTM_CAP_INIT: u64 = 1;
const PTM_CAP_SHUTDOWN: u64 = 1 << 1;
const PTM_CAP_GET_TPMESTABLISHED: u64 = 1 << 2;
const PTM_CAP_SET_LOCALITY: u64 = 1 << 3;
const PTM_CAP_CANCEL_TPM_CMD: u64 = 1 << 5;
const PTM_CAP_RESET_TPMESTABLISHED: u64 = 1 << 7;
const PTM_CAP_STOP: u64 = 1 << 10;
const PTM_CAP_SET_DATAFD: u64 = 1 << 12;
const PTM_CAP_SET_BUFFERSIZE: u64 = 1 << 13;

/// Check if the input command is selftest
pub fn is_selftest(input: &[u8]) -> bool {
    if input.len() >= TPM_REQ_HDR_SIZE {
        let ordinal: &[u8; 4] = input[TPM_REQ_CC_OFFSET..TPM_REQ_HDR_SIZE]
            .try_into()
            .expect("slice with incorrect length");

        return u32::from_ne_bytes(*ordinal).to_be() == 0x143; // 0x143 refers to TPM_CC_SelfTest in TPM2.0 spec part 2
    }
    false
}

#[derive(Error, Debug)]
pub enum EmulatorError {
    #[error("TPM Backend disconnected")]
    Disconnected,
    #[error("Control socket error: {0}")]
    ControlSocket(#[source] socket::Error),
    #[error("Data plane IO error: {0}")]
    DataPlaneIo(#[source] io::Error),
    #[error("Failed to initialize emulator: {0}")]
    Initialize(String),
    #[error("Failed to run control command")]
    RunControlCmd,
    #[error("Failed to parse response for control command {cmd:?}: {err}")]
    ParseResponse { cmd: CtrlCmdCode, err: String },
    #[error("Truncated read/write during control command")]
    TruncatedData,
    #[error("Invalid response size")]
    InvalidResponseSize,
    #[error("Failed to prepare data fd: {0}")]
    PrepareDataFd(#[source] std::io::Error),
    #[error("Emulator does not implement capability: {0}")]
    UnsupportedCapability(&'static str),
    #[error("Command failed with TPM Error Code: {0}")]
    TpmError(u32),
    #[error("Self test failed: {0}")]
    SelfTest(String),
}

impl From<socket::Error> for EmulatorError {
    fn from(value: socket::Error) -> Self {
        match value {
            socket::Error::Disconnected => Self::Disconnected,
            _ => Self::ControlSocket(value),
        }
    }
}

impl From<io::Error> for EmulatorError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof => {
                EmulatorError::Disconnected
            }
            _ => EmulatorError::DataPlaneIo(e),
        }
    }
}

/// Collapse the detailed emulator error into the backend-agnostic
/// `BackendError` exposed across the `TpmBackend` trait boundary.
impl From<EmulatorError> for BackendError {
    fn from(e: EmulatorError) -> Self {
        match e {
            EmulatorError::Disconnected
            | EmulatorError::ControlSocket(socket::Error::NotConnected) => {
                BackendError::Disconnected
            }
            EmulatorError::UnsupportedCapability(cap) => BackendError::UnsupportedCapability(cap),
            EmulatorError::TpmError(code) => BackendError::TpmError(code),
            other => BackendError::Other(anyhow::Error::new(other)),
        }
    }
}

impl From<BackendError> for AioError {
    fn from(val: BackendError) -> Self {
        match val {
            BackendError::Disconnected => AioError::Disconnected,
            other => AioError::TpmError(format!("{:?}", other)),
        }
    }
}

pub type Result<T> = anyhow::Result<T, EmulatorError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TpmStateBlob {
    pub flags: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TpmStateBlobs {
    pub permanent: TpmStateBlob,
    pub volatile: TpmStateBlob,
    pub savestate: TpmStateBlob,
}

pub struct Emulator {
    caps: PtmCap, /* capabilities of the TPM */
    control_socket: SocketDev,
    data_stream: SocketDev,
    evt_fd: Arc<EventFd>,
    established_flag_cached: bool,
    established_flag: bool,
    cur_loc: u32,
}

impl Emulator {
    /// Send data fd to swtpm
    fn set_data_fd(&mut self, data_fd: RawFd) -> Result<()> {
        let mut res: PtmResult = 0;
        self.run_control_cmd(&mut res, CtrlCmdCode::SetDatafd, Some(data_fd))
    }

    fn probe_and_check_caps(&mut self) -> Result<&mut Self> {
        self.probe_caps()
            .map_err(|e| EmulatorError::Initialize(format!("Failed to probe caps, {e:?}")))?;

        if !self.check_caps() {
            return Err(EmulatorError::Initialize(
                "Required capabilities not supported by tpm backend".to_string(),
            ));
        }
        Ok(self)
    }

    /// Gather TPM Capabilities and cache them in Emulator
    fn probe_caps(&mut self) -> Result<()> {
        let mut caps: PtmCap = 0;
        self.run_control_cmd(&mut caps, CtrlCmdCode::GetCapability, None)?;
        self.caps = caps;
        Ok(())
    }

    /// Check if minimum set of capabilities are supported
    fn check_caps(&mut self) -> bool {
        /* minimum required set of capabilities for TPM2.0 */
        const MIN_REQUIRED_CAPS: PtmCap = PTM_CAP_INIT
            | PTM_CAP_SHUTDOWN
            | PTM_CAP_GET_TPMESTABLISHED
            | PTM_CAP_SET_LOCALITY
            | PTM_CAP_RESET_TPMESTABLISHED
            | PTM_CAP_SET_DATAFD
            | PTM_CAP_STOP
            | PTM_CAP_SET_BUFFERSIZE;

        (self.caps & MIN_REQUIRED_CAPS) == MIN_REQUIRED_CAPS
    }

    /// Run Control Command
    ///
    /// # Arguments
    ///
    /// * `cmd` - Control Command to run
    /// * `msg` - Optional message to be sent along with Control Command
    /// * `msg_len_in` - length of 'msg'.ptm_to_request() in bytes
    /// * `msg_len_out` - length of expected output from Control Command in bytes
    fn run_control_cmd(
        &mut self,
        ptm: &mut impl Ptm,
        cmd: CtrlCmdCode,
        msg_fd: Option<RawFd>,
    ) -> Result<()> {
        const CTRL_RESP_SIZE: usize = 16;

        if ptm.get_resp_size() > CTRL_RESP_SIZE {
            return Err(EmulatorError::InvalidResponseSize);
        }

        let cmd_buf = (cmd as u32).to_be_bytes();
        let req_buf = ptm.to_req_buf();

        let mut buf = Vec::<u8>::with_capacity(mem::size_of::<u32>() + ptm.get_req_size());
        buf.extend(cmd_buf);
        buf.extend(req_buf);

        if let Some(fd) = msg_fd {
            self.control_socket.write_with_fd(&buf, fd)?;
        } else {
            self.control_socket.write_all(&buf)?;
        }

        let resp_size = ptm.get_resp_size();
        let mut output = vec![0_u8; resp_size];

        // Every control command gets at least a result code in response
        self.control_socket.read_exact(&mut output)?;

        if ptm.get_resp_size() != 0 {
            ptm.update_ptm_with_response(&output)
                .map_err(|e| EmulatorError::ParseResponse {
                    cmd,
                    err: e.to_string(),
                })?;
        }

        if ptm.get_result_code() != TPM_SUCCESS {
            return Err(EmulatorError::TpmError(ptm.get_result_code()));
        }

        Ok(())
    }

    /// Configure buffer size to use while communicating with swtpm
    fn set_buffer_size(&mut self, wanted_size: usize) -> Result<usize> {
        let mut psbs: PtmSetBufferSize = PtmSetBufferSize::new(wanted_size as u32);

        self.stop_tpm()?;

        self.run_control_cmd(&mut psbs, CtrlCmdCode::SetBufferSize, None)?;

        Ok(psbs.get_bufsize() as usize)
    }

    fn set_locality(&mut self, loc: u32) -> Result<()> {
        if self.cur_loc == loc {
            return Ok(());
        }

        let mut psl: PtmSetLoc = PtmSetLoc {
            loc,
            ..Default::default()
        };
        self.run_control_cmd(&mut psl, CtrlCmdCode::SetLocality, None)?;

        self.cur_loc = loc;

        Ok(())
    }

    fn stop_tpm(&mut self) -> Result<()> {
        let mut res: PtmResult = 0;

        self.run_control_cmd(&mut res, CtrlCmdCode::Stop, None)
    }

    fn get_state_blobs(&mut self) -> Result<TpmStateBlobs> {
        let permanent = self.get_state_blob(PTM_BLOB_TYPE_PERMANENT)?;
        let volatile = self.get_state_blob(PTM_BLOB_TYPE_VOLATILE)?;
        let savestate = self.get_state_blob(PTM_BLOB_TYPE_SAVESTATE)?;

        Ok(TpmStateBlobs {
            permanent,
            volatile,
            savestate,
        })
    }

    fn get_state_blob(&mut self, blob_type: u32) -> Result<TpmStateBlob> {
        let mut ptm_state = PtmGetState {
            req_state_flags: PTM_STATE_FLAG_DECRYPTED,
            req_type: blob_type,
            req_offset: 0,
            ..Default::default()
        };

        self.run_control_cmd(&mut ptm_state, CtrlCmdCode::GetStateBlob, None)?;

        if ptm_state.totlength != ptm_state.length {
            error!(
                "swtpm stateblob size mismatch: expected {}, got {}",
                ptm_state.totlength, ptm_state.length
            );
            return Err(EmulatorError::ParseResponse {
                cmd: CtrlCmdCode::GetStateBlob,
                err: format!(
                    "totlength {} != length {}",
                    ptm_state.totlength, ptm_state.length
                ),
            });
        }

        let mut data = vec![0u8; ptm_state.totlength as usize];
        if ptm_state.totlength > 0 {
            self.control_socket
                .read_exact(&mut data)
                .map_err(EmulatorError::ControlSocket)?;
        }

        Ok(TpmStateBlob {
            flags: ptm_state.resp_state_flags,
            data,
        })
    }

    fn set_state_blobs(&mut self, blobs: TpmStateBlobs) -> Result<()> {
        self.stop_tpm().map_err(|e| {
            EmulatorError::Initialize(format!(
                "Failed to stop TPM before restoring state: {:?}",
                e
            ))
        })?;

        self.set_state_blob(PTM_BLOB_TYPE_PERMANENT, &blobs.permanent)?;
        self.set_state_blob(PTM_BLOB_TYPE_VOLATILE, &blobs.volatile)?;
        self.set_state_blob(PTM_BLOB_TYPE_SAVESTATE, &blobs.savestate)?;

        Ok(())
    }

    fn set_state_blob(&mut self, blob_type: u32, blob: &TpmStateBlob) -> Result<()> {
        if blob.data.is_empty() {
            return Ok(());
        }

        // 16 bytes control header
        // [0..4] Command (CMD_SET_STATEBLOB = 0x0000_000D)
        // [4..8] state_flags
        // [8..12] type
        // [12..16] length (payload)
        let mut header = [0u8; 16];
        let cmd_val: u32 = CtrlCmdCode::SetStateBlob as u32;
        header[0..4].copy_from_slice(&cmd_val.to_be_bytes());
        header[4..8].copy_from_slice(&blob.flags.to_be_bytes());
        header[8..12].copy_from_slice(&blob_type.to_be_bytes());

        let length = blob.data.len() as u32;
        header[12..16].copy_from_slice(&length.to_be_bytes());

        self.control_socket.write_all(&header)?;
        self.control_socket.write_all(&blob.data)?;

        let mut resp = [0u8; 4];
        self.control_socket.read_exact(&mut resp)?;

        let mut tpm_result: PtmResult = 0;
        tpm_result
            .update_ptm_with_response(&resp[0..4])
            .inspect_err(|e| error!("Failed to update ptm with response, {e:?}"))
            .map_err(|_| EmulatorError::RunControlCmd)?;
        if tpm_result.get_result_code() != TPM_SUCCESS {
            error!(
                "swtpm setting stateblob (type {}) failed with TPM error {:#x}",
                blob_type, tpm_result
            );
            return Err(EmulatorError::TpmError(tpm_result));
        }

        Ok(())
    }

    /// Connect to the swtpm control socket and negotiate capabilities.
    ///
    /// `path` is the Unix Domain Socket swtpm is listening on.
    fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let (cli_stream, srv_stream) = UnixStream::pair()?;

        let mut emulator = Self {
            caps: 0,
            control_socket: SocketDev::new_with_path(path)?,
            data_stream: SocketDev::new(cli_stream),
            evt_fd: Arc::new(EventFd::new(libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)?),
            established_flag_cached: false,
            established_flag: false,
            cur_loc: TPM_INVALID_LOC,
        };

        emulator
            .probe_and_check_caps()?
            .set_data_fd(srv_stream.as_raw_fd())?;

        Ok(emulator)
    }

    /// Send a command over the data channel and read the response back into
    /// `cmd_buf`, returning the total response size.
    fn run_data_cmd(&mut self, cmd_buf: &mut [u8], cmd_len: usize) -> Result<usize> {
        let is_selftest_cmd = is_selftest(cmd_buf);

        self.data_stream.write_all(&cmd_buf[..cmd_len])?;

        let mut header = [0u8; TPM_RSP_HDR_SIZE];
        self.data_stream.read_exact(&mut header)?;

        let total_size =
            BigEndian::read_u32(&header[TPM_RSP_PS_OFFSET..TPM_RSP_RC_OFFSET]) as usize;
        if total_size < TPM_RSP_HDR_SIZE || total_size > cmd_buf.len() {
            return Err(EmulatorError::InvalidResponseSize);
        }

        if is_selftest_cmd && total_size != TPM_RSP_HDR_SIZE {
            return Err(EmulatorError::SelfTest(format!(
                "Self test response should have 10 bytes. Only {} returned",
                total_size
            )));
        }

        cmd_buf[..TPM_RSP_HDR_SIZE].copy_from_slice(&header);

        let remaining = total_size - TPM_RSP_HDR_SIZE;
        if remaining > 0 {
            self.data_stream
                .read_exact(&mut cmd_buf[TPM_RSP_HDR_SIZE..total_size])?;
        }

        Ok(total_size)
    }
}

impl AsyncMsgHandle for Emulator {
    fn handle_async_request(&mut self, request: AsyncMsg) -> (aio::Result<()>, Vec<u8>) {
        let AsyncMsg::Request {
            mut cmd_buf,
            cmd_len,
            locty,
        } = request;

        if let Err(e) = self.set_locality(locty as u32) {
            error!("TPM set locality failed: {:?}", e);
            return (Err(BackendError::from(e).into()), cmd_buf);
        }

        match self.process_request(&mut cmd_buf, cmd_len) {
            Ok(_) => (Ok(()), cmd_buf),
            Err(e) => (Err(e.into()), cmd_buf),
        }
    }

    fn get_evt_fd(&self) -> Arc<EventFd> {
        self.evt_fd.clone()
    }

    fn get_data_fd(&self) -> Option<RawFd> {
        self.data_stream.as_raw_fd()
    }
}

impl TpmBackend for Emulator {
    fn new(path: impl AsRef<Path>) -> anyhow::Result<Self, BackendError> {
        Ok(Self::connect(path)?)
    }

    fn get_buffer_size(&mut self) -> usize {
        self.set_buffer_size(0).unwrap_or(TPM_TIS_BUFFER_MAX)
    }

    fn startup_tpm(
        &mut self,
        buffersize: usize,
        is_resume: bool,
    ) -> anyhow::Result<(), BackendError> {
        let mut init: PtmInit = PtmInit::default();

        if buffersize != 0 {
            self.set_buffer_size(buffersize)?;
        }

        if is_resume {
            init.init_flags |= PTM_INIT_FLAG_DELETE_VOLATILE;
        }

        self.run_control_cmd(&mut init, CtrlCmdCode::Init, None)?;
        Ok(())
    }

    fn shutdown_tpm(&mut self) -> anyhow::Result<(), BackendError> {
        let mut res: PtmResult = 0;

        self.run_control_cmd(&mut res, CtrlCmdCode::Shutdown, None)?;
        Ok(())
    }

    fn process_request(
        &mut self,
        cmd_buf: &mut [u8],
        cmd_len: usize,
    ) -> anyhow::Result<usize, BackendError> {
        Ok(self.run_data_cmd(cmd_buf, cmd_len)?)
    }

    fn cancel_cmd(&mut self) -> anyhow::Result<(), BackendError> {
        // Check if emulator implements Cancel command
        if (self.caps & PTM_CAP_CANCEL_TPM_CMD) != PTM_CAP_CANCEL_TPM_CMD {
            return Err(BackendError::UnsupportedCapability("Cancel TPM Command"));
        }

        let mut res: PtmResult = 0;
        self.run_control_cmd(&mut res, CtrlCmdCode::CancelTpmCmd, None)?;
        Ok(())
    }

    fn get_established_flag(&mut self) -> anyhow::Result<bool, BackendError> {
        let mut est: PtmEst = PtmEst::default();

        if self.established_flag_cached {
            return Ok(self.established_flag);
        }

        if let Err(e) = self.run_control_cmd(&mut est, CtrlCmdCode::GetTpmEstablished, None) {
            error!("Failed to run CmdGetTpmEstablished control command. Error: {e:?}");
            return Err(e.into());
        }

        self.established_flag_cached = true;
        self.established_flag = est.resp.bit == 0;

        Ok(self.established_flag)
    }

    fn reset_established_flag(&mut self, loc: u8) -> anyhow::Result<(), BackendError> {
        if self.cur_loc != loc as u32 {
            warn!(
                "Reset established flag with another locality: {} current locality: {}",
                loc, self.cur_loc
            );
        }
        let mut pre: PtmResetEst = PtmResetEst {
            loc: loc as u32,
            ..Default::default()
        };
        self.run_control_cmd(&mut pre, CtrlCmdCode::ResetTpmEstablished, None)?;
        Ok(())
    }
}

impl TpmMigration for Emulator {
    fn get_state(&mut self) -> anyhow::Result<Vec<u8>> {
        let blobs = self.get_state_blobs()?;

        Ok(serde_json::to_vec(&blobs)?)
    }

    fn set_state(&mut self, state: Vec<u8>) -> anyhow::Result<()> {
        let blobs: TpmStateBlobs = serde_json::from_slice(&state)?;
        self.set_state_blobs(blobs)?;

        Ok(())
    }
}
