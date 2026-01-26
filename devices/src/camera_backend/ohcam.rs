// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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
use std::ffi::CStr;
use std::sync::RwLock;

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info, warn};
use once_cell::sync::Lazy;
use ui::console::{get_dpy_rotation, Rotation};

use crate::camera_backend::{
    CamBasicFmt, CameraAvailCallback, CameraBackend, CameraBrokenCallback, CameraFormatList,
    CameraFrame, CameraNotifyCallback, FmtType,
};
use machine_manager::{
    event,
    qmp::qmp_channel::QmpChannel,
    qmp::qmp_schema::{VmNotifyEvent, CAMERA_TYPE, DEVICE_CLASS_ID},
};
#[cfg(any(
    feature = "trace_to_logger",
    feature = "trace_to_ftrace",
    all(target_env = "ohos", feature = "trace_to_hitrace")
))]
use trace::trace_scope::Scope;
use util::aio::Iovec;
use util::ohos_binding::camera::*;
use util::ohos_binding::misc::bound_tokenid;
use util::ohos_binding::yuv::*;

type OhCamCB = RwLock<HashMap<String, OhCamCallBack>>;
static OHCAM_CALLBACKS: Lazy<OhCamCB> = Lazy::new(|| RwLock::new(HashMap::new()));

// In UVC, interval's unit is 100ns.
// So, fps * interval / 10_000_000 == 1.
const FPS_INTERVAL_TRANS: u32 = 10_000_000;
const MIN_WIDTH: i32 = 640;
const FRAME_FORMAT_WHITELIST: [i32; 4] = [
    CAMERA_FORMAT_YUYV422,
    CAMERA_FORMAT_NV12,
    CAMERA_FORMAT_YUV420SP,
    CAMERA_FORMAT_MJPEG,
];
const FPS_WHITELIST: [i32; 3] = [30, 15, 10];

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum OhCamStatus {
    #[default]
    Preempted,
    Started,
    StartFailed,
    Release,
}

#[allow(clippy::from_over_into)]
impl Into<u32> for OhCamStatus {
    fn into(self) -> u32 {
        match self {
            OhCamStatus::Preempted => 1,
            OhCamStatus::Started => 2,
            OhCamStatus::StartFailed => 3,
            OhCamStatus::Release => 4,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OhCamErrorCode {
    Success,
    NoSystemAppPermission,
    ParameterError,
    InvalidArgument,
    OperationNotAllowed,
    SessionNotConfig,
    SessionNotRunning,
    SessionConfigLocked,
    DeviceSettingLocked,
    ConflictCamera,
    DeviceDisabled,
    DevicePreempted,
    UnresolvedConflictsBetweenStreams,
    ServiceFatlError,
    Unknown,
}

impl From<i32> for OhCamErrorCode {
    fn from(val: i32) -> OhCamErrorCode {
        match val {
            0 => OhCamErrorCode::Success,
            202 => OhCamErrorCode::NoSystemAppPermission,
            401 => OhCamErrorCode::ParameterError,
            7400101 => OhCamErrorCode::InvalidArgument,
            7400102 => OhCamErrorCode::OperationNotAllowed,
            7400103 => OhCamErrorCode::SessionNotConfig,
            7400104 => OhCamErrorCode::SessionNotRunning,
            7400105 => OhCamErrorCode::SessionConfigLocked,
            7400106 => OhCamErrorCode::DeviceSettingLocked,
            7400107 => OhCamErrorCode::ConflictCamera,
            7400108 => OhCamErrorCode::DeviceDisabled,
            7400109 => OhCamErrorCode::DevicePreempted,
            7400110 => OhCamErrorCode::UnresolvedConflictsBetweenStreams,
            7400201 => OhCamErrorCode::ServiceFatlError,
            _ => OhCamErrorCode::Unknown,
        }
    }
}

#[derive(Default)]
struct OhCamCallBack {
    /// Callback to used to notify when data is coming.
    notify_cb: Option<CameraNotifyCallback>,
    /// Callback to used to notify the broken.
    broken_cb: Option<CameraNotifyCallback>,
    /// Callback to used to notify when status available or not.
    avail_cb: Option<CameraAvailCallback>,
    /// ID of OH camera device.
    camid: String,
    /// Flag whether the camera is turned on by ourselves or not.
    owned: bool,
    /// Flag for whether to OH camera status available or not.
    avail: bool,
    /// Record OH camera status.
    status: OhCamStatus,
    ptr: Option<u64>,
    buffer_size: u64,
}

impl OhCamCallBack {
    fn new(camid: String) -> Self {
        OhCamCallBack {
            notify_cb: None,
            broken_cb: None,
            avail_cb: None,
            camid,
            owned: false,
            avail: false,
            status: OhCamStatus::Release,
            ptr: None,
            buffer_size: 0,
        }
    }
    fn set_buffer(&mut self, addr: u64, s: i32) {
        self.buffer_size = s as u64;
        self.ptr = Some(addr);
    }

    fn get_buffer(&self) -> (Option<u64>, u64) {
        (self.ptr, self.buffer_size)
    }

    fn clear_buffer(&mut self) {
        self.buffer_size = 0;
        self.ptr = None;
    }

    fn set_notify_cb(&mut self, cb: CameraNotifyCallback) {
        self.notify_cb = Some(cb);
    }

    fn set_broken_cb(&mut self, cb: CameraNotifyCallback) {
        self.broken_cb = Some(cb);
    }

    fn set_avail_cb(&mut self, cb: CameraAvailCallback) {
        self.avail_cb = Some(cb);
    }

    fn notify(&self) {
        if let Some(notify_cb) = &self.notify_cb {
            notify_cb();
        }
    }

    fn broken(&self) {
        if let Some(broken_cb) = &self.broken_cb {
            broken_cb();
        }
    }

    fn set_owned(&mut self, owned: bool) {
        self.owned = owned;
    }

    fn avail(&mut self, avail: bool) {
        self.avail = avail;
        if !self.owned {
            return;
        }

        if !self.avail {
            self.send_status(OhCamStatus::Preempted);
        } else if let Some(avail_cb) = &self.avail_cb {
            avail_cb();
        }
    }

    fn on_error(&mut self, error_type: i32) {
        let error_code = OhCamErrorCode::from(error_type);
        if error_code == OhCamErrorCode::DevicePreempted {
            self.avail = false;
        }

        if !self.owned {
            return;
        }

        if OhCamErrorCode::from(error_type) == OhCamErrorCode::DevicePreempted {
            self.send_status(OhCamStatus::Preempted);
        }
    }

    fn get_avail(&self) -> bool {
        self.avail
    }

    fn send_status(&mut self, status: OhCamStatus) {
        if self.status == status {
            return;
        }

        self.status = status;
        if QmpChannel::is_connected() {
            let success_msg = VmNotifyEvent {
                klass: DEVICE_CLASS_ID,
                type_t: CAMERA_TYPE,
                code: status.into(),
                message: Some(self.camid.to_owned()),
            };
            event!(VmNotifyEvent; success_msg);
        } else {
            warn!("Qmp channel is not connected while sending camera status message");
        }
    }
}

fn ohcam_cb_set_owned(camid: &String, owned: bool) {
    if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(camid) {
        cb.set_owned(owned);
    }
}

fn ohcam_cb_get_avail(camid: &String) -> Option<bool> {
    if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(camid) {
        return Some(cb.get_avail());
    }

    None
}

fn ohcam_set_status(camid: &String, status: OhCamStatus) {
    if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(camid) {
        cb.send_status(status);
    }
}

#[cfg(any(
    feature = "trace_to_logger",
    feature = "trace_to_ftrace",
    all(target_env = "ohos", feature = "trace_to_hitrace")
))]
#[derive(Clone, Default)]
struct OhCameraAsyncScope {
    next_frame_id: u64,
    async_scope: Option<Scope>,
}

#[cfg(any(
    feature = "trace_to_logger",
    feature = "trace_to_ftrace",
    all(target_env = "ohos", feature = "trace_to_hitrace")
))]
impl OhCameraAsyncScope {
    fn start(&mut self) {
        self.async_scope = Some(trace::ohcam_next_frame(true, self.next_frame_id));
        self.next_frame_id += 1;
    }

    fn stop(&mut self) {
        self.async_scope = None;
    }
}

#[derive(Clone)]
struct OhPhysCamState {
    /// The physical position where the camera is mounted (e.g., Back, Front, FoldInner)
    cam_position: CamPosition,
    /// The actual mounting angle of the physical camera lens
    cam_orientation: Option<Rotation>,
    /// Whether the camera frame needs to be rotated
    rotation_required: bool,
    /// Whether the camera frame rotation is enabled
    rotation_enabled: bool,
    rotation_buffer: Vec<u8>,
}

impl OhPhysCamState {
    fn new(
        connection_type: CamConnectionType,
        position: CamPosition,
        orientation: Option<i32>,
    ) -> Self {
        let mut rotation_required = false;
        let mut cam_orientation = None;

        if let Some(value) = orientation {
            match value {
                0 => cam_orientation = Some(Rotation::Rotation0),
                90 => cam_orientation = Some(Rotation::Rotation90),
                180 => cam_orientation = Some(Rotation::Rotation180),
                270 => cam_orientation = Some(Rotation::Rotation270),
                _ => {
                    error!("OH Camera: invalid camera orientation value: {}", value);
                }
            }
        }

        if connection_type == CamConnectionType::BuiltIn && cam_orientation.is_some() {
            rotation_required = true;
        }

        Self {
            cam_position: position,
            cam_orientation,
            rotation_required,
            rotation_enabled: false,
            rotation_buffer: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct OhCameraBackend {
    // ID for this OhCameraBackend.
    id: String,
    // ID of OH camera device.
    camid: String,
    profile_cnt: u8,
    ctx: OhCamera,
    fmt_list: Vec<CameraFormatList>,
    selected_profile: u8,
    stream_on: bool,
    paused: bool,
    #[cfg(any(
        feature = "trace_to_logger",
        feature = "trace_to_ftrace",
        all(target_env = "ohos", feature = "trace_to_hitrace")
    ))]
    async_scope: Box<OhCameraAsyncScope>,
    tokenid: u64,
    fmt: Option<CamBasicFmt>,
    cam_state: OhPhysCamState,
}

// SAFETY:
// - The `OhCamera` type internally holds a raw pointer to a `OhCameraCtx` provided by
//   the Oh camera framework.
// - Although raw pointers are not `Send` or `Sync` by default, this backend ensures
//   that the camera handle (`ctx`) is only accessed through thread-safe API calls.
// - All operations on `OhCameraBackend` are protected by higher-level synchronization (i.g. mutex).
// - No aliasing mutable references to `ctx` are ever created across threads.
// - Therefore, it is safe to mark `CameraBackend` as `Send` and `Sync` under these invariants.
unsafe impl Send for OhCameraBackend {}
// SAFETY: Same reason as above.
unsafe impl Sync for OhCameraBackend {}

fn cam_fmt_from_oh(t: i32) -> Result<FmtType> {
    let fmt = match t {
        CAMERA_FORMAT_YUV420SP => FmtType::Nv21,
        CAMERA_FORMAT_NV12 => FmtType::Nv12,
        CAMERA_FORMAT_YUYV422 => FmtType::Yuy2,
        CAMERA_FORMAT_MJPEG => FmtType::Mjpg,
        _ => bail!("OHCAM: No supported type {}", t),
    };

    Ok(fmt)
}

impl Drop for OhCameraBackend {
    fn drop(&mut self) {
        OHCAM_CALLBACKS.write().unwrap().remove_entry(&self.camid);
    }
}

impl OhCameraBackend {
    pub fn new(id: String, cam_name: String, tokenid: u64) -> Result<Self> {
        let (ctx, profile_cnt, connection_type, position, orientation) =
            match OhCamera::new(cam_name.clone()) {
                Ok(v) => v,
                Err(code) => {
                    hisysevent::STRATOVIRT_CAMERA_INIT_FAILED(code);
                    return Err(anyhow!("Failed to init OhCamera, code is {code}."));
                }
            };

        Ok(OhCameraBackend {
            id,
            camid: cam_name,
            profile_cnt: profile_cnt as u8,
            ctx,
            fmt_list: vec![],
            selected_profile: 0,
            stream_on: false,
            paused: false,
            #[cfg(any(
                feature = "trace_to_logger",
                feature = "trace_to_ftrace",
                all(target_env = "ohos", feature = "trace_to_hitrace")
            ))]
            async_scope: Box::<OhCameraAsyncScope>::default(),
            tokenid,
            fmt: None,
            cam_state: OhPhysCamState::new(connection_type, position, orientation),
        })
    }
}

impl CameraBackend for OhCameraBackend {
    fn set_fmt(&mut self, cam_fmt: &CamBasicFmt) -> Result<()> {
        for fmt in &self.fmt_list {
            if fmt.format != cam_fmt.fmttype {
                continue;
            }
            for frm in &fmt.frame {
                if frm.width != cam_fmt.width || frm.height != cam_fmt.height {
                    continue;
                }

                let fps = FPS_INTERVAL_TRANS
                    .checked_div(frm.interval)
                    .with_context(|| format!("OHCAM: Invalid interval {}", frm.interval))?;
                if fps != cam_fmt.fps {
                    continue;
                }
                self.selected_profile = fmt.fmt_index - 1;
                self.ctx.set_fmt(i32::from(self.selected_profile))?;
                info!(
                    "OHCAM {}: set format {:?}, width {}, height {}",
                    self.camid, cam_fmt.fmttype, cam_fmt.width, cam_fmt.height
                );
                self.fmt = Some(*cam_fmt);
                return Ok(());
            }
        }
        Ok(())
    }

    fn set_ctl(&self) -> Result<()> {
        Ok(())
    }

    fn video_stream_on(&mut self) -> Result<()> {
        if self.stream_on {
            return Ok(());
        }
        if self.tokenid != 0 {
            bound_tokenid(self.tokenid)?;
        }
        if let Err(code) =
            self.ctx
                .start_stream(on_buffer_available, on_broken, on_status_avail, on_error)
        {
            hisysevent::STRATOVIRT_CAMERA_START_FAILED(code);
            ohcam_set_status(&self.camid, OhCamStatus::StartFailed);
            return Err(anyhow!("Failed to start camera stream, code is {code}."));
        }
        self.stream_on = true;
        if self.cam_state.rotation_required {
            self.cam_state.rotation_enabled = true;
        }
        ohcam_cb_set_owned(&self.camid, true);
        ohcam_set_status(&self.camid, OhCamStatus::Started);
        Ok(())
    }

    fn video_stream_off(&mut self) -> Result<()> {
        if !self.stream_on {
            ohcam_set_status(&self.camid, OhCamStatus::Release);
            return Ok(());
        }
        self.ctx.stop_stream();
        ohcam_cb_set_owned(&self.camid, false);
        if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&self.camid) {
            cb.clear_buffer();
        }
        self.stream_on = false;
        ohcam_set_status(&self.camid, OhCamStatus::Release);
        #[cfg(any(
            feature = "trace_to_logger",
            feature = "trace_to_ftrace",
            all(target_env = "ohos", feature = "trace_to_hitrace")
        ))]
        self.async_scope.stop();
        Ok(())
    }

    fn list_format(&mut self) -> Result<Vec<CameraFormatList>> {
        let mut fmt_list: Vec<CameraFormatList> = Vec::new();

        for idx in 0..self.profile_cnt {
            match self.ctx.get_profile(i32::from(idx)) {
                Ok((fmt, width, height, fps)) => {
                    if !FRAME_FORMAT_WHITELIST.contains(&fmt)
                        || width < MIN_WIDTH
                        || !FPS_WHITELIST.contains(&fps)
                    {
                        continue;
                    }

                    let frame = CameraFrame {
                        width: width as u32,
                        height: height as u32,
                        index: 1,
                        interval: FPS_INTERVAL_TRANS / fps as u32,
                    };
                    fmt_list.push(CameraFormatList {
                        format: cam_fmt_from_oh(fmt)?,
                        frame: vec![frame],
                        fmt_index: idx.checked_add(1).unwrap_or_else(|| {
                            error!("list_format: too much profile ID");
                            u8::MAX
                        }),
                    });
                }
                Err(e) => error!("{:?}", e),
            }
        }

        fmt_list = remove_duplicate_nv21(fmt_list);
        // Just for APP ToDesk, This stupid APP uses the format reported first
        // to realize camera-related functions. It doesn't support NV12, so
        // we put YUY2 forward.
        fmt_list.sort_by(|a, b| a.format.partial_cmp(&b.format).unwrap());
        self.fmt_list = fmt_list.clone();
        Ok(fmt_list)
    }

    fn reset(&mut self) {
        if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&self.camid) {
            cb.clear_buffer();
        }
        if self.stream_on {
            self.video_stream_off().unwrap_or_else(|e| {
                error!("OHCAM: stream off failed: {:?}", e);
            });
        }
        if let Err(e) = self.ctx.reset_camera(self.camid.clone()) {
            error!("OHCAM: reset failed, err: {e}");
        }
        #[cfg(any(
            feature = "trace_to_logger",
            feature = "trace_to_ftrace",
            all(target_env = "ohos", feature = "trace_to_hitrace")
        ))]
        self.async_scope.stop();
    }

    fn get_format_by_index(&self, format_index: u8, frame_index: u8) -> Result<CamBasicFmt> {
        let mut out = CamBasicFmt::default();
        for fmt in &self.fmt_list {
            if fmt.fmt_index != format_index {
                continue;
            }
            out.fmttype = fmt.format;
            for frm in &fmt.frame {
                if frm.index != frame_index {
                    continue;
                }
                out.width = frm.width;
                out.height = frm.height;
                out.fps = FPS_INTERVAL_TRANS
                    .checked_div(frm.interval)
                    .with_context(|| {
                        format!(
                            "{}: Invalid interval {} for format/frame {}:{}",
                            self.id, frm.interval, format_index, frame_index
                        )
                    })?;
                return Ok(out);
            }
        }
        bail!(
            "{}: format/frame with idx {}/{} is not found",
            self.id,
            format_index,
            frame_index
        );
    }

    fn get_frame_size(&self) -> usize {
        if let Some(cb) = OHCAM_CALLBACKS.read().unwrap().get(&self.camid) {
            return cb.get_buffer().1 as usize;
        }
        0
    }

    fn next_frame(&mut self) -> Result<()> {
        #[cfg(any(
            feature = "trace_to_logger",
            feature = "trace_to_ftrace",
            all(target_env = "ohos", feature = "trace_to_hitrace")
        ))]
        self.async_scope.start();
        self.ctx.next_frame();
        if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&self.camid) {
            cb.clear_buffer();
        }
        Ok(())
    }

    fn get_frame(&mut self, iovecs: &[Iovec], frame_offset: usize, len: usize) -> Result<usize> {
        let (src, src_len) = OHCAM_CALLBACKS
            .read()
            .unwrap()
            .get(&self.camid)
            .with_context(|| "Invalid camid in callback table")?
            .get_buffer();

        if src.is_none() || src.unwrap() == 0 {
            bail!("Invalid frame src")
        }

        if src_len == 0_u64 || (src_len - frame_offset as u64) < len as u64 {
            bail!(
                "Invalid frame src_len of {}, frame_offset of {}, packet expects len of {}",
                src_len,
                frame_offset,
                len
            );
        }

        if frame_offset == 0 && self.cam_state.rotation_required && self.cam_state.rotation_enabled
        {
            if let Err(e) = self.rotate_frame(src.unwrap()) {
                error!("ohcam: {:?}", e);
                self.cam_state.rotation_enabled = false;
            }
        }

        trace::trace_scope_start!(ohcam_get_frame, args = (frame_offset, len));

        let mut copied = 0_usize;
        for iov in iovecs {
            if len == copied {
                break;
            }
            let cnt = std::cmp::min(iov.iov_len as usize, len - copied);
            let src_ptr = src.unwrap() + frame_offset as u64 + copied as u64;
            // SAFETY: The safety of this operation is guaranteed by the checks above.
            // - `src_ptr` is valid for reads of `cnt` bytes:
            //    - `src_addr` is a non-null address provided by an external component (`get_buffer`).
            //    - We have explicitly checked that `(src_len - frame_offset) >= len`, ensuring that
            //      any read within the loop, where `copied` goes from `0` to `len`, remains
            //      within the bounds of the source buffer .
            // - `iov.iov_base` is valid for writes of `cnt` bytes:
            //    - The usb packet from xhci provide `iovecs` where each `iov_base` points to a valid,
            //      writable memory buffer of at least `iov_len` bytes.
            // - The source and destination memory regions do not overlap
            unsafe {
                std::ptr::copy_nonoverlapping(src_ptr as *const u8, iov.iov_base as *mut u8, cnt);
            }
            copied += cnt;
        }
        Ok(copied)
    }

    fn register_notify_cb(&mut self, cb: CameraNotifyCallback) {
        OHCAM_CALLBACKS
            .write()
            .unwrap()
            .entry(self.camid.clone())
            .or_insert(OhCamCallBack::new(self.camid.clone()))
            .set_notify_cb(cb);
    }

    fn register_broken_cb(&mut self, cb: CameraBrokenCallback) {
        OHCAM_CALLBACKS
            .write()
            .unwrap()
            .entry(self.camid.clone())
            .or_insert(OhCamCallBack::new(self.camid.clone()))
            .set_broken_cb(cb);
    }

    fn register_avail_cb(&mut self, cb: CameraAvailCallback) {
        OHCAM_CALLBACKS
            .write()
            .unwrap()
            .entry(self.camid.clone())
            .or_insert(OhCamCallBack::new(self.camid.clone()))
            .set_avail_cb(cb);
    }

    fn pause(&mut self, paused: bool) {
        if self.paused == paused {
            return;
        }

        if paused {
            // If stream is off, we don't need to set self.paused.
            // Because it's not required to re-open stream while
            // vm is resuming.
            if !self.stream_on {
                return;
            }
            self.paused = true;
            self.video_stream_off().unwrap_or_else(|e| {
                error!("ohcam pause: failed to pause stream {:?}", e);
            });
        } else {
            self.paused = false;
            if let Err(e) = self.video_stream_on() {
                error!("ohcam resume: failed to resume stream {:?}", e);
                if let Some(false) = ohcam_cb_get_avail(&self.camid) {
                    ohcam_set_status(&self.camid, OhCamStatus::Preempted);
                }
            }
        }
    }
}

impl OhCameraBackend {
    fn rotate_frame(&mut self, src: u64) -> Result<()> {
        if self.fmt.is_none() {
            return Ok(());
        }

        if let (Some(dpy_rotation), Some(cam_orientation)) =
            (get_dpy_rotation(), self.cam_state.cam_orientation)
        {
            self.rotate_frame_by_angle(
                src,
                self.calc_compensated_angle(dpy_rotation, cam_orientation)?,
            )?;
        }

        Ok(())
    }

    // Calculates the net rotation angle required to align camera orientation
    // with display orientation. The logic is based on oh camera mounting:
    // - Front-facing cameras are mirrored relative to display, so subtract.
    // - Back-facing cameras align directly, so add.
    fn calc_compensated_angle(
        &self,
        dpy_rotation: Rotation,
        cam_orientation: Rotation,
    ) -> Result<Rotation> {
        match self.cam_state.cam_position {
            CamPosition::Front => Ok(cam_orientation - dpy_rotation),
            CamPosition::Back => Ok(cam_orientation + dpy_rotation),
            _ => bail!(
                "unsupported camera position: {:?}",
                self.cam_state.cam_position
            ),
        }
    }

    fn rotate_frame_by_angle(&mut self, src: u64, rotation: Rotation) -> Result<()> {
        if rotation == Rotation::Rotation0 {
            return Ok(());
        }

        let fmt = self.fmt.as_ref().unwrap();
        let width = fmt.width as i32;
        let height = fmt.height as i32;

        match fmt.fmttype {
            FmtType::Yuy2 => {
                self.rotate_yuy2(src, width, height, rotation)
                    .with_context(|| format!("Failed to rotate {:?} yuv2 frame", rotation))?;
            }
            FmtType::Nv12 | FmtType::Nv21 => {
                self.rotate_nv(src, width, height, rotation)
                    .with_context(|| format!("Failed to rotate {:?} nv frame", rotation))?;
            }
            FmtType::Mjpg => {
                bail!("rotation for mjpg not supported");
            }
            FmtType::Rgb565 => {
                bail!("rotation for rgb565 not supported");
            }
        }

        Ok(())
    }

    fn check_rotate_frame(&mut self, width: i32, height: i32) -> Result<()> {
        if width % 2 != 0 && height % 2 != 0 {
            bail!("Invalid width {} or height {}", width, height);
        }

        let size = width
            .checked_mul(height)
            .with_context(|| format!("Invalid width {} or height {}", width, height))?;

        let buffer_size = (size as usize)
            .checked_mul(3)
            .with_context(|| format!("Invalid width {} or height {}", width, height))?;

        if self.cam_state.rotation_buffer.len() < buffer_size {
            self.cam_state.rotation_buffer.resize(buffer_size, 0u8);
        }

        Ok(())
    }

    fn rotate_nv(&mut self, src: u64, width: i32, height: i32, rotation: Rotation) -> Result<()> {
        self.check_rotate_frame(width, height)?;

        let half_height = height >> 1;
        let half_width = width >> 1;
        let y_size = (width * height) as u64;
        let u_size = (half_height * half_width) as u64;
        let v_size = u_size;
        let y_plane = self.cam_state.rotation_buffer.as_mut_ptr() as u64;
        let u_plane = y_plane + y_size;
        let v_plane = u_plane + u_size;
        let (i420_stride_y, i420_stride_u, i420_stride_v) = match rotation {
            Rotation::Rotation90 | Rotation::Rotation270 => (height, half_height, half_height),
            _ => (width, half_width, half_width),
        };

        let src_y = src;
        let src_vu = src + y_size;

        // SAFETY: we have checked the buffer size indicated by src which must
        // be correct. The parameters passed to nv12_to_i420_rotate() are carefully
        // calculated above. And the destination buffer has been checked and resized
        // if needed in check_rotate_frame().
        let mut ret = unsafe {
            nv12_to_i420_rotate(
                src_y,
                width,
                src_vu,
                width,
                y_plane,
                i420_stride_y,
                u_plane,
                i420_stride_u,
                v_plane,
                i420_stride_v,
                width,
                height,
                rotation.to_degree(),
            )
        };
        if ret < 0 {
            bail!("Failed to rotate nv to i420: {}", ret);
        }

        if rotation == Rotation::Rotation270 || rotation == Rotation::Rotation90 {
            let scale_src = v_plane + v_size;
            self.scale_i420(width, height, y_plane, u_plane, v_plane, scale_src)?;
        }

        // SAFETY: the reason is same as above.
        ret = unsafe {
            i420_to_nv12(
                y_plane, width, u_plane, half_width, v_plane, half_width, src_y, width, src_vu,
                width, width, height,
            )
        };
        if ret < 0 {
            bail!("Failed to transfer from i420 to nv: {}", ret);
        }

        Ok(())
    }

    fn rotate_yuy2(&mut self, src: u64, width: i32, height: i32, rotation: Rotation) -> Result<()> {
        self.check_rotate_frame(width, height)?;

        let half_height = height >> 1;
        let half_width = width >> 1;
        let y_size = (width * height) as u64;
        let u_size = (half_height * half_width) as u64;
        let v_size = u_size;
        let y_plane = self.cam_state.rotation_buffer.as_mut_ptr() as u64;
        let u_plane = y_plane + y_size;
        let v_plane = u_plane + u_size;

        // SAFETY: we have checked the buffer size indicated by src which must
        // be correct. The parameters passed to yuy2_to_i420() are carefully
        // calculated above. And the destination buffer has been checked and resized
        // if needed in check_rotate_frame().
        let mut ret = unsafe {
            yuy2_to_i420(
                src,
                width << 1,
                y_plane,
                width,
                u_plane,
                half_width,
                v_plane,
                half_width,
                width,
                height,
            )
        };
        if ret < 0 {
            bail!("Failed to transfer from yuy2 to i420: {}", ret);
        }

        let rotated_y_plane = v_plane + v_size;
        let rotated_u_plane = rotated_y_plane + y_size;
        let rotated_v_plane = rotated_u_plane + u_size;

        let (dst_stride_y, dst_stride_u, dst_stride_v) = match rotation {
            Rotation::Rotation90 | Rotation::Rotation270 => (height, half_height, half_height),
            _ => (width, half_width, half_width),
        };

        // SAFETY: the reason is same as above.
        ret = unsafe {
            i420_rotate(
                y_plane,
                width,
                u_plane,
                half_width,
                v_plane,
                half_width,
                rotated_y_plane,
                dst_stride_y,
                rotated_u_plane,
                dst_stride_u,
                rotated_v_plane,
                dst_stride_v,
                width,
                height,
                rotation.to_degree(),
            )
        };
        if ret < 0 {
            bail!("Failed to rotate to i420: {}", ret);
        }

        if rotation == Rotation::Rotation270 || rotation == Rotation::Rotation90 {
            let scale_src = y_plane;
            self.scale_i420(
                width,
                height,
                rotated_y_plane,
                rotated_u_plane,
                rotated_v_plane,
                scale_src,
            )?;
        }

        // SAFETY: the reason is same as above.
        ret = unsafe {
            i420_to_yuy2(
                rotated_y_plane,
                width,
                rotated_u_plane,
                half_width,
                rotated_v_plane,
                half_width,
                src,
                width << 1,
                width,
                height,
            )
        };
        if ret < 0 {
            bail!("Failed to transfer from i420 to yuy2: {}", ret);
        }

        Ok(())
    }

    fn scale_i420(
        &mut self,
        width: i32,
        height: i32,
        y_plane: u64,
        u_plane: u64,
        v_plane: u64,
        scale_src: u64,
    ) -> Result<()> {
        if height > width {
            bail!("Invalid width {} or height {}", width, height);
        }

        let half_height = height >> 1;
        let half_width = width >> 1;

        let scale_height = height;
        let scale_width = height
            .checked_mul(scale_height)
            .with_context(|| format!("Invalid width {} or height {}", width, height))?
            .checked_div(width)
            .with_context(|| format!("Invalid width {} or height {}", width, height))?
            & !1;
        let half_scale_width = scale_width >> 1;
        let half_scale_height = scale_height >> 1;
        let scale_y_plane_size = (scale_height * scale_width) as u64;
        let scale_u_plane_size = (half_scale_width * half_scale_height) as u64;

        let scale_y_plane = scale_src;
        let scale_u_plane = scale_y_plane + scale_y_plane_size;
        let scale_v_plane = scale_u_plane + scale_u_plane_size;

        // Scales a YUV 4:2:0 image from the src width and height to the dst width and height.
        // SAFETY: we have checked and carefully calculated the parameters and all the buffers
        // are valid.
        let mut ret = unsafe {
            i420_scale(
                y_plane,
                height,
                u_plane,
                half_height,
                v_plane,
                half_height,
                height,
                width,
                scale_y_plane,
                scale_width,
                scale_u_plane,
                half_scale_width,
                scale_v_plane,
                half_scale_width,
                scale_width,
                scale_height,
                FilterMode::FilterNone.into(),
            )
        };
        if ret < 0 {
            bail!("Failed to scale i420: {}", ret);
        }

        // Fill in the I420 data in black
        // SAFETY: the reason is same as above.
        ret = unsafe {
            i420_rect(
                y_plane, width, u_plane, half_width, v_plane, half_width, 0, 0, width, height, 0,
                128, 128,
            )
        };
        if ret < 0 {
            bail!("Failed to fill in I420 data in black: {}", ret);
        }

        let offset = ((width - scale_width) >> 1) & !1;
        let half_offset = offset >> 1;
        // Filling the scaled-down I420 image centred in the source I420
        // SAFETY: the buffers are valid and we have checked all parameters
        // related to size.
        ret = unsafe {
            i420_copy(
                scale_y_plane,
                scale_width,
                scale_u_plane,
                half_scale_width,
                scale_v_plane,
                half_scale_width,
                y_plane + (offset as u64),
                width,
                u_plane + (half_offset as u64),
                half_width,
                v_plane + (half_offset as u64),
                half_width,
                scale_width,
                scale_height,
            )
        };
        if ret < 0 {
            bail!("Failed to copy I420 data: {}", ret);
        }

        Ok(())
    }
}

fn remove_duplicate_nv21(mut list: Vec<CameraFormatList>) -> Vec<CameraFormatList> {
    let list_clone = list.clone();
    list.retain_mut(|f| {
        if f.format != FmtType::Nv21 {
            return true;
        }
        f.format = FmtType::Nv12;

        for fmt in &list_clone {
            if fmt.format == FmtType::Nv12 && fmt.frame[0] == f.frame[0] {
                return false;
            }
        }
        true
    });
    list
}

/// SAFETY:
/// The caller must ensure:
/// - `src` is non-null.
/// - `src` points to a valid, null-terminated C string.
/// - The memory referenced by `src` is valid for the duration of this call.
///
/// If these conditions are not met, undefined behavior may occur.
unsafe fn cstr_to_string(src: *const u8) -> Result<String> {
    if src.is_null() {
        bail!("cstr_to_string: src is null");
    }
    // SAFETY: preconditions guaranteed by caller (see function safety contract).
    let src_cstr = unsafe { CStr::from_ptr(src) };
    let target_string = src_cstr
        .to_str()
        .with_context(|| "cstr_to_string: failed to transfer camid")?
        .to_owned();

    Ok(target_string)
}

/// # Safety
///
/// This function is called from the oh camera framework side as a callback.
/// The caller (C side) must guarantee the following preconditions:
///
/// - `camid` is a valid, non-null pointer to a null-terminated C string
///   representing the camera ID, and remains valid for the duration of the call.
/// - `src_buffer` and `length` together describe a valid memory region
///   accessible for the callback’s lifetime.
///
/// The internal `RwLock` ensures thread-safe access to the global
/// `OHCAM_CALLBACKS` registry.
///
/// Violating any of the above may cause undefined behavior.
unsafe extern "C" fn on_buffer_available(src_buffer: u64, length: i32, camid: *const u8) {
    let cam = cstr_to_string(camid).unwrap_or_else(|e| {
        error!("{e}");
        "".to_string()
    });
    if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&cam) {
        cb.set_buffer(src_buffer, length);
        cb.notify();
    }
}

/// # Safety
///
/// This function is called from the oh camera framework side as a callback.
/// The caller (C side) must guarantee the following preconditions:
///
/// - `camid` is a valid, non-null pointer to a null-terminated C string
///   representing the camera ID, and remains valid for the duration of the call.
/// - `src_buffer` and `length` together describe a valid memory region
///   accessible for the callback’s lifetime.
///
/// The internal `RwLock` ensures thread-safe access to the global
/// `OHCAM_CALLBACKS` registry.
///
/// Violating any of the above may cause undefined behavior.
unsafe extern "C" fn on_broken(camid: *const u8) {
    let cam = cstr_to_string(camid).unwrap_or_else(|e| {
        error!("{e}");
        "".to_string()
    });
    hisysevent::STRATOVIRT_CAMERA_ON_BROKEN(cam.clone());
    error!("Camera:{} stream broken", cam);
    if let Some(cb) = OHCAM_CALLBACKS.read().unwrap().get(&cam) {
        cb.broken();
    }
}

/// # Safety
///
/// This function is called from the oh camera framework side as a callback.
/// The caller (C side) must guarantee the following preconditions:
///
/// - `camid` is a valid, non-null pointer to a null-terminated C string
///   representing the camera ID, and remains valid for the duration of the call.
/// - `src_buffer` and `length` together describe a valid memory region
///   accessible for the callback’s lifetime.
///
/// The internal `RwLock` ensures thread-safe access to the global
/// `OHCAM_CALLBACKS` registry.
///
/// Violating any of the above may cause undefined behavior.
unsafe extern "C" fn on_status_avail(avail: bool, camid: *const u8) {
    let cam = cstr_to_string(camid).unwrap_or_else(|e| {
        error!("{e}");
        "".to_string()
    });
    if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&cam) {
        cb.avail(avail);
    }
}

/// # Safety
///
/// This function is called from the oh camera framework side as a callback.
/// The caller (C side) must guarantee the following preconditions:
///
/// - `camid` is a valid, non-null pointer to a null-terminated C string
///   representing the camera ID, and remains valid for the duration of the call.
/// - `src_buffer` and `length` together describe a valid memory region
///   accessible for the callback’s lifetime.
///
/// The internal `RwLock` ensures thread-safe access to the global
/// `OHCAM_CALLBACKS` registry.
///
/// Violating any of the above may cause undefined behavior.
unsafe extern "C" fn on_error(error_type: i32, camid: *const u8) {
    let cam = cstr_to_string(camid).unwrap_or_else(|e| {
        error!("{e}");
        "".to_string()
    });
    if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&cam) {
        cb.on_error(error_type);
    }
}
