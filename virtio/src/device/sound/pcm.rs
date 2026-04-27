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

use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use log::{error, info, warn};

use super::{
    dev::VirtQ, read_request, spec::*, Stream, SUPPORTED_FORMATS, SUPPORTED_MAX_CHANNELS,
    SUPPORTED_RATES,
};
use crate::Element;
use address_space::{AddressSpace, RegionCache};
use audio::{
    create_audio_interface, get_record_authority, AudioBackend, AudioStreamDirection,
    AudioStreamParams, PcmFmt, PcmRate,
};

pub struct Pcm {
    streams: Vec<Stream>,
    token_id: Option<Arc<RwLock<u64>>>,
    backend_type: AudioBackend,
}

impl Pcm {
    pub fn new(
        streams: u32,
        token_id: Option<Arc<RwLock<u64>>>,
        backend_type: AudioBackend,
    ) -> Self {
        Self {
            streams: Vec::with_capacity(streams as usize),
            token_id,
            backend_type,
        }
    }

    pub fn init_stream(&mut self, streams: u32, tx_virtq: VirtQ, rx_virtq: VirtQ) {
        for i in 0..streams {
            if i % 2 == 0 {
                self.streams
                    .push(Stream::new(VIRTIO_SND_D_OUTPUT, tx_virtq.clone()));
            } else {
                self.streams
                    .push(Stream::new(VIRTIO_SND_D_INPUT, rx_virtq.clone()));
            };
        }
    }

    pub fn push_elem_to_stream(&self, id: usize, elem: Element) -> Option<Element> {
        if id >= self.streams.len() {
            // Return back element to the caller to notify guest error.
            return Some(elem);
        }

        self.streams[id].io_handler.append(elem);
        None
    }

    pub fn handle_pcm(
        &mut self,
        code: u32,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        match code {
            VIRTIO_SND_R_PCM_INFO => self.handle_pcm_info(sys_mem, cache, elem),
            VIRTIO_SND_R_PCM_SET_PARAMS => self.handle_pcm_set_params(sys_mem, cache, elem),
            VIRTIO_SND_R_PCM_PREPARE => self.handle_pcm_prepare(sys_mem, cache, elem),
            VIRTIO_SND_R_PCM_RELEASE => self.handle_pcm_release(sys_mem, cache, elem),
            VIRTIO_SND_R_PCM_START => self.handle_pcm_start(sys_mem, cache, elem),
            VIRTIO_SND_R_PCM_STOP => self.handle_pcm_stop(sys_mem, cache, elem),
            _ => (VIRTIO_SND_S_BAD_MSG, 0),
        }
    }

    fn handle_pcm_info(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: QueryInfo = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let start_id = u32::from_le(req.start_id);
        let count = u32::from_le(req.count);
        let size = u32::from_le(req.size);
        let len = count.saturating_mul(size) as usize;

        if len > size_of::<PcmInfo>() * VIRTIO_SND_STREAM_DEFAULT as usize
            || !len.is_multiple_of(size_of::<PcmInfo>())
        {
            error!("invalid pcm query info: {:?}", req);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        if start_id >= VIRTIO_SND_STREAM_DEFAULT || (start_id + count) > VIRTIO_SND_STREAM_DEFAULT {
            error!("invalid pcm query info: {:?}", req);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let mut info_bytes = Vec::with_capacity(len);
        for stream in self
            .streams
            .iter()
            .skip(start_id as usize)
            .take(count as usize)
        {
            info_bytes.extend_from_slice(&stream.info.to_le_bytes());
        }

        if let Err(e) = elem.iov_from_buf_with_offset(
            mem_space,
            cache,
            size_of::<SndHdr>() as u64,
            &info_bytes[..],
        ) {
            error!("{:?}", e);
            return (VIRTIO_SND_S_IO_ERR, 0);
        }

        (VIRTIO_SND_S_OK, info_bytes.len() as u32)
    }

    fn handle_pcm_set_params(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmSetParams = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        if (SUPPORTED_RATES & (1 << req.rate)) == 0 {
            return (VIRTIO_SND_S_NOT_SUPP, 0);
        }

        if (SUPPORTED_FORMATS & (1 << req.format)) == 0 {
            return (VIRTIO_SND_S_NOT_SUPP, 0);
        }

        if req.channels < 1 || req.channels > SUPPORTED_MAX_CHANNELS {
            return (VIRTIO_SND_S_NOT_SUPP, 0);
        }

        let stream_id = u32::from_le(req.hdr.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        self.set_params(stream_id, &req);

        (VIRTIO_SND_S_OK, 0)
    }

    fn set_params(&mut self, stream_id: u32, other: &PcmSetParams) {
        let id = stream_id as usize;

        assert!(id < self.streams.len());
        self.streams[id].params = PcmSetParams::from_le(other);
        self.streams[id]
            .io_handler
            .set_period_bytes(u32::from_le(other.period_bytes) as usize);
    }

    fn get_stream_mut(&mut self, stream_id: u32) -> &mut Stream {
        &mut self.streams[stream_id as usize]
    }

    fn check_record_auth(stream: &Stream) -> bool {
        if stream.info.direction == VIRTIO_SND_D_OUTPUT {
            return true;
        }
        get_record_authority()
    }

    fn handle_pcm_prepare(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmHdr = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let stream_id = u32::from_le(req.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let backend_type = self.backend_type.clone();
        let token_id = self.token_id.clone();
        let stream = self.get_stream_mut(stream_id);

        let io_handler = stream.io_handler.clone();
        let mut interface = stream.interface.lock().unwrap();
        if interface.is_some() {
            warn!("audio interface already created");
            return (VIRTIO_SND_S_OK, 0);
        }

        let Ok(params) = convert_params(
            &stream.params,
            stream.info.direction,
            stream.params.period_bytes,
        ) else {
            return (VIRTIO_SND_S_IO_ERR, 0);
        };

        let result = create_audio_interface(backend_type, params, io_handler, token_id);

        match result {
            Ok(audio) => {
                *interface = Some(audio);
                (VIRTIO_SND_S_OK, 0)
            }
            Err(e) => {
                error!("Failed to create audio backend: {}", e);
                (VIRTIO_SND_S_IO_ERR, 0)
            }
        }
    }

    fn handle_pcm_start(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmHdr = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let stream_id = u32::from_le(req.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let stream = self.get_stream_mut(stream_id);
        if !Self::check_record_auth(stream) {
            return (VIRTIO_SND_S_IO_ERR, 0);
        }

        stream.register_vm_pause_notifier();

        let mut interface = stream.interface.lock().unwrap();
        if let Some(i) = interface.as_mut() {
            if let Err(e) = i.start() {
                error!("Failed to start stream, {:?}", e);
                return (VIRTIO_SND_S_IO_ERR, 0);
            }
        }

        info!("stream started: {:?}.", stream.params);

        (VIRTIO_SND_S_OK, 0)
    }

    fn handle_pcm_stop(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmHdr = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let stream_id = u32::from_le(req.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let stream = self.get_stream_mut(stream_id);
        stream.unregister_vm_pause_notifier();

        let mut interface = stream.interface.lock().unwrap();
        if let Some(audio) = interface.as_mut() {
            if let Err(e) = audio.stop() {
                error!("Failed to stop stream, {:?}", e);
                return (VIRTIO_SND_S_IO_ERR, 0);
            }
        }

        info!("stream stopped: {:?}", stream.params);

        (VIRTIO_SND_S_OK, 0)
    }

    fn handle_pcm_release(
        &mut self,
        mem_space: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: PcmHdr = match read_request(mem_space, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let stream_id = u32::from_le(req.stream_id);
        if stream_id as usize >= self.streams.len() {
            error!("invalid stream_id {}", stream_id);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let stream = self.get_stream_mut(stream_id);
        if let Err(e) = stream.flush() {
            error!("Failed to flush stream {}, {:?}", stream_id, e);
        }
        if let Some(mut interface) = stream.interface.lock().unwrap().take() {
            if let Err(e) = interface.stop() {
                error!("Failed to stop interface, {:?}", e);
            }
        }
        (VIRTIO_SND_S_OK, 0)
    }
}

fn convert_params(
    params: &PcmSetParams,
    direction: u8,
    period_bytes: u32,
) -> Result<AudioStreamParams> {
    let rate = match params.rate {
        VIRTIO_SND_PCM_RATE_44100 => PcmRate::Rate44100,
        VIRTIO_SND_PCM_RATE_48000 => PcmRate::Rate48000,
        _ => bail!("unsupported pcm rate"),
    };

    let format = match params.format {
        VIRTIO_SND_PCM_FMT_S16 => PcmFmt::FmtS16,
        VIRTIO_SND_PCM_FMT_S24 => PcmFmt::FmtS24,
        VIRTIO_SND_PCM_FMT_S32 => PcmFmt::FmtS32,
        _ => bail!("unsupported pcm format"),
    };

    let direction = match direction {
        VIRTIO_SND_D_OUTPUT => AudioStreamDirection::Playback,
        VIRTIO_SND_D_INPUT => AudioStreamDirection::Record,
        _ => bail!("unsupported direction"),
    };

    Ok(AudioStreamParams {
        rate,
        format,
        channels: SUPPORTED_MAX_CHANNELS,
        direction,
        period_bytes,
    })
}
