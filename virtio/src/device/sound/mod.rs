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

mod dev;
mod io;
mod spec;

pub use dev::Sound;

use std::mem::size_of;
use std::sync::Arc;

use anyhow::{bail, Result};
use clap::{ArgAction, Parser};

use crate::Element;
use address_space::{AddressSpace, RegionCache};
use audio::AudioBackend;
use io::{CtrlIoHandler, IoHandler, RxIoHandler, Stream, TxIoHandler, VirtioSndVolume};
use machine_manager::{
    config::valid_id,
    config::{get_pci_df, parse_bool},
};
use spec::*;
use util::byte_code::ByteCode;

const SUPPORTED_FORMATS: u32 =
    1 << VIRTIO_SND_PCM_FMT_S16 | 1 << VIRTIO_SND_PCM_FMT_S24 | 1 << VIRTIO_SND_PCM_FMT_S32;
const SUPPORTED_RATES: u32 = 1 << VIRTIO_SND_PCM_RATE_44100 | 1 << VIRTIO_SND_PCM_RATE_48000;
const SUPPORTED_MAX_CHANNELS: u8 = 2;

#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct SoundConfig {
    #[arg(long)]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser = parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    #[arg(long)]
    pub iothread: Option<String>,
    #[arg(long)]
    backendtype: AudioBackend,
    #[arg(long, default_value = "on", action = ArgAction::Append, value_parser = parse_bool)]
    pub record_auth: bool,
}

fn read_request<T: ByteCode>(
    sys_mem: &Arc<AddressSpace>,
    cache: &Option<RegionCache>,
    elem: &Element,
) -> Result<T> {
    let mut req = T::default();

    let len = elem.iov_to_buf_with_offset(sys_mem, cache, 0, req.as_mut_bytes())?;
    if len != size_of::<T>() {
        bail!("invalid request size {}, expect {}", len, size_of::<T>());
    }

    Ok(req)
}
