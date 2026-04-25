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

use std::sync::Arc;

use anyhow::{bail, Result};
use log::error;

use super::{read_request, spec::*};
use crate::Element;
use address_space::{AddressSpace, RegionCache};
use audio::volume::VolumeControl;
use util::byte_code::ByteCode;

pub struct Ctl {
    volume_ctrl: Arc<dyn VolumeControl>,
    pub range: (u32, u32),
    pub volume: u32,
    pub mute: bool,
}

impl Ctl {
    const SUPPORTED_CTLS: [u32; VIRTIO_SND_CTL_DEFAULT as usize] =
        [VIRTIO_SND_CTL_ROLE_VOLUME, VIRTIO_SND_CTL_ROLE_MUTE];

    pub fn new(volume_ctrl: Arc<dyn VolumeControl>) -> Self {
        Self {
            range: volume_ctrl.get_volume_range(),
            volume: volume_ctrl.get_volume(),
            mute: volume_ctrl.get_mute(),
            volume_ctrl,
        }
    }

    pub fn update_volume(&mut self, new_vol: u32, new_mute: bool) {
        self.volume = new_vol;
        self.mute = new_mute;
    }

    pub fn get_ctl_id_by_role(&self, role: u32) -> usize {
        Self::SUPPORTED_CTLS
            .iter()
            .position(|r| *r == role)
            .unwrap_or(0)
    }

    pub fn handle_ctl(
        &mut self,
        code: u32,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        match code {
            VIRTIO_SND_R_CTL_INFO => self.handle_ctl_info(sys_mem, cache, elem),
            VIRTIO_SND_R_CTL_READ => self.handle_ctl_read(sys_mem, cache, elem),
            VIRTIO_SND_R_CTL_WRITE => self.handle_ctl_write(sys_mem, cache, elem),
            VIRTIO_SND_R_CTL_ENUM_ITEMS
            | VIRTIO_SND_R_CTL_TLV_READ
            | VIRTIO_SND_R_CTL_TLV_WRITE
            | VIRTIO_SND_R_CTL_TLV_COMMAND => (VIRTIO_SND_S_NOT_SUPP, 0),
            _ => (VIRTIO_SND_S_BAD_MSG, 0),
        }
    }

    fn handle_ctl_info(
        &self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: QueryInfo = match read_request(sys_mem, cache, elem) {
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

        if len > size_of::<CtlInfo>() * VIRTIO_SND_CTL_DEFAULT as usize
            || !len.is_multiple_of(size_of::<CtlInfo>())
        {
            error!("invalid ctl query info: {:?}", req);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        let mut buf = vec![0u8; len];
        for i in start_id..(start_id + count) {
            let info = match self.do_ctl_info(i) {
                Ok(info) => info,
                Err(e) => {
                    error!("CTL_INFO failed: {:?}", e);
                    return (VIRTIO_SND_S_BAD_MSG, 0);
                }
            };

            let info_bytes = info.to_le_bytes();
            if info_bytes.len() > size as usize {
                error!(
                    "CTL_INFO failed: insufficient memory, expect {} actual {}",
                    info_bytes.len(),
                    size
                );
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }

            let l = (i * size) as usize;
            let r = l + info_bytes.len();
            buf[l..r].copy_from_slice(&info_bytes);
        }

        match elem.iov_from_buf_with_offset(sys_mem, cache, size_of::<SndHdr>() as u64, &buf[..]) {
            Ok(len) => {
                if len != buf.len() {
                    return (VIRTIO_SND_S_IO_ERR, 0);
                }
                (VIRTIO_SND_S_OK, size * count)
            }
            Err(e) => {
                error!("{:?}", e);
                (VIRTIO_SND_S_IO_ERR, 0)
            }
        }
    }

    fn handle_ctl_read(
        &self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        let req: CtlHdr = match read_request(sys_mem, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let value = match self.do_ctl_read(u32::from_le(req.control_id)) {
            Ok(value) => value,
            Err(e) => {
                error!("CTL_READ failed: {:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let value_bytes = value.as_bytes();
        if let Err(e) =
            elem.iov_from_buf_with_offset(sys_mem, cache, size_of::<SndHdr>() as u64, value_bytes)
        {
            error!("{:?}", e);
            return (VIRTIO_SND_S_IO_ERR, value_bytes.len() as u32);
        }

        (VIRTIO_SND_S_OK, value_bytes.len() as u32)
    }

    fn handle_ctl_write(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        cache: &Option<RegionCache>,
        elem: &Element,
    ) -> (u32, u32) {
        // Read CtlHdr + CtlValue from the element
        let req: CtlHdr = match read_request(sys_mem, cache, elem) {
            Ok(req) => req,
            Err(e) => {
                error!("{:?}", e);
                return (VIRTIO_SND_S_BAD_MSG, 0);
            }
        };

        let control_id = u32::from_le(req.control_id);

        // Read the CtlValue payload after the CtlHdr
        let mut value = CtlValue::default();
        let Ok(len) = elem.iov_to_buf_with_offset(
            sys_mem,
            cache,
            size_of::<CtlHdr>() as u64,
            value.as_mut_bytes(),
        ) else {
            error!("CTL_WRITE: failed to read value from virtqueue");
            return (VIRTIO_SND_S_IO_ERR, 0);
        };

        if len != size_of::<CtlValue>() {
            error!(
                "CTL_WRITE: invalid value size {}, expect {}",
                len,
                size_of::<CtlValue>()
            );
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        if let Err(e) = self.do_ctl_write(control_id, &value) {
            error!("CTL_WRITE failed: {:?}", e);
            return (VIRTIO_SND_S_BAD_MSG, 0);
        }

        (VIRTIO_SND_S_OK, 0)
    }

    fn validate_control_id(&self, control_id: u32) -> Result<()> {
        if control_id >= VIRTIO_SND_CTL_DEFAULT {
            bail!("invalid control id {}", control_id);
        }
        Ok(())
    }

    fn do_ctl_info(&self, control_id: u32) -> Result<CtlInfo> {
        self.validate_control_id(control_id)?;

        match Self::SUPPORTED_CTLS[control_id as usize] {
            VIRTIO_SND_CTL_ROLE_VOLUME => {
                let mut name = [0u8; VIRTIO_SND_CTL_INFO_NAME_LEN];
                let vol_name = b"Master Playback Volume";
                name[..vol_name.len()].copy_from_slice(vol_name);

                let (min, max) = self.volume_ctrl.get_volume_range();

                Ok(CtlInfo {
                    hdr: SoundInfo { hda_fn_nid: 0 },
                    role: VIRTIO_SND_CTL_ROLE_VOLUME,
                    ctl_type: VIRTIO_SND_CTL_TYPE_INTEGER,
                    access: (1 << VIRTIO_SND_CTL_ACCESS_READ) | (1 << VIRTIO_SND_CTL_ACCESS_WRITE),
                    count: 1,
                    index: 0,
                    name,
                    value: CtlInfoValue {
                        integer: CtlIntegerRange { min, max, step: 1 },
                    },
                })
            }
            VIRTIO_SND_CTL_ROLE_MUTE => {
                let mut name = [0u8; VIRTIO_SND_CTL_INFO_NAME_LEN];
                let mute_name = b"Master Playback Switch";
                name[..mute_name.len()].copy_from_slice(mute_name);

                Ok(CtlInfo {
                    hdr: SoundInfo { hda_fn_nid: 0 },
                    role: VIRTIO_SND_CTL_ROLE_MUTE,
                    ctl_type: VIRTIO_SND_CTL_TYPE_BOOLEAN,
                    access: (1 << VIRTIO_SND_CTL_ACCESS_READ) | (1 << VIRTIO_SND_CTL_ACCESS_WRITE),
                    count: 1,
                    index: 0,
                    name,
                    value: CtlInfoValue {
                        integer: CtlIntegerRange {
                            min: 0,
                            max: 1,
                            step: 1,
                        },
                    },
                })
            }
            _ => unreachable!(),
        }
    }

    fn do_ctl_read(&self, control_id: u32) -> Result<CtlValue> {
        self.validate_control_id(control_id)?;

        let mut result = CtlValue::default();
        result.integer[0] = match Self::SUPPORTED_CTLS[control_id as usize] {
            VIRTIO_SND_CTL_ROLE_VOLUME => self.volume,
            VIRTIO_SND_CTL_ROLE_MUTE => u32::from(!self.mute),
            _ => unreachable!(),
        };

        Ok(result)
    }

    fn do_ctl_write(&mut self, control_id: u32, value: &CtlValue) -> Result<()> {
        self.validate_control_id(control_id)?;

        let value = u32::from_le(value.integer[0]);

        match Self::SUPPORTED_CTLS[control_id as usize] {
            VIRTIO_SND_CTL_ROLE_VOLUME => {
                if value < self.range.0 || value > self.range.1 {
                    bail!("volume value {} is out of range {:?}", value, self.range);
                }

                self.volume = value;
                if !self.mute {
                    self.volume_ctrl.set_volume(value);
                }
            }
            VIRTIO_SND_CTL_ROLE_MUTE => {
                self.mute = value == 0;
                self.volume_ctrl.set_mute(self.mute);
            }
            _ => unreachable!(),
        }

        Ok(())
    }
}
