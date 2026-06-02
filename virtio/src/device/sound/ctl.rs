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
use log::{error, info};

use super::{read_request, spec::*};
use crate::Element;
use address_space::{AddressSpace, RegionCache};
use audio::volume::VolumeControl;
use util::byte_code::ByteCode;

pub struct Ctl {
    volume_ctrl: Arc<dyn VolumeControl>,
    range: (u32, u32),
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
        info!(
            "volume(host -> guest): {}, mute: {}",
            self.volume, self.mute
        );
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
                self.volume_ctrl.set_volume(value);
                info!("volume(guest -> host): {}", value);
            }
            VIRTIO_SND_CTL_ROLE_MUTE => {
                self.mute = value == 0;
                self.volume_ctrl.set_mute(self.mute);
                info!("mute(guest -> host): {}", self.mute);
            }
            _ => unreachable!(),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVolumeControl {
        volume: u32,
        mute: bool,
        range: (u32, u32),
    }

    impl MockVolumeControl {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                volume: 75,
                mute: false,
                range: (0, 100),
            })
        }
    }

    impl VolumeControl for MockVolumeControl {
        fn get_volume(&self) -> u32 {
            self.volume
        }

        fn set_volume(&self, _volume: u32) {
            // no-op for mock
        }

        fn get_mute(&self) -> bool {
            self.mute
        }

        fn set_mute(&self, _mute: bool) {
            // no-op for mock
        }

        fn get_volume_range(&self) -> (u32, u32) {
            self.range
        }

        fn register_listener(&self, _listener: Arc<dyn audio::volume::VolumeListener>) -> u64 {
            0
        }

        fn unregister_listener(&self, _id: u64) {
            // no-op for mock
        }
    }

    fn create_dummy_address_space() -> Arc<AddressSpace> {
        use address_space::Region;
        let root = Region::init_container_region(u64::MAX, "test_root");
        AddressSpace::new(root, "test", None).unwrap()
    }

    #[test]
    fn test_ctl_new() {
        let vol_ctrl = MockVolumeControl::new();
        let ctl = Ctl::new(vol_ctrl);
        assert_eq!(ctl.volume, 75);
        assert!(!ctl.mute);
        assert_eq!(ctl.range, (0, 100));
    }

    #[test]
    fn test_update_volume() {
        let vol_ctrl = MockVolumeControl::new();
        let mut ctl = Ctl::new(vol_ctrl);
        ctl.update_volume(50, true);
        assert_eq!(ctl.volume, 50);
        assert!(ctl.mute);
    }

    #[test]
    fn test_get_ctl_id_by_role() {
        let vol_ctrl = MockVolumeControl::new();
        let ctl = Ctl::new(vol_ctrl);
        assert_eq!(ctl.get_ctl_id_by_role(VIRTIO_SND_CTL_ROLE_VOLUME), 0);
        assert_eq!(ctl.get_ctl_id_by_role(VIRTIO_SND_CTL_ROLE_MUTE), 1);
        assert_eq!(ctl.get_ctl_id_by_role(VIRTIO_SND_CTL_ROLE_UNDEFINED), 0);
    }

    #[test]
    fn test_handle_ctl_unsupported() {
        let sys_mem = create_dummy_address_space();
        let vol_ctrl = MockVolumeControl::new();
        let mut ctl = Ctl::new(vol_ctrl);
        let result = ctl.handle_ctl(
            VIRTIO_SND_R_CTL_ENUM_ITEMS,
            &sys_mem,
            &None,
            &Element::default(),
        );
        assert_eq!(result.0, VIRTIO_SND_S_NOT_SUPP);

        let result = ctl.handle_ctl(0xFFFFFFFF, &sys_mem, &None, &Element::default());
        assert_eq!(result.0, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_validate_control_id() {
        let vol_ctrl = MockVolumeControl::new();
        let ctl = Ctl::new(vol_ctrl);
        assert!(ctl.validate_control_id(0).is_ok());
        assert!(ctl.validate_control_id(1).is_ok());
        assert!(ctl.validate_control_id(2).is_err());
        assert!(ctl.validate_control_id(100).is_err());
    }

    #[test]
    fn test_do_ctl_read_volume() {
        let vol_ctrl = MockVolumeControl::new();
        let ctl = Ctl::new(vol_ctrl);
        let result = ctl.do_ctl_read(0).unwrap();
        assert_eq!(u32::from_le(result.integer[0]), 75);
    }

    #[test]
    fn test_do_ctl_read_mute() {
        let vol_ctrl = MockVolumeControl::new();
        let ctl = Ctl::new(vol_ctrl);
        let result = ctl.do_ctl_read(1).unwrap();
        assert_eq!(u32::from_le(result.integer[0]), 1);
    }

    #[test]
    fn test_do_ctl_read_invalid_id() {
        let vol_ctrl = MockVolumeControl::new();
        let ctl = Ctl::new(vol_ctrl);
        assert!(ctl.do_ctl_read(2).is_err());
    }

    #[test]
    fn test_do_ctl_write_volume() {
        let vol_ctrl = MockVolumeControl::new();
        let mut ctl = Ctl::new(vol_ctrl);
        let mut value = CtlValue::default();
        value.integer[0] = 50u32.to_le();
        assert!(ctl.do_ctl_write(0, &value).is_ok());
        assert_eq!(ctl.volume, 50);
    }

    #[test]
    fn test_do_ctl_write_volume_out_of_range() {
        let vol_ctrl = MockVolumeControl::new();
        let mut ctl = Ctl::new(vol_ctrl);
        let mut value = CtlValue::default();
        value.integer[0] = 200u32.to_le();
        assert!(ctl.do_ctl_write(0, &value).is_err());
    }

    #[test]
    fn test_do_ctl_write_mute_true() {
        let vol_ctrl = MockVolumeControl::new();
        let mut ctl = Ctl::new(vol_ctrl);
        let mut value = CtlValue::default();
        value.integer[0] = 0u32.to_le();
        assert!(ctl.do_ctl_write(1, &value).is_ok());
        assert!(ctl.mute);
    }

    #[test]
    fn test_do_ctl_write_mute_false() {
        let vol_ctrl = MockVolumeControl::new();
        let mut ctl = Ctl::new(vol_ctrl);
        ctl.mute = true;
        let mut value = CtlValue::default();
        value.integer[0] = 1u32.to_le();
        assert!(ctl.do_ctl_write(1, &value).is_ok());
        assert!(!ctl.mute);
    }
}
