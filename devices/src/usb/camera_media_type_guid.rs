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

//! Media Type GUID. referred with uvc.h in linux kernel.

use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::camera_backend::FmtType;

pub const MEDIA_TYPE_GUID: [(FmtType, [u8; 16]); 3] = [
    (
        FmtType::Yuy2,
        [
            b'Y', b'U', b'Y', b'2', 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38,
            0x9b, 0x71,
        ],
    ),
    (
        FmtType::Rgb565,
        [
            b'R', b'G', b'B', b'P', 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38,
            0x9b, 0x71,
        ],
    ),
    (
        FmtType::Nv12,
        [
            b'N', b'V', b'1', b'2', 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38,
            0x9b, 0x71,
        ],
    ),
];

pub static MEDIA_TYPE_GUID_HASHMAP: Lazy<HashMap<FmtType, [u8; 16]>> =
    Lazy::new(gen_mediatype_hashmap);

fn gen_mediatype_hashmap() -> HashMap<FmtType, [u8; 16]> {
    HashMap::from(MEDIA_TYPE_GUID)
}
