// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

use super::byte_code::ByteCode;

pub fn checksum(slice: &[u8]) -> u8 {
    let mut sum: u32 = 0;

    for byte in slice.iter() {
        sum += u32::from(*byte);
        sum &= 0xff;
    }

    (sum & 0xff) as u8
}

pub fn obj_checksum<T: ByteCode>(t: &T) -> u8 {
    let mut sum: u32 = 0;

    for byte in t.as_bytes().iter() {
        sum += u32::from(*byte);
        sum &= 0xff;
    }

    (sum & 0xff) as u8
}
