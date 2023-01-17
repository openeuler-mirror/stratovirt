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

pub fn is_aligned(offset: u64, align: u32) -> bool {
    offset & (align as u64 - 1) == 0
}

pub fn align_down(offset: u64, align: u32) -> u64 {
    offset - (offset & (align as u64 - 1))
}

pub fn align_up(offset: u64, align: u32) -> u64 {
    if !is_aligned(offset, align) {
        align_down(offset, align) + align as u64
    } else {
        offset
    }
}
