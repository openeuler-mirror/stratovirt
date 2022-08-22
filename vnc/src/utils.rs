// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::cmp;

/// Simple bufferpool can improve read performance of tcpstream.
pub struct BuffPool {
    /// Cache received data.
    buf: Vec<u8>,
    /// Start Byte.
    pos: usize,
    /// Number of bytes in buff.
    cap: usize,
}

impl Default for BuffPool {
    fn default() -> Self {
        Self::new()
    }
}

/// The buffpool to improve read performance.
impl BuffPool {
    pub fn new() -> Self {
        BuffPool {
            buf: Vec::new(),
            pos: 0,
            cap: 0,
        }
    }

    /// Read from the buff.
    pub fn read(&mut self, buf: &mut Vec<u8>) {
        self.buf.drain(..self.pos);
        self.buf.append(buf);
        self.pos = 0;
        self.cap = self.buf.len();
    }

    /// Return the len of the buffpool.
    pub fn len(&mut self) -> usize {
        self.cap
    }

    /// Is empty.
    pub fn is_empty(&mut self) -> bool {
        self.cap != 0
    }

    /// Read from front.
    pub fn read_front(&mut self, len: usize) -> &[u8] {
        let length = cmp::min(self.cap, len);
        &self.buf[self.pos..self.pos + length]
    }

    /// Remove front.
    pub fn remov_front(&mut self, len: usize) {
        self.pos = cmp::min(self.pos + len, self.buf.len());
        self.cap = cmp::max(0_usize, self.cap - len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buff_pool() {
        let mut buffpool = BuffPool::new();
        buffpool.read(&mut (0x12345678 as u32).to_be_bytes().to_vec());
        assert!(buffpool.len() == 4 as usize);
        buffpool.remov_front(1);
        assert!(buffpool.read_front(3) == vec![52, 86, 120]);
    }
}
