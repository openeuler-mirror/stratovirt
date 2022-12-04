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

use std::collections::LinkedList;
use std::io::Read;

/// Linked the bytes buffer by linklist, to avoid the
/// extra copies when appending a new bytes buffer.
pub struct BuffPool {
    /// Cache received data.
    buf_list: LinkedList<Vec<u8>>,
    /// Limit size of the buffpool.
    limit: Option<usize>,
    /// Total length of Buffer.
    len: usize,
}

impl Default for BuffPool {
    fn default() -> Self {
        Self::new()
    }
}

impl BuffPool {
    pub fn new() -> Self {
        Self {
            buf_list: LinkedList::new(),
            limit: None,
            len: 0,
        }
    }

    /// Update the length of bufflist.
    fn update_len(&mut self) {
        let mut len: usize = 0;
        for bytes in &self.buf_list {
            len += bytes.len();
        }
        self.len = len;
    }

    /// Return the len of the pool.
    pub fn len(&self) -> usize {
        self.len
    }

    /// If it is empty.
    pub fn is_empty(&self) -> bool {
        self.buf_list.is_empty()
    }

    /// For a given length of buffer data, whether there is
    /// enough space left to store.
    pub fn is_enough(&self, require: usize) -> bool {
        if let Some(limit) = self.limit {
            if self.len() + require > limit {
                return false;
            }
        }
        true
    }

    /// Set the limitation for bufferpool.
    ///
    /// # Example
    /// ```rust
    /// use vnc::utils::BuffPool;
    ///
    /// let mut buffpool = BuffPool::new();
    /// buffpool.set_limit(Some(1));
    /// assert!(!buffpool.is_enough(2));
    /// ```
    pub fn set_limit(&mut self, limit: Option<usize>) {
        self.limit = limit;
    }

    /// Add data to the bufferpool. If the remaining
    /// free space is not enough, it will not work. So it is
    /// recommended to call is_enouth() before this function.
    ///
    /// # Example
    /// ```rust
    /// use vnc::utils::BuffPool;
    ///
    /// let mut buffpool = BuffPool::new();
    /// buffpool.append_limit((0_u8).to_be_bytes().to_vec());
    /// ```
    pub fn append_limit(&mut self, buf: Vec<u8>) {
        let len = buf.len();
        if len == 0 {
            return;
        }
        if self.is_enough(len) {
            self.buf_list.push_back(buf);
        }
        self.update_len();
    }

    /// Read the first n bytes.
    ///
    /// # Example
    /// ```rust
    /// use vnc::utils::BuffPool;
    ///
    /// let mut buffpool = BuffPool::new();
    /// buffpool.append_limit((0x12345678 as u32).to_be_bytes().to_vec());
    /// let mut buf: Vec<u8> = vec![0_u8; 4];
    /// buffpool.read_front(&mut buf, 4);
    /// assert_eq!(buf, vec![18, 52, 86, 120]);
    /// ```
    pub fn read_front(&mut self, buf: &mut [u8], len: usize) -> usize {
        if buf.len() < len {
            return 0_usize;
        }

        let mut offset: usize = 0;
        for bytes in &self.buf_list {
            if let Ok(n) = bytes.as_slice().read(&mut buf[offset..]) {
                offset += n;
            } else {
                return 0_usize;
            }
            if offset >= len {
                break;
            }
        }
        offset
    }

    /// Remove the first n bytes.
    ///
    /// # Example
    /// ```rust
    /// use vnc::utils::BuffPool;
    ///
    /// let mut buffpool = BuffPool::new();
    /// buffpool.append_limit((0x12345678 as u32).to_be_bytes().to_vec());
    /// buffpool.remove_front(1);
    /// let mut buf: Vec<u8> = vec![0_u8; 3];
    /// buffpool.read_front(&mut buf, 3);
    /// assert_eq!(buf, vec![52, 86, 120]);
    /// ```
    pub fn remove_front(&mut self, mut len: usize) {
        while let Some(mut bytes) = self.buf_list.pop_front() {
            if len < bytes.len() {
                self.buf_list.push_front(bytes.split_off(len));
                break;
            } else {
                len -= bytes.len();
            }
        }
        self.update_len();
    }

    /// Read first chunk of vec in linklist.
    pub fn read_front_chunk(&mut self) -> Option<&Vec<u8>> {
        self.buf_list.front()
    }

    /// Remove first front chunk of vec in linklist.
    pub fn remove_front_chunk(&mut self) {
        if !self.is_empty() {
            self.buf_list.pop_front();
        }
        self.update_len();
    }
}
#[cfg(test)]
mod tests {
    use crate::utils::BuffPool;

    #[test]
    fn test_buffpool_base() {
        let mut buffpool = BuffPool::new();
        buffpool.set_limit(Some(7));
        buffpool.append_limit((0x12345678 as u32).to_be_bytes().to_vec());
        buffpool.append_limit((0x12 as u8).to_be_bytes().to_vec());
        buffpool.append_limit((0x1234 as u16).to_be_bytes().to_vec());
        assert!(buffpool.len() == 7 as usize);
        buffpool.remove_front(1);
        assert!(buffpool.len() == 6 as usize);
        let mut buf: Vec<u8> = vec![0_u8; 4];
        buffpool.read_front(&mut buf, 4);
        assert!(buf == vec![52, 86, 120, 18]);

        let ans: Vec<Vec<u8>> = vec![vec![52, 86, 120], vec![18], vec![18, 52]];
        let mut idx: usize = 0;
        while let Some(buf) = buffpool.read_front_chunk() {
            assert_eq!(ans[idx], buf.to_vec());
            idx += 1;
            buffpool.remove_front_chunk();
        }
    }
}
