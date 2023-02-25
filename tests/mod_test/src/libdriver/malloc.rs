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

use util::num_ops::round_up;

#[derive(Clone, Copy)]
struct MemBlock {
    start: u64,
    size: u64,
}

impl MemBlock {
    fn new(start: u64, size: u64) -> Self {
        MemBlock { start, size }
    }

    pub fn reduce(&mut self, size: u64) {
        assert!(self.size > size);
        self.start += size;
        self.size -= size;
    }
}

pub struct GuestAllocator {
    start: u64,
    end: u64,
    page_size: u64,
    free: Vec<MemBlock>,
    used: Vec<MemBlock>,
}

impl GuestAllocator {
    pub fn new(start: u64, size: u64, page_size: u64) -> Self {
        Self {
            start,
            end: start + size,
            page_size,
            free: vec![MemBlock::new(start, size)],
            used: Vec::new(),
        }
    }

    fn add_free_block(&mut self, new_mb: MemBlock) {
        let mut target = self.free.len();
        for (i, mb) in self.free.iter().enumerate() {
            if mb.size >= new_mb.size {
                target = i;
                break;
            }
        }
        self.free.insert(target, new_mb);
    }

    fn add_used_block(&mut self, new_mb: MemBlock) {
        let mut target = self.used.len();
        for (i, mb) in self.used.iter().enumerate() {
            if mb.start >= new_mb.start {
                target = i;
                break;
            }
        }
        self.used.insert(target, new_mb);
    }

    fn alloc_free_block(&mut self, index: usize, size: u64) {
        let start = self.free[index].start;
        let used_mb = MemBlock::new(start, size);
        self.add_used_block(used_mb);
        if self.free[index].size == size {
            self.free.remove(index);
        } else {
            self.free[index].reduce(size);
        }
    }

    fn free_used_block(&mut self, index: usize) {
        let free_mb = self.used[index];
        self.add_free_block(free_mb);
        self.used.remove(index);
    }

    pub fn alloc(&mut self, size: u64) -> u64 {
        let alloc_size = round_up(size, self.page_size).unwrap();

        let mut addr: Option<u64> = None;
        let mut index: Option<usize> = None;
        for (i, mb) in self.free.iter().enumerate() {
            if mb.size >= alloc_size {
                addr = Some(mb.start);
                index = Some(i);
                break;
            }
        }

        self.alloc_free_block(index.unwrap(), alloc_size);
        addr.unwrap()
    }

    pub fn free(&mut self, addr: u64) {
        assert!(self.start <= addr && addr < self.end);
        let mut index: Option<usize> = None;
        for (i, mb) in self.used.iter().enumerate() {
            if mb.start >= addr {
                index = Some(i);
                break;
            }
        }

        if let Some(i) = index {
            self.free_used_block(i);
        }
    }
}

#[cfg(test)]
mod test {
    use super::GuestAllocator;

    const PAGE_SIZE_4K: u64 = 1 << 12;
    const ADDRESS_BASE: u64 = 0x4000_0000;
    const ADDRESS_SIZE: u64 = 0x2000_0000;

    #[test]
    fn test_guest_allocator() {
        let mut guest_allocator = GuestAllocator::new(ADDRESS_BASE, ADDRESS_SIZE, PAGE_SIZE_4K);

        let mut expect_addr = ADDRESS_BASE;
        let mut addr = guest_allocator.alloc(4096 + 1);
        assert_eq!(addr, expect_addr);
        guest_allocator.free(addr);

        addr = guest_allocator.alloc(4096 * 10);
        expect_addr += 4096 * 2;
        assert_eq!(addr, expect_addr);
        guest_allocator.free(addr);

        addr = guest_allocator.alloc(4096);
        expect_addr = ADDRESS_BASE;
        assert_eq!(addr, expect_addr);
    }
}
