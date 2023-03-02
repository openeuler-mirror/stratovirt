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

use super::malloc::GuestAllocator;
use crate::libtest::TestState;
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem::size_of;
use std::rc::Rc;
use std::time;
use util::byte_code::ByteCode;
use util::num_ops::round_up;
use util::offset_of;

pub const VIRTIO_F_BAD_FEATURE: u64 = 0x40000000;
pub const VIRTIO_F_VERSION_1: u64 = 32;
pub const VIRTIO_CONFIG_S_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_CONFIG_S_DRIVER: u8 = 2;
pub const VIRTIO_CONFIG_S_DRIVER_OK: u8 = 4;
pub const VIRTIO_CONFIG_S_FEATURES_OK: u8 = 8;
pub const VIRTIO_CONFIG_S_NEEDS_RESET: u8 = 0x40;
pub const VIRTIO_CONFIG_S_FAILED: u8 = 0x80;
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;
pub const VRING_USED_F_NO_NOTIFY: u16 = 1;
pub const VIRTIO_PCI_VRING_ALIGN: u32 = 4096;
pub const VIRTIO_F_NOTIFY_ON_EMPTY: u64 = 24;
pub const VIRTIO_RING_F_INDIRECT_DESC: u64 = 28;
pub const VIRTIO_RING_F_EVENT_IDX: u64 = 29;
/// When host consumes a buffer, don't interrupt the guest.
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;

pub trait VirtioDeviceOps {
    fn config_readb(&self, addr: u64) -> u8;
    fn config_readw(&self, addr: u64) -> u16;
    fn config_readl(&self, addr: u64) -> u32;
    fn config_readq(&self, addr: u64) -> u64;
    fn config_writeb(&self, addr: u64, value: u8);
    fn config_writew(&self, addr: u64, value: u16);
    fn config_writel(&self, addr: u64, value: u32);
    fn config_writeq(&self, addr: u64, value: u64);
    fn enable_interrupt(&mut self);
    fn disable_interrupt(&mut self);
    fn get_device_features(&self) -> u64;
    fn set_guest_features(&self, features: u64);
    fn get_guest_features(&self) -> u64;
    fn get_status(&self) -> u8;
    fn set_status(&self, status: u8);
    fn get_queue_nums(&self) -> u16;
    fn get_generation(&self) -> u8;
    fn queue_select(&self, index: u16);
    fn get_queue_select(&self) -> u16;
    fn set_queue_size(&self, size: u16);
    fn get_queue_size(&self) -> u16;
    fn activate_queue(&self, desc: u64, avail: u64, used: u64);
    fn queue_was_notified(&self, virtqueue: Rc<RefCell<TestVirtQueue>>) -> bool;
    fn setup_virtqueue(
        &self,
        test_state: Rc<RefCell<TestState>>,
        alloc: Rc<RefCell<GuestAllocator>>,
        index: u16,
    ) -> Rc<RefCell<TestVirtQueue>>;
    fn cleanup_virtqueue(&self, alloc: Rc<RefCell<GuestAllocator>>, desc_addr: u64);
    fn init_virtqueue(
        &mut self,
        test_state: Rc<RefCell<TestState>>,
        alloc: Rc<RefCell<GuestAllocator>>,
        num_queues: usize,
    ) -> Vec<Rc<RefCell<TestVirtQueue>>>;
    fn virtqueue_notify(&self, virtqueue: Rc<RefCell<TestVirtQueue>>);
    fn kick_virtqueue(
        &self,
        test_state: Rc<RefCell<TestState>>,
        virtqueue: Rc<RefCell<TestVirtQueue>>,
    );
    fn poll_used_elem(
        &self,
        test_state: Rc<RefCell<TestState>>,
        virtqueue: Rc<RefCell<TestVirtQueue>>,
        desc_idx: u32,
        timeout_us: u64,
        len: &mut Option<u32>,
        wait_notified: bool,
    );
    fn init_device(
        &mut self,
        test_state: Rc<RefCell<TestState>>,
        alloc: Rc<RefCell<GuestAllocator>>,
        features: u64,
        num_queues: usize,
    ) -> Vec<Rc<RefCell<TestVirtQueue>>>;
    fn destroy_device(
        &mut self,
        alloc: Rc<RefCell<GuestAllocator>>,
        vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    );
    fn reset(&mut self);
    fn negotiate_features(&mut self, features: u64);
    fn set_features_ok(&mut self);
    fn set_driver_ok(&self);

    fn start(&mut self) {
        self.reset();
        self.set_acknowledge();
        self.set_driver();
    }

    fn set_acknowledge(&self) {
        let status = self.get_status() | VIRTIO_CONFIG_S_ACKNOWLEDGE;
        self.set_status(status);

        assert_eq!(self.get_status(), status);
    }

    fn set_driver(&self) {
        let status = self.get_status() | VIRTIO_CONFIG_S_DRIVER;
        self.set_status(status);

        assert_eq!(self.get_status(), status);
    }

    fn req_result(&self, test_state: Rc<RefCell<TestState>>, addr: u64, timeout_us: u64) -> u8 {
        let start_time = time::Instant::now();
        let timeout_us = time::Duration::from_micros(timeout_us);
        let mut value = test_state.borrow().readb(addr);

        while value == 0xFF {
            test_state.borrow().clock_step_ns(100);
            assert!(
                time::Instant::now() - start_time <= timeout_us,
                "The device failed to process the request!"
            );
            value = test_state.borrow().readb(addr);
        }

        value
    }
}

#[repr(C, packed(16))]
#[derive(Default, Copy, Clone, Debug)]
pub struct VringDesc {
    addr: u64,
    len: u32,
    pub flags: u16,
    next: u16,
}

impl ByteCode for VringDesc {}
pub static VRING_DESC_SIZE: u64 = size_of::<VringDesc>() as u64;

#[allow(unused)]
#[repr(C, packed(2))]
pub struct VringAvail {
    flags: u16,
    idx: u16,
    ring: Vec<u16>,
}

#[repr(C, packed(4))]
pub struct VringUsedElem {
    id: u32,
    pub len: u32,
}

#[repr(C, packed(4))]
pub struct VringUsed {
    flags: u16,
    pub idx: u16,
    pub ring: Vec<VringUsedElem>,
}

#[allow(unused)]
struct Vring {
    num: u32,
    desc: VringDesc,
    avail: VringAvail,
    used: VringUsed,
}

#[derive(Default)]
pub struct TestVringIndirectDesc {
    pub desc: u64,
    pub index: u16,
    pub elem: u16,
}

#[derive(Default)]
pub struct TestVringDescEntry {
    pub data: u64,
    pub len: u32,
    pub write: bool,
}

impl TestVringIndirectDesc {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn setup(
        &mut self,
        alloc: Rc<RefCell<GuestAllocator>>,
        test_state: Rc<RefCell<TestState>>,
        elem: u16,
    ) {
        self.elem = elem;
        self.desc = alloc
            .borrow_mut()
            .alloc((size_of::<VringDesc>() * elem as usize).try_into().unwrap());

        for i in 0..elem - 1 {
            test_state
                .borrow()
                .writeq(self.desc + (size_of::<VringDesc>() * i as usize) as u64, 0);

            test_state.borrow().writel(
                self.desc
                    + (size_of::<VringDesc>() * i as usize + offset_of!(VringDesc, len)) as u64,
                0,
            );

            test_state.borrow().writew(
                self.desc
                    + (size_of::<VringDesc>() * i as usize + offset_of!(VringDesc, flags)) as u64,
                VRING_DESC_F_NEXT,
            );

            test_state.borrow().writew(
                self.desc
                    + (size_of::<VringDesc>() * i as usize + offset_of!(VringDesc, next)) as u64,
                i + 1,
            );
        }
    }

    pub fn add_desc(
        &mut self,
        test_state: Rc<RefCell<TestState>>,
        data: u64,
        len: u32,
        write: bool,
    ) {
        assert!(self.index < self.elem);

        let mut flags = test_state.borrow().readw(
            self.desc
                + (size_of::<VringDesc>() as u64 * self.index as u64)
                + offset_of!(VringDesc, flags) as u64,
        );

        if write {
            flags |= VRING_DESC_F_WRITE;
        }

        test_state.borrow().writeq(
            self.desc + (size_of::<VringDesc>() * self.index as usize) as u64,
            data,
        );
        test_state.borrow().writel(
            self.desc
                + (size_of::<VringDesc>() * self.index as usize + offset_of!(VringDesc, len))
                    as u64,
            len,
        );
        test_state.borrow().writew(
            self.desc
                + (size_of::<VringDesc>() * self.index as usize + offset_of!(VringDesc, flags))
                    as u64,
            flags,
        );

        self.index += 1;
    }

    pub fn set_desc_flag(&mut self, test_state: Rc<RefCell<TestState>>, idx: u64, flag: u16) {
        test_state.borrow().writew(
            self.desc
                + (size_of::<VringDesc>() * idx as usize + offset_of!(VringDesc, flags)) as u64,
            flag,
        );
    }
}

#[derive(Default)]
pub struct TestVirtQueue {
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
    pub index: u16,
    pub size: u32,
    pub free_head: u32,
    pub num_free: u32,
    pub align: u32,
    last_used_idx: u16,
    pub indirect: bool,
    pub event: bool,
    pub msix_entry: u16,
    pub msix_addr: u64,
    pub msix_data: u32,
    pub queue_notify_off: u64,
    pub desc_len: HashMap<u32, u32>,
}

impl TestVirtQueue {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn vring_init(&self, test_state: Rc<RefCell<TestState>>) {
        // desc[i]->addr = 0, desc[i]->next = i + 1;
        for i in 0..self.size - 1 {
            test_state
                .borrow()
                .writeq(self.desc + (size_of::<VringDesc>() * i as usize) as u64, 0);
            test_state.borrow().writew(
                self.desc
                    + (size_of::<VringDesc>() * i as usize + offset_of!(VringDesc, next)) as u64,
                (i + 1).try_into().unwrap(),
            );
        }

        // virtqueue.avail.flags
        test_state.borrow().writew(self.avail, 0);
        // virtqueue.avail.idx
        test_state
            .borrow()
            .writew(self.avail + offset_of!(VringAvail, idx) as u64, 0);
        // virtqueue.avail.used_event
        test_state.borrow().writew(
            self.avail
                + offset_of!(VringAvail, ring) as u64
                + (size_of::<u16>() * self.size as usize) as u64,
            0,
        );

        // virtqueue.used.flags
        test_state.borrow().writew(self.used, 0);
        // virtqueue.used.idx
        test_state
            .borrow()
            .writew(self.used + offset_of!(VringUsed, idx) as u64, 0);
        // virtqueue.used.avail_event
        test_state.borrow().writew(
            self.used
                + offset_of!(VringUsed, ring) as u64
                + (size_of::<VringUsedElem>() as u64 * self.size as u64),
            0,
        );
    }

    pub fn setup(
        &mut self,
        virtio_dev: &dyn VirtioDeviceOps,
        alloc: Rc<RefCell<GuestAllocator>>,
        index: u16,
    ) {
        let num_queues = virtio_dev.get_queue_nums();
        assert!(index <= num_queues);

        let features = virtio_dev.get_guest_features();
        virtio_dev.queue_select(index);

        let queue_size = virtio_dev.get_queue_size().try_into().unwrap();
        assert!(queue_size != 0);
        assert!(queue_size & (queue_size - 1) == 0);

        self.index = index;
        self.size = queue_size;
        self.free_head = 0;
        self.num_free = self.size;
        self.align = VIRTIO_PCI_VRING_ALIGN;
        self.indirect = (features & (1 << VIRTIO_RING_F_INDIRECT_DESC)) != 0;
        self.event = (features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;

        let addr = alloc
            .borrow_mut()
            .alloc(get_vring_size(self.size, self.align) as u64);
        self.desc = addr;
        self.avail = self.desc + (self.size * size_of::<VringDesc>() as u32) as u64;
        self.used = round_up(
            self.avail + (size_of::<u16>() as u32 * (3 + self.size)) as u64,
            self.align as u64,
        )
        .unwrap();
    }

    /// Get used elements from used ring and save to self.desc_len
    pub fn get_buf(&mut self, test_state: Rc<RefCell<TestState>>) -> bool {
        let mut ret = false;
        loop {
            let index = test_state
                .borrow()
                .readw(self.used + offset_of!(VringUsed, idx) as u64);
            if index == self.last_used_idx {
                break;
            }

            let elem_addr = self.used
                + offset_of!(VringUsed, ring) as u64
                + (self.last_used_idx as u32 % self.size) as u64
                    * size_of::<VringUsedElem>() as u64;

            let id_addr = elem_addr + offset_of!(VringUsedElem, id) as u64;
            let id_val = test_state.borrow().readl(id_addr);
            let len_addr = elem_addr + offset_of!(VringUsedElem, len) as u64;
            let len_val = test_state.borrow().readl(len_addr);
            self.desc_len.insert(id_val, len_val);

            self.last_used_idx += 1;
            ret = true;
        }
        ret
    }

    pub fn get_avail_event(&self, test_state: Rc<RefCell<TestState>>) -> u16 {
        assert!(self.event);

        test_state.borrow().readw(
            self.used
                + offset_of!(VringUsed, ring) as u64
                + (size_of::<VringUsedElem>() as u64 * self.size as u64),
        )
    }

    pub fn set_used_event(&self, test_state: Rc<RefCell<TestState>>, index: u16) {
        test_state.borrow().writew(
            self.avail
                + offset_of!(VringAvail, ring) as u64
                + (size_of::<u16>() as u64 * self.size as u64),
            index,
        );
    }

    pub fn set_avail_flags(&self, test_state: Rc<RefCell<TestState>>, flags: u16) {
        test_state
            .borrow()
            .writew(self.avail + offset_of!(VringAvail, flags) as u64, flags);
    }

    fn set_avail_idx(&self, test_state: Rc<RefCell<TestState>>, index: u16) {
        test_state
            .borrow()
            .writew(self.avail + offset_of!(VringAvail, idx) as u64, index);
    }

    fn set_avail_ring(&self, test_state: Rc<RefCell<TestState>>, desc_idx: u16) {
        let idx: u16 = test_state
            .borrow()
            .readw(self.avail + offset_of!(VringAvail, idx) as u64);
        test_state.borrow().writew(
            self.avail
                + offset_of!(VringAvail, ring) as u64
                + (size_of::<u16>() * (idx as u32 % self.size) as usize) as u64,
            desc_idx,
        );
    }

    pub fn update_avail(&self, test_state: Rc<RefCell<TestState>>, desc_idx: u32) {
        let idx: u16 = test_state
            .borrow()
            .readw(self.avail + offset_of!(VringAvail, idx) as u64);
        // Update avail.used_event.
        if self.event {
            self.set_used_event(test_state.clone(), idx);
        }
        // avail.ring[idx] = desc_idx.
        self.set_avail_ring(test_state.clone(), desc_idx as u16);
        // Update avail.idx.
        self.set_avail_idx(test_state, idx + 1);
    }

    pub fn add(
        &mut self,
        test_state: Rc<RefCell<TestState>>,
        data: u64,
        len: u32,
        write: bool,
    ) -> u32 {
        let free_head = self.free_head;
        let mut flags: u16 = 0;
        if write {
            flags |= VRING_DESC_F_WRITE;
        }

        let desc_elem = VringDesc {
            addr: data,
            len: len,
            flags,
            next: 0,
        };
        self.add_elem_to_desc(test_state.clone(), desc_elem);
        self.update_avail(test_state.clone(), free_head);

        free_head
    }

    pub fn add_chained(
        &mut self,
        test_state: Rc<RefCell<TestState>>,
        data_entries: Vec<TestVringDescEntry>,
    ) -> u32 {
        let free_head = self.free_head;

        for (i, entry) in data_entries.iter().enumerate() {
            let mut flags: u16 = 0;
            let mut next_desc = 0;
            if entry.write {
                flags |= VRING_DESC_F_WRITE;
            }
            if i < data_entries.len() - 1 {
                flags |= VRING_DESC_F_NEXT;
                next_desc = self.free_head + 1;
            }

            let desc_elem = VringDesc {
                addr: entry.data,
                len: entry.len,
                flags,
                next: next_desc as u16,
            };
            self.add_elem_to_desc(test_state.clone(), desc_elem);
        }
        self.update_avail(test_state.clone(), free_head);
        free_head
    }

    pub fn add_indirect(
        &mut self,
        test_state: Rc<RefCell<TestState>>,
        indirect: TestVringIndirectDesc,
        mixed: bool,
    ) -> u32 {
        assert!(indirect.index >= indirect.elem);

        let free_head = self.free_head;
        let desc_elem = VringDesc {
            addr: indirect.desc,
            len: size_of::<VringDesc>() as u32 * indirect.elem as u32,
            flags: VRING_DESC_F_INDIRECT,
            next: 0,
        };
        self.add_elem_to_desc(test_state.clone(), desc_elem);
        if !mixed {
            self.update_avail(test_state.clone(), free_head);
        }
        free_head
    }

    // Add a vring desc elem to desc table.
    fn add_elem_to_desc(&mut self, test_state: Rc<RefCell<TestState>>, elem: VringDesc) {
        self.num_free -= 1;
        let desc_elem_addr = self.desc + VRING_DESC_SIZE * self.free_head as u64;
        test_state
            .borrow()
            .memwrite(desc_elem_addr, elem.as_bytes());
        self.free_head += 1;
    }
}

#[derive(Default)]
pub struct TestVirtioDev {
    pub features: u64,
    pub device_type: u16,
    pub feature_negotiated: bool,
}

impl TestVirtioDev {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[inline]
pub fn get_vring_size(num: u32, align: u32) -> u32 {
    let desc_avail =
        (size_of::<VringDesc>() as u32 * num + size_of::<u16>() as u32 * (3 + num)) as u64;
    let desc_avail_align = round_up(desc_avail, align as u64).unwrap() as u32;
    desc_avail_align + size_of::<u16>() as u32 * 3 + size_of::<VringUsedElem>() as u32 * num
}
