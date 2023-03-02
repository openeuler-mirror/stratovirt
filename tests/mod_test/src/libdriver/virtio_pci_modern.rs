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
use super::pci::{
    PCIBarAddr, PciMsixOps, TestPciDev, PCI_CAP_ID_VNDR, PCI_DEVICE_ID, PCI_SUBSYSTEM_ID,
    PCI_VENDOR_ID,
};
use super::pci_bus::TestPciBus;
use super::virtio::{
    TestVirtQueue, TestVirtioDev, VirtioDeviceOps, VIRTIO_CONFIG_S_DRIVER_OK,
    VIRTIO_CONFIG_S_FEATURES_OK, VIRTIO_F_VERSION_1,
};
use crate::libtest::TestState;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};
use util::offset_of;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

#[repr(C, packed)]
pub struct VirtioPciCap {
    cap_vndr: u8,
    cap_next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar: u8,
    id: u8,
    padding: [u8; 2],
    offset: u32,
    length: u32,
}

#[repr(C, packed)]
pub struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: u32,
}

#[repr(C, packed)]
pub struct VirtioPciCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    guest_feature_select: u32,
    guest_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,

    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    pub queue_enable: u16,
    pub queue_notify_off: u16,
    pub queue_desc_lo: u32,
    pub queue_desc_hi: u32,
    pub queue_avail_lo: u32,
    pub queue_avail_hi: u32,
    pub queue_used_lo: u32,
    pub queue_used_hi: u32,
}

pub trait VirtioPCIMSIXOps {
    fn set_config_vector(&self, entry: u16);
    fn set_queue_vector(&self, vq_idx: u16, vector: u16);
}

pub struct TestVirtioPciDev {
    pub pci_dev: TestPciDev,
    pub bar: PCIBarAddr,
    pub bar_idx: u8,
    pub config_msix_entry: u16,
    pub config_msix_addr: u64,
    pub config_msix_data: u32,
    pub common_base: u32,
    isr_base: u32,
    pub notify_base: u32,
    pub notify_off_multiplier: u32,
    device_base: u32,
    pub virtio_dev: TestVirtioDev,
}

impl TestVirtioPciDev {
    pub fn new(pci_bus: Rc<RefCell<TestPciBus>>) -> Self {
        Self {
            pci_dev: TestPciDev::new(pci_bus),
            bar: 0,
            bar_idx: 0,
            config_msix_entry: 0,
            config_msix_addr: 0,
            config_msix_data: 0,
            common_base: 0,
            isr_base: 0,
            notify_base: 0,
            notify_off_multiplier: 0,
            device_base: 0,
            virtio_dev: TestVirtioDev::new(),
        }
    }

    pub fn init(&mut self, pci_slot: u8, pci_fn: u8) {
        let devfn = pci_slot << 3 | pci_fn;
        assert!(self.find_pci_device(devfn));

        let device_type = self.pci_device_type_probe().unwrap_or(0);
        self.virtio_dev.device_type = device_type;
        self.enable();
        self.start();
    }

    fn enable(&mut self) {
        self.pci_dev.enable();
        self.bar = self.pci_dev.io_map(self.bar_idx);
    }

    fn find_pci_device(&mut self, devfn: u8) -> bool {
        self.pci_dev.devfn = devfn;
        self.pci_dev.config_readw(PCI_VENDOR_ID) != 0xFFFF
    }

    fn find_structure(
        &self,
        cfg_type: u8,
        bar: &mut u8,
        offset: &mut u32,
        cfg_addr: Rc<RefCell<Option<u8>>>,
    ) -> bool {
        let mut addr: u8 = 0;
        loop {
            addr = self.pci_dev.find_capability(PCI_CAP_ID_VNDR, addr);
            if addr == 0 {
                break;
            }

            let config_type = self
                .pci_dev
                .config_readb(addr + offset_of!(VirtioPciCap, cfg_type) as u8);
            if config_type != cfg_type {
                continue;
            }

            *bar = self
                .pci_dev
                .config_readb(addr + offset_of!(VirtioPciCap, bar) as u8);
            *offset = self
                .pci_dev
                .config_readl(addr + offset_of!(VirtioPciCap, offset) as u8);

            if cfg_addr.borrow().is_some() {
                cfg_addr.borrow_mut().replace(addr);
            }

            return true;
        }

        false
    }

    fn pci_device_type_probe(&mut self) -> Option<u16> {
        let device_type;
        let vendor_id = self.pci_dev.config_readw(PCI_VENDOR_ID);
        if vendor_id != 0x1af4 {
            return None;
        }

        let device_id = self.pci_dev.config_readw(PCI_DEVICE_ID);
        if !(0x1000..=0x107f).contains(&device_id) {
            return None;
        }
        if device_id < 0x1040 {
            device_type = self.pci_dev.config_readw(PCI_SUBSYSTEM_ID);
        } else {
            device_type = device_id - 0x1040;
        }

        self.pci_layout_probe();
        Some(device_type)
    }

    fn pci_layout_probe(&mut self) -> bool {
        let mut bar: u8 = 0;
        let notify_cfg_addr: Rc<RefCell<Option<u8>>> = Rc::new(RefCell::new(Some(0)));

        let mut offset: u32 = 0;

        if !self.find_structure(
            VIRTIO_PCI_CAP_COMMON_CFG,
            &mut bar,
            &mut offset,
            Rc::new(RefCell::new(None)),
        ) {
            return false;
        }
        self.common_base = offset;
        self.bar_idx = bar;

        if !self.find_structure(
            VIRTIO_PCI_CAP_ISR_CFG,
            &mut bar,
            &mut offset,
            Rc::new(RefCell::new(None)),
        ) {
            return false;
        }
        self.isr_base = offset;
        assert!(bar == self.bar_idx);

        if !self.find_structure(
            VIRTIO_PCI_CAP_NOTIFY_CFG,
            &mut bar,
            &mut offset,
            notify_cfg_addr.clone(),
        ) {
            return false;
        }
        self.notify_base = offset;
        assert!(bar == self.bar_idx);

        self.notify_off_multiplier = self.pci_dev.config_readl(
            notify_cfg_addr.borrow().unwrap()
                + offset_of!(VirtioPciNotifyCap, notify_off_multiplier) as u8,
        );

        if !self.find_structure(
            VIRTIO_PCI_CAP_DEVICE_CFG,
            &mut bar,
            &mut offset,
            Rc::new(RefCell::new(None)),
        ) {
            return false;
        }
        self.device_base = offset;
        assert!(bar == self.bar_idx);

        true
    }

    pub fn setup_msix_configuration_vector(
        &mut self,
        alloc: Rc<RefCell<GuestAllocator>>,
        entry: u16,
    ) {
        self.config_msix_entry = entry;
        self.config_msix_data = 0x12345678;
        self.config_msix_addr = alloc.borrow_mut().alloc(4);

        self.pci_dev.set_msix_vector(
            self.config_msix_entry,
            self.config_msix_addr,
            self.config_msix_data,
        );
        self.set_config_vector(self.config_msix_entry);
    }

    fn has_msix(&self, msix_addr: u64, msix_data: u32) -> bool {
        return self.pci_dev.has_msix(msix_addr, msix_data);
    }

    pub fn setup_virtqueue_intr(
        &self,
        entry: u16,
        alloc: Rc<RefCell<GuestAllocator>>,
        virtqueue: Rc<RefCell<TestVirtQueue>>,
    ) {
        virtqueue.borrow_mut().msix_entry = entry;
        virtqueue.borrow_mut().msix_addr = alloc.borrow_mut().alloc(4);
        virtqueue.borrow_mut().msix_data = 0x12345678;

        self.pci_dev.set_msix_vector(
            virtqueue.borrow().msix_entry,
            virtqueue.borrow().msix_addr,
            virtqueue.borrow().msix_data,
        );
        self.set_queue_vector(virtqueue.borrow().index, entry);
    }
}

impl VirtioDeviceOps for TestVirtioPciDev {
    fn config_readb(&self, addr: u64) -> u8 {
        self.pci_dev
            .io_readb(self.bar, self.device_base as u64 + addr)
    }

    fn config_readw(&self, addr: u64) -> u16 {
        self.pci_dev
            .io_readw(self.bar, self.device_base as u64 + addr)
    }

    fn config_readl(&self, addr: u64) -> u32 {
        self.pci_dev
            .io_readl(self.bar, self.device_base as u64 + addr)
    }

    fn config_readq(&self, addr: u64) -> u64 {
        self.pci_dev
            .io_readq(self.bar, self.device_base as u64 + addr)
    }

    #[allow(unused)]
    fn config_writeb(&self, addr: u64, value: u8) {
        self.pci_dev
            .io_writeb(self.bar, self.device_base as u64 + addr, value)
    }

    #[allow(unused)]
    fn config_writew(&self, addr: u64, value: u16) {
        self.pci_dev
            .io_writew(self.bar, self.device_base as u64 + addr, value)
    }

    #[allow(unused)]
    fn config_writel(&self, addr: u64, value: u32) {
        self.pci_dev
            .io_writel(self.bar, self.device_base as u64 + addr, value)
    }

    #[allow(unused)]
    fn config_writeq(&self, addr: u64, value: u64) {
        self.pci_dev
            .io_writeq(self.bar, self.device_base as u64 + addr, value)
    }

    fn enable_interrupt(&mut self) {
        self.pci_dev.enable_msix(None);
    }

    fn disable_interrupt(&mut self) {
        self.pci_dev.disable_msix();
    }

    fn get_device_features(&self) -> u64 {
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, device_feature_select) as u64,
            0,
        );
        let lo: u64 = self.pci_dev.io_readl(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, device_feature) as u64,
        ) as u64;

        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, device_feature_select) as u64,
            1,
        );
        let hi: u64 = self.pci_dev.io_readl(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, device_feature) as u64,
        ) as u64;
        (hi << 32) | lo
    }

    fn set_guest_features(&self, features: u64) {
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, guest_feature_select) as u64,
            0,
        );
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, guest_feature) as u64,
            features as u32,
        );

        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, guest_feature_select) as u64,
            1,
        );
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, guest_feature) as u64,
            (features >> 32) as u32,
        );
    }

    fn get_guest_features(&self) -> u64 {
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, guest_feature_select) as u64,
            0,
        );
        let lo: u64 = self.pci_dev.io_readl(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, guest_feature) as u64,
        ) as u64;
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, guest_feature_select) as u64,
            1,
        );
        let hi: u64 = self.pci_dev.io_readl(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, guest_feature) as u64,
        ) as u64;
        (hi << 32) | lo
    }

    fn get_status(&self) -> u8 {
        self.pci_dev.io_readb(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, device_status) as u64,
        )
    }

    fn set_status(&self, status: u8) {
        self.pci_dev.io_writeb(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, device_status) as u64,
            status,
        )
    }

    fn get_generation(&self) -> u8 {
        self.pci_dev.io_readb(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, config_generation) as u64,
        )
    }

    fn get_queue_nums(&self) -> u16 {
        self.pci_dev.io_readw(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, num_queues) as u64,
        )
    }

    fn queue_select(&self, index: u16) {
        self.pci_dev.io_writew(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_select) as u64,
            index,
        );
    }

    fn get_queue_select(&self) -> u16 {
        self.pci_dev.io_readw(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_select) as u64,
        )
    }

    fn set_queue_size(&self, size: u16) {
        self.pci_dev.io_writew(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_size) as u64,
            size,
        )
    }

    fn get_queue_size(&self) -> u16 {
        self.pci_dev.io_readw(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_size) as u64,
        )
    }

    fn activate_queue(&self, desc: u64, avail: u64, used: u64) {
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_desc_lo) as u64,
            desc as u32,
        );
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_desc_hi) as u64,
            (desc >> 32) as u32,
        );
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_avail_lo) as u64,
            avail as u32,
        );
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_avail_hi) as u64,
            (avail >> 32) as u32,
        );
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_used_lo) as u64,
            used as u32,
        );
        self.pci_dev.io_writel(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_used_hi) as u64,
            (used >> 32) as u32,
        );
    }

    fn poll_used_elem(
        &self,
        test_state: Rc<RefCell<TestState>>,
        virtqueue: Rc<RefCell<TestVirtQueue>>,
        desc_idx: u32,
        timeout_us: u64,
        len: &mut Option<u32>,
        wait_notified: bool,
    ) {
        let start_time = Instant::now();
        let timeout_us = Duration::from_micros(timeout_us);

        loop {
            if (!wait_notified || self.queue_was_notified(virtqueue.clone()))
                && virtqueue.borrow_mut().get_buf(test_state.clone())
            {
                if let Some(got_len) = virtqueue.borrow().desc_len.get(&desc_idx) {
                    if let Some(len) = len {
                        *len = *got_len;
                    }
                    break;
                }
            }
            assert!(Instant::now() - start_time < timeout_us);
        }
    }

    fn queue_was_notified(&self, virtqueue: Rc<RefCell<TestVirtQueue>>) -> bool {
        assert!(self.pci_dev.msix_enabled);
        return self.has_msix(virtqueue.borrow().msix_addr, virtqueue.borrow().msix_data);
    }

    fn setup_virtqueue(
        &self,
        test_state: Rc<RefCell<TestState>>,
        alloc: Rc<RefCell<GuestAllocator>>,
        index: u16,
    ) -> Rc<RefCell<TestVirtQueue>> {
        let virtqueue = Rc::new(RefCell::new(TestVirtQueue::new()));
        virtqueue.borrow_mut().setup(self, alloc, index);
        virtqueue.borrow().vring_init(test_state);

        let desc = virtqueue.borrow().desc;
        let avail = virtqueue.borrow().avail;
        let used = virtqueue.borrow().used;
        self.activate_queue(desc, avail, used);

        let notify_off = self.pci_dev.io_readw(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_notify_off) as u64,
        );

        virtqueue.borrow_mut().queue_notify_off =
            self.notify_base as u64 + notify_off as u64 * self.notify_off_multiplier as u64;

        self.pci_dev.io_writew(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_enable) as u64,
            1,
        );

        virtqueue
    }

    fn cleanup_virtqueue(&self, alloc: Rc<RefCell<GuestAllocator>>, desc_addr: u64) {
        alloc.borrow_mut().free(desc_addr);
    }

    fn virtqueue_notify(&self, virtqueue: Rc<RefCell<TestVirtQueue>>) {
        let index = virtqueue.borrow().index;
        let notify_offset = virtqueue.borrow().queue_notify_off;
        self.pci_dev.io_writew(self.bar, notify_offset, index);
    }

    /// Notify the virtio device to process req. free_head is Head
    /// of free buffer list of descriptor table. num_add is the number
    /// of the io request added to the virtqueue.
    fn kick_virtqueue(
        &self,
        test_state: Rc<RefCell<TestState>>,
        virtqueue: Rc<RefCell<TestVirtQueue>>,
    ) {
        let vq = virtqueue.borrow();
        let idx: u16 = test_state.borrow().readw(vq.avail + 2);

        if (!vq.event) || (idx >= vq.get_avail_event(test_state.clone()) + 1) {
            self.virtqueue_notify(virtqueue.clone());
        }
    }

    fn reset(&mut self) {
        self.set_status(0);
        assert_eq!(self.get_status(), 0);
        self.virtio_dev.feature_negotiated = false;
    }

    fn negotiate_features(&mut self, features: u64) {
        self.virtio_dev.features = features;
        self.set_guest_features(features);
    }

    fn set_features_ok(&mut self) {
        if (self.get_guest_features() & (1 << VIRTIO_F_VERSION_1)) != 0 {
            let status: u8 = self.get_status() | VIRTIO_CONFIG_S_FEATURES_OK;
            self.set_status(status);
            assert_eq!(self.get_status(), status);
        }

        self.virtio_dev.feature_negotiated = true;
    }

    fn set_driver_ok(&self) {
        let status = self.get_status() | VIRTIO_CONFIG_S_DRIVER_OK;
        self.set_status(status);
        assert_eq!(self.get_status(), status);
    }

    fn init_virtqueue(
        &mut self,
        test_state: Rc<RefCell<TestState>>,
        alloc: Rc<RefCell<GuestAllocator>>,
        num_queues: usize,
    ) -> Vec<Rc<RefCell<TestVirtQueue>>> {
        assert!(num_queues < (1 << 15));
        let mut virtqueues = Vec::new();
        for i in 0..num_queues {
            let virtqueue = self.setup_virtqueue(test_state.clone(), alloc.clone(), i as u16);
            self.setup_virtqueue_intr((i + 1) as u16, alloc.clone(), virtqueue.clone());
            virtqueues.push(virtqueue);
        }

        virtqueues
    }

    fn init_device(
        &mut self,
        test_state: Rc<RefCell<TestState>>,
        alloc: Rc<RefCell<GuestAllocator>>,
        features: u64,
        num_queues: usize,
    ) -> Vec<Rc<RefCell<TestVirtQueue>>> {
        // Reset device by write 0 to device status.
        self.reset();
        self.set_acknowledge();
        self.set_driver();
        self.negotiate_features(features);
        assert_eq!(self.get_guest_features(), features);
        self.set_features_ok();
        // FIXME: add handling the specific device features as needed.

        self.pci_dev.enable_msix(None);
        self.setup_msix_configuration_vector(alloc.clone(), 0);
        let vqs = self.init_virtqueue(test_state, alloc, num_queues);

        self.set_driver_ok();
        vqs
    }

    fn destroy_device(
        &mut self,
        alloc: Rc<RefCell<GuestAllocator>>,
        vqs: Vec<Rc<RefCell<TestVirtQueue>>>,
    ) {
        self.reset();
        self.pci_dev.disable_msix();
        for vq in vqs.iter() {
            self.cleanup_virtqueue(alloc.clone(), vq.borrow().desc);
        }
    }
}

impl VirtioPCIMSIXOps for TestVirtioPciDev {
    fn set_config_vector(&self, vector: u16) {
        self.pci_dev.io_writew(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, msix_config) as u64,
            vector,
        );
        let vector_get: u16 = self.pci_dev.io_readw(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, msix_config) as u64,
        );
        assert_eq!(
            vector, vector_get,
            "WARN: set config vector {}, get vector {}",
            vector, vector_get
        );
    }

    fn set_queue_vector(&self, vq_idx: u16, vector: u16) {
        self.queue_select(vq_idx);
        self.pci_dev.io_writew(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_msix_vector) as u64,
            vector,
        );
        let vector_get: u16 = self.pci_dev.io_readw(
            self.bar,
            self.common_base as u64 + offset_of!(VirtioPciCommonCfg, queue_msix_vector) as u64,
        );
        if vector_get != vector {
            println!("WARN: set vector {}, get vector {}", vector, vector_get);
        }
    }
}
