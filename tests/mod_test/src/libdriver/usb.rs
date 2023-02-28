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

use std::{
    cell::{RefCell, RefMut},
    collections::{HashMap, LinkedList},
    mem::size_of,
    rc::Rc,
    time::Duration,
};

use byteorder::{ByteOrder, LittleEndian};

use super::{
    machine::TestStdMachine,
    malloc::GuestAllocator,
    pci::{PCIBarAddr, TestPciDev, PCI_VENDOR_ID},
    pci_bus::TestPciBus,
};
use crate::libdriver::pci::{PciMsixOps, PCI_DEVICE_ID};
use crate::libtest::{test_init, TestState};
use usb::{
    config::*,
    hid::{
        HID_GET_IDLE, HID_GET_PROTOCOL, HID_GET_REPORT, HID_SET_IDLE, HID_SET_PROTOCOL,
        HID_SET_REPORT,
    },
    usb::UsbDeviceRequest,
    xhci::{
        xhci_controller::{
            DwordOrder, XhciEpCtx, XhciInputCtrlCtx, XhciSlotCtx, EP_RUNNING, SLOT_DEFAULT,
        },
        xhci_regs::{
            XHCI_INTR_REG_ERDP_LO, XHCI_INTR_REG_ERSTBA_LO, XHCI_INTR_REG_ERSTSZ,
            XHCI_INTR_REG_IMAN, XHCI_INTR_REG_SIZE, XHCI_OPER_REG_CONFIG, XHCI_OPER_REG_PAGESIZE,
            XHCI_OPER_REG_USBCMD, XHCI_OPER_REG_USBSTS,
        },
        TRBCCode, TRBType, TRB_SIZE,
    },
};

pub const PCI_VENDOR_ID_REDHAT: u16 = 0x1b36;
pub const PCI_DEVICE_ID_REDHAT_XHCI: u16 = 0x000d;
pub const PCI_CLASS_PI: u8 = 0x9;
pub const SUB_CLASS_CODE: u8 = 0xa;
pub const PCI_CLASS_SERIAL_USB: u16 = 0x0c03;

pub const XHCI_PCI_CAP_OFFSET: u32 = 0;
pub const XHCI_PCI_OPER_OFFSET: u32 = 0x40;
pub const XHCI_PCI_PORT_OFFSET: u32 = 0x440;
pub const XHCI_PCI_PORT_LENGTH: u32 = 0x10;
pub const XHCI_PCI_RUNTIME_OFFSET: u32 = 0x1000;
pub const XHCI_PCI_DOORBELL_OFFSET: u32 = 0x2000;
pub const XHCI_PORTSC_OFFSET: u64 = 0x0;
pub const XHCI_OPER_REG_DCBAAP: u64 = 0x30;
pub const XHCI_OPER_REG_CMD_RING_CTRL: u64 = 0x18;

pub const USB_CONFIG_MAX_SLOTS_EN_MASK: u32 = 0xff;
const DEVICE_CONTEXT_ENTRY_SIZE: u32 = 0x8;
const EVENT_RING_SEGMENT_TABLE_ENTRY_SIZE: u32 = 0x10;
const RUNTIME_REGS_INTERRUPT_OFFSET: u64 = 0x20;
const PORT_EVENT_ID_SHIFT: u32 = 24;
const PORT_EVENT_ID_MASK: u32 = 0xff;
// TRB
const TRB_INTR_SHIFT: u32 = 22;
const TRB_INTR_MASK: u32 = 0x3ff;
const TRB_C: u32 = 1;
const TRB_TYPE_SHIFT: u32 = 10;
const TRB_TYPE_MASK: u32 = 0x3f;
const TRB_SLOT_ID_SHIFT: u32 = 24;
const TRB_SLOT_ID_MASK: u32 = 0xff;
const TRB_EP_ID_SHIFT: u32 = 16;
const TRB_EP_ID_MASK: u32 = 0x1f;
const TRB_BSR_SHIFT: u32 = 9;
const TRB_BSR_MASK: u32 = 0x1;
const TRB_TD_SIZE_SHIFT: u32 = 9;
const TRB_TD_SIZE_MASK: u32 = 0x1;
const TRB_TRANSFER_LENGTH_SHIFT: u32 = 0;
const TRB_TRANSFER_LENGTH_MASK: u32 = 0xffff;
const TRB_IOC_SHIFT: u32 = 5;
const TRB_IOC_MASK: u32 = 0x1;
const TRB_CH_SHIFT: u32 = 4;
const TRB_CH_MASK: u32 = 0x1;
const TRB_IDT_SHIFT: u32 = 6;
const TRB_IDT_MASK: u32 = 0x1;
const TRB_ISP_SHIFT: u32 = 2;
const TRB_ISP_MASK: u32 = 0x1;
const TRB_DIR_SHIFT: u32 = 16;
const TRB_DIR_MASK: u32 = 0x1;
const TRB_TRT_SHIFT: u32 = 16;
const TRB_TRT_MASK: u32 = 0x1;
const TRB_TC_SHIFT: u32 = 1;
const TRB_TC_MASK: u32 = 0x1;
const TRB_DC_SHIFT: u32 = 9;
const TRB_DC_MASK: u32 = 0x1;
const DEVICE_CONTEXT_SIZE: u64 = 0x400;
const INPUT_CONTEXT_SIZE: u64 = 0x420;
pub const CONTROL_ENDPOINT_ID: u32 = 1;
pub const HID_KEYBOARD_LEN: u64 = 8;
pub const HID_POINTER_LEN: u64 = 6;
pub const KEYCODE_SPACE: u32 = 57;
pub const KEYCODE_NUM1: u32 = 2;
// Descriptor type
pub const USB_DESCRIPTOR_TYPE_DEVICE: u8 = 1;
pub const USB_DESCRIPTOR_TYPE_CONFIG: u8 = 2;
pub const USB_DESCRIPTOR_TYPE_STRING: u8 = 3;
pub const USB_DESCRIPTOR_TYPE_INTERFACE: u8 = 4;
pub const USB_DESCRIPTOR_TYPE_ENDPOINT: u8 = 5;
// Test config
pub const USB_CONFIG_MAX_SLOTS_ENABLED: u32 = 4;
pub const USB_CONFIG_MAX_INTERRUPTER: u32 = 4;
pub const COMMAND_RING_LEN: u64 = 256;
pub const EVENT_RING_SEGMENT_TABLE_LEN: u32 = 1;
pub const EVENT_RING_LEN: u64 = 64;
pub const TRANSFER_RING_LEN: u64 = 256;
// Max TRB limit in one TD.
pub const TD_TRB_LIMIT: u64 = 0x20000 + 10;
// The USB keyboard and tablet intr endpoint id.
pub const HID_DEVICE_ENDPOINT_ID: u32 = 3;
// Primary Interrupter
pub const PRIMARY_INTERRUPTER_ID: usize = 0;
pub const XHCI_PCI_SLOT_NUM: u8 = 0x5;
pub const XHCI_PCI_FUN_NUM: u8 = 0;

#[derive(Debug, Default, Copy, Clone)]
pub struct TestNormalTRB {
    parameter: u64,
    status: u32,
    control: u32,
    // Force mismatch cycle
    pub force_cycle: bool,
}

impl TestNormalTRB {
    pub fn generate_setup_td(device_req: &UsbDeviceRequest) -> TestNormalTRB {
        let mut setup_trb = TestNormalTRB::default();
        setup_trb.parameter = (device_req.length as u64) << 48
            | (device_req.index as u64) << 32
            | (device_req.value as u64) << 16
            | (device_req.request as u64) << 8
            | device_req.request_type as u64;
        setup_trb.set_idt_flag(true);
        setup_trb.set_ch_flag(true);
        setup_trb.set_trb_type(TRBType::TrSetup as u32);
        setup_trb.set_trb_transfer_length(8);
        setup_trb.set_transfer_type(3);
        setup_trb
    }

    pub fn generate_data_td(ptr: u64, len: u16, in_dir: bool) -> TestNormalTRB {
        let mut data_trb = TestNormalTRB::default();
        data_trb.set_pointer(ptr);
        data_trb.set_ch_flag(true);
        data_trb.set_dir_flag(in_dir);
        data_trb.set_trb_type(TRBType::TrData as u32);
        data_trb.set_trb_transfer_length(len as u32);
        data_trb
    }

    pub fn generate_status_td(dir: bool) -> TestNormalTRB {
        let mut status_trb = TestNormalTRB::default();
        status_trb.set_ch_flag(false);
        status_trb.set_ioc_flag(true);
        status_trb.set_dir_flag(dir);
        status_trb.set_trb_type(TRBType::TrStatus as u32);
        status_trb
    }

    pub fn generate_event_data_trb(ptr: u64) -> TestNormalTRB {
        let mut ev_data_trb = TestNormalTRB::default();
        ev_data_trb.set_pointer(ptr);
        ev_data_trb.set_ioc_flag(true);
        ev_data_trb.set_trb_type(TRBType::TrEvdata as u32);
        ev_data_trb
    }

    pub fn set_interrupter_target(&mut self, v: u32) {
        self.status &= !(TRB_INTR_MASK << TRB_INTR_SHIFT);
        self.status |= (v & TRB_INTR_MASK) << TRB_INTR_SHIFT;
    }

    pub fn set_cycle_bit(&mut self, v: bool) {
        if v {
            self.control |= TRB_C;
        } else {
            self.control &= !TRB_C;
        }
    }

    pub fn set_trb_type(&mut self, v: u32) {
        self.control &= !(TRB_TYPE_MASK << TRB_TYPE_SHIFT);
        self.control |= (v & TRB_TYPE_MASK) << TRB_TYPE_SHIFT;
    }

    pub fn set_slot_id(&mut self, v: u32) {
        self.control &= !(TRB_SLOT_ID_MASK << TRB_SLOT_ID_SHIFT);
        self.control |= (v & TRB_SLOT_ID_MASK) << TRB_SLOT_ID_SHIFT;
    }

    pub fn set_ep_id(&mut self, v: u32) {
        self.control &= !(TRB_EP_ID_MASK << TRB_EP_ID_SHIFT);
        self.control |= (v & TRB_EP_ID_MASK) << TRB_EP_ID_SHIFT;
    }

    pub fn set_bsr(&mut self, v: bool) {
        self.control &= !(TRB_BSR_MASK << TRB_BSR_SHIFT);
        self.control |= (if v { 1 } else { 0 } & TRB_BSR_MASK) << TRB_BSR_SHIFT;
    }

    fn to_xhci_event(&self) -> TestXhciEvent {
        let mut evt = TestXhciEvent::default();
        evt.ptr = self.parameter;
        evt.ccode = (self.status >> 24) & 0xff;
        evt.length = self.status & 0xffffff;
        evt.flags = self.control;
        evt
    }

    pub fn set_pointer(&mut self, dequeue: u64) {
        self.parameter = dequeue;
    }

    pub fn set_td_size(&mut self, sz: u32) {
        self.status &= !(TRB_TD_SIZE_MASK << TRB_TD_SIZE_SHIFT);
        self.status |= (sz & TRB_TD_SIZE_MASK) << TRB_TD_SIZE_SHIFT;
    }

    pub fn set_trb_transfer_length(&mut self, len: u32) {
        self.status &= !(TRB_TRANSFER_LENGTH_MASK << TRB_TRANSFER_LENGTH_SHIFT);
        self.status |= (len & TRB_TRANSFER_LENGTH_MASK) << TRB_TRANSFER_LENGTH_SHIFT;
    }

    pub fn set_ioc_flag(&mut self, v: bool) {
        if v {
            self.control |= TRB_IOC_MASK << TRB_IOC_SHIFT;
        } else {
            self.control &= !(TRB_IOC_MASK << TRB_IOC_SHIFT);
        }
    }

    pub fn set_ch_flag(&mut self, v: bool) {
        if v {
            self.control |= TRB_CH_MASK << TRB_CH_SHIFT;
        } else {
            self.control &= !(TRB_CH_MASK << TRB_CH_SHIFT);
        }
    }

    pub fn set_idt_flag(&mut self, v: bool) {
        if v {
            self.control |= TRB_IDT_MASK << TRB_IDT_SHIFT;
        } else {
            self.control &= !(TRB_IDT_MASK << TRB_IDT_SHIFT);
        }
    }

    pub fn set_isp_flag(&mut self, v: bool) {
        if v {
            self.control |= TRB_ISP_MASK << TRB_ISP_SHIFT;
        } else {
            self.control &= !(TRB_ISP_MASK << TRB_ISP_SHIFT);
        }
    }

    pub fn set_dir_flag(&mut self, v: bool) {
        if v {
            self.control |= TRB_DIR_MASK << TRB_DIR_SHIFT;
        } else {
            self.control &= !(TRB_DIR_MASK << TRB_DIR_SHIFT);
        }
    }

    pub fn set_transfer_type(&mut self, v: u32) {
        self.control &= !(TRB_TRT_MASK << TRB_TRT_SHIFT);
        self.control |= (v & TRB_TRT_MASK) << TRB_TRT_SHIFT;
    }

    pub fn set_toggle_cycle(&mut self, v: bool) {
        if v {
            self.control |= TRB_TC_MASK << TRB_TC_SHIFT;
        } else {
            self.control &= !(TRB_TC_MASK << TRB_TC_SHIFT);
        }
    }

    pub fn set_dc_flag(&mut self, v: bool) {
        self.control &= !(TRB_DC_MASK << TRB_DC_SHIFT);
        self.control |= (if v { 1 } else { 0 } & TRB_DC_MASK) << TRB_DC_SHIFT;
    }
}

#[derive(Default)]
pub struct TestXhciEvent {
    pub ccode: u32,
    pub ptr: u64,
    pub length: u32,
    flags: u32,
}

impl TestXhciEvent {
    pub fn get_port_id(&self) -> u32 {
        (self.ptr as u32) >> PORT_EVENT_ID_SHIFT & PORT_EVENT_ID_MASK
    }

    pub fn get_slot_id(&self) -> u32 {
        (self.flags >> TRB_SLOT_ID_SHIFT) & TRB_SLOT_ID_MASK
    }

    pub fn get_ep_id(&self) -> u32 {
        (self.flags >> TRB_EP_ID_SHIFT) & TRB_EP_ID_MASK
    }

    pub fn get_trb_type(&self) -> u32 {
        (self.flags >> TRB_TYPE_SHIFT) & TRB_TYPE_MASK
    }
}

#[derive(Default, Debug, Copy, Clone)]
struct TestXhciRing {
    pointer: u64,
    start: u64,
    size: u64,
    cycle_bit: bool,
}

impl TestXhciRing {
    fn new() -> Self {
        Self {
            pointer: 0,
            start: 0,
            size: 0,
            cycle_bit: true,
        }
    }

    fn init(&mut self, addr: u64, sz: u64) {
        self.pointer = addr;
        self.start = addr;
        self.size = sz;
        self.cycle_bit = true;
    }

    fn update_pointer(&mut self, addr: u64) {
        self.pointer = addr;
    }

    fn increase_pointer(&mut self, sz: u64) {
        self.pointer += sz;
    }
}

pub struct TestEventRingSegment {
    pub addr: u64,
    pub size: u32,
    pub reserved: u32,
}

impl TestEventRingSegment {
    pub fn new() -> Self {
        Self {
            addr: 0,
            size: 0,
            reserved: 0,
        }
    }

    pub fn init(&mut self, addr: u64, sz: u32) {
        self.addr = addr;
        self.size = sz;
    }
}

#[derive(Default, Clone, Copy)]
struct TestXhciInterrupter {
    erstsz: u32,
    erstba: u64,
    segment_index: u32,
    cycle_bit: bool,
    er_pointer: u64,
    trb_count: u32,
}

#[derive(Default, Clone, Copy)]
struct DeviceSlot {
    endpoints: [EndpointContext; 31],
}

#[derive(Default, Clone, Copy)]
struct EndpointContext {
    transfer_ring: TestXhciRing,
}

// Iovec for test transfer.
#[derive(Default, Clone, Copy)]
pub struct TestIovec {
    pub io_base: u64,
    pub io_len: usize,
    pub direct: bool,
    // Whether the trb is event data trb.
    pub event_data: bool,
}

impl TestIovec {
    pub fn new(base: u64, len: usize, direct: bool) -> Self {
        Self {
            io_base: base,
            io_len: len,
            direct,
            event_data: false,
        }
    }
}

struct TestXhciDevice {
    cmd_ring: TestXhciRing,
    dcbaap: u64,
    device_slot: Vec<DeviceSlot>,
    interrupter: Vec<TestXhciInterrupter>,
}

impl TestXhciDevice {
    fn new() -> Self {
        Self {
            cmd_ring: TestXhciRing::new(),
            dcbaap: 0,
            device_slot: vec![DeviceSlot::default(); (USB_CONFIG_MAX_SLOTS_ENABLED + 1) as usize],
            interrupter: vec![TestXhciInterrupter::default(); USB_CONFIG_MAX_INTERRUPTER as usize],
        }
    }
}

pub struct TestXhciPciDevice {
    pub pci_dev: TestPciDev,
    pub bar_addr: PCIBarAddr,
    bar_idx: u8,
    allocator: Rc<RefCell<GuestAllocator>>,
    xhci: TestXhciDevice,
    pub device_config: HashMap<String, bool>,
    // Event list to save all ready event when has msix.
    event_list: LinkedList<TestXhciEvent>,
    // msix config
    config_msix_entry: u16,
    config_msix_addr: u64,
    config_msix_data: u32,
}

impl TestXhciPciDevice {
    pub fn new(pci_bus: Rc<RefCell<TestPciBus>>, allocator: Rc<RefCell<GuestAllocator>>) -> Self {
        Self {
            pci_dev: TestPciDev::new(pci_bus),
            bar_addr: 0,
            bar_idx: 0,
            allocator,
            xhci: TestXhciDevice::new(),
            device_config: HashMap::new(),
            event_list: LinkedList::new(),
            config_msix_entry: 0,
            config_msix_addr: 0,
            config_msix_data: 0,
        }
    }

    pub fn run(&mut self) {
        let status = self.pci_dev.io_readl(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_USBSTS as u64,
        );
        assert!(status & USB_STS_HCH == USB_STS_HCH);
        let cmd = self.pci_dev.io_readl(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_USBCMD as u64,
        );
        self.pci_dev.io_writel(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_USBCMD as u64,
            cmd | USB_CMD_RUN,
        );
        let status = self.pci_dev.io_readl(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_USBSTS as u64,
        );
        assert!(status & USB_STS_HCH != USB_STS_HCH);
    }

    /// Reference 4.2 Host Controller initialization.
    pub fn init_host_controller(&mut self, pci_slot: u8, pci_fn: u8) {
        self.init_pci_device(pci_slot, pci_fn);
        self.read_pci_config();
        self.read_capability();
        self.init_memory();
        self.init_max_device_slot_enabled();
        self.init_device_context_base_address_array_pointer();
        self.init_command_ring_dequeue_pointer();
        self.init_interrupter();
    }

    pub fn init_device(&mut self, port_id: u32) -> u32 {
        // reset usb port
        self.reset_port(port_id);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // enable slot
        self.enable_slot();
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        if *self
            .device_config
            .get("address_device_bsr")
            .unwrap_or(&false)
        {
            // address device bsr = 1
            let slot_id = evt.get_slot_id();
            self.address_device(slot_id, true, port_id);
            let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let slot_ctx = self.get_slot_context(slot_id);
            assert_eq!(slot_ctx.get_slot_state(), SLOT_DEFAULT);
            let ep0_ctx = self.get_endpoint_context(slot_id, CONTROL_ENDPOINT_ID);
            assert_eq!(ep0_ctx.get_ep_state(), EP_RUNNING);
            // reset device
            self.reset_device(slot_id);
            let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let slot_ctx = self.get_slot_context(slot_id);
            assert_eq!(slot_ctx.get_slot_state(), SLOT_DEFAULT);
            assert_eq!(slot_ctx.get_usb_device_address(), 0);
        }
        // address device bsr = 0
        let slot_id = evt.get_slot_id();
        self.address_device(slot_id, false, port_id);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // get descriptor
        self.get_usb_descriptor(slot_id);
        // get hid report descriptor
        self.check_hid_report_descriptor(slot_id);
        // evaluate context
        self.evaluate_context(slot_id, 0x1234, 0, 64);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let slot_ctx = self.get_slot_context(slot_id);
        assert_eq!(slot_ctx.get_max_exit_latency(), 0x1234);
        assert_eq!(slot_ctx.get_interrupter_target(), 0);
        let ep0_ctx = self.get_endpoint_context(slot_id, CONTROL_ENDPOINT_ID);
        assert_eq!(ep0_ctx.get_max_packet_size(), 64);
        // get configuration
        self.get_configuration(slot_id);
        self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        let buf = self.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, 1);
        assert_eq!(buf[0], 0);
        // configure endpoint
        self.configure_endpoint(slot_id, false);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // set feature
        self.set_feature(slot_id, USB_DEVICE_REMOTE_WAKEUP as u16);
        self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        // get status
        self.get_status(slot_id);
        self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        let buf = self.get_transfer_data_indirect(evt.ptr - 16, 2);
        assert_eq!(buf, [2, 0]);
        slot_id
    }

    /// Rest host controller.
    pub fn reset_controller(&mut self, auto_run: bool) {
        // reset xhci
        self.oper_regs_write(0, USB_CMD_HCRST);
        let status = self.oper_regs_read(XHCI_OPER_REG_USBSTS as u64);
        assert!(status & USB_STS_HCE != USB_STS_HCE);
        if auto_run {
            self.init_host_controller(XHCI_PCI_SLOT_NUM, XHCI_PCI_FUN_NUM);
            self.run();
        } else {
            self.init_pci_device(XHCI_PCI_SLOT_NUM, XHCI_PCI_FUN_NUM);
        }
        // clean up the event list.
        self.event_list.clear();
    }

    // Low Level API

    pub fn oper_regs_read(&self, offset: u64) -> u32 {
        self.pci_dev
            .io_readl(self.bar_addr, XHCI_PCI_OPER_OFFSET as u64 + offset)
    }

    pub fn oper_regs_write(&mut self, offset: u64, value: u32) {
        self.pci_dev
            .io_writel(self.bar_addr, XHCI_PCI_OPER_OFFSET as u64 + offset, value);
    }

    pub fn interrupter_regs_read(&self, intr_idx: u64, offset: u64) -> u32 {
        self.pci_dev.io_readl(
            self.bar_addr,
            XHCI_PCI_RUNTIME_OFFSET as u64
                + XHCI_INTR_REG_SIZE
                + intr_idx * XHCI_INTR_REG_SIZE
                + offset,
        )
    }

    pub fn interrupter_regs_write(&mut self, intr_idx: u64, offset: u64, value: u32) {
        self.pci_dev.io_writel(
            self.bar_addr,
            XHCI_PCI_RUNTIME_OFFSET as u64
                + RUNTIME_REGS_INTERRUPT_OFFSET
                + intr_idx * XHCI_INTR_REG_SIZE
                + offset,
            value,
        );
    }

    pub fn interrupter_regs_readq(&self, intr_idx: u64, offset: u64) -> u64 {
        self.pci_dev.io_readq(
            self.bar_addr,
            XHCI_PCI_RUNTIME_OFFSET as u64
                + XHCI_INTR_REG_SIZE
                + intr_idx * XHCI_INTR_REG_SIZE
                + offset,
        )
    }

    pub fn interrupter_regs_writeq(&mut self, intr_idx: u64, offset: u64, value: u64) {
        self.pci_dev.io_writeq(
            self.bar_addr,
            XHCI_PCI_RUNTIME_OFFSET as u64
                + RUNTIME_REGS_INTERRUPT_OFFSET
                + intr_idx * XHCI_INTR_REG_SIZE
                + offset,
            value,
        );
    }

    pub fn port_regs_read(&self, port_id: u32, offset: u64) -> u32 {
        self.pci_dev.io_readl(
            self.bar_addr,
            (XHCI_PCI_PORT_OFFSET + XHCI_PCI_PORT_LENGTH * (port_id - 1) as u32) as u64 + offset,
        )
    }

    pub fn port_regs_write(&mut self, port_id: u32, offset: u64, value: u32) {
        self.pci_dev.io_writel(
            self.bar_addr,
            (XHCI_PCI_PORT_OFFSET + XHCI_PCI_PORT_LENGTH * (port_id - 1) as u32) as u64 + offset,
            value,
        );
    }

    pub fn doorbell_write(&mut self, slot_id: u32, target: u32) {
        self.pci_dev.io_writel(
            self.bar_addr,
            XHCI_PCI_DOORBELL_OFFSET as u64 + (slot_id << 2) as u64,
            target,
        );
    }

    pub fn init_pci_device(&mut self, pci_slot: u8, pci_fn: u8) {
        let devfn = pci_slot << 3 | pci_fn;
        assert!(self.find_pci_device(devfn));

        self.pci_dev.enable();
        self.bar_addr = self.pci_dev.io_map(self.bar_idx);
    }

    pub fn read_pci_config(&self) {
        let vendor_id = self.pci_dev.config_readw(PCI_VENDOR_ID);
        assert_eq!(vendor_id, PCI_VENDOR_ID_REDHAT);
        // device id
        let device_id = self.pci_dev.config_readw(PCI_DEVICE_ID);
        assert_eq!(device_id, PCI_DEVICE_ID_REDHAT_XHCI);
        // class code
        let pi = self.pci_dev.config_readb(PCI_CLASS_PI);
        assert_eq!(pi, 0x30);
        let class_code = self.pci_dev.config_readw(SUB_CLASS_CODE);
        assert_eq!(class_code, PCI_CLASS_SERIAL_USB);
    }

    pub fn read_capability(&self) {
        // Interface Version Number
        let cap = self
            .pci_dev
            .io_readl(self.bar_addr, XHCI_PCI_CAP_OFFSET as u64);
        assert!(cap & 0x01000000 == 0x01000000);
        // HCSPARAMS1
        let hcsparams1 = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x4) as u64);
        assert_eq!(hcsparams1, 0x08001040);
        // HCSPARAMS2
        let hcsparams2 = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x8) as u64);
        assert_eq!(hcsparams2, 0xf);
        // HCSPARAMS3
        let hcsparams3 = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0xc) as u64);
        assert_eq!(hcsparams3, 0);
        // HCCPARAMS1
        let hccparams1 = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x10) as u64);
        // AC64 = 1
        assert_eq!(hccparams1 & 1, 1);
        // HCCPARAMS2
        let hccparams2 = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x1c) as u64);
        assert_eq!(hccparams2, 0);
        // USB 2.0
        let usb2_version = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x20) as u64);
        assert!(usb2_version & 0x02000000 == 0x02000000);
        let usb2_name = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x24) as u64);
        assert_eq!(usb2_name, 0x20425355);
        let usb2_port = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x28) as u64);
        assert!(usb2_port & 0x400 == 0x400);
        // USB 3.0
        let usb3_version = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x30) as u64);
        assert!(usb3_version & 0x03000000 == 0x03000000);
        let usb3_name = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x34) as u64);
        assert_eq!(usb3_name, 0x20425355);
        let usb3_port = self
            .pci_dev
            .io_readl(self.bar_addr, (XHCI_PCI_CAP_OFFSET + 0x38) as u64);
        assert!(usb3_port & 0x400 == 0x400);
    }

    pub fn init_max_device_slot_enabled(&mut self) {
        // NOTE: not implement yet. use a fake value.
        let enabled_slot = USB_CONFIG_MAX_SLOTS_ENABLED & USB_CONFIG_MAX_SLOTS_EN_MASK;
        self.pci_dev.io_writel(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_CONFIG as u64,
            enabled_slot,
        );

        let config = self.pci_dev.io_readl(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_CONFIG as u64,
        );
        assert_eq!(config, enabled_slot);
    }

    pub fn init_device_context_base_address_array_pointer(&mut self) {
        let dcba = DEVICE_CONTEXT_ENTRY_SIZE * (USB_CONFIG_MAX_SLOTS_ENABLED + 1);
        let dcbaap = self.allocator.borrow_mut().alloc(dcba as u64);
        self.pci_dev.io_writeq(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_DCBAAP as u64,
            dcbaap,
        );

        let value = self.pci_dev.io_readq(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_DCBAAP as u64,
        );
        assert_eq!(value, dcbaap);
        self.xhci.dcbaap = value;
    }

    pub fn init_command_ring_dequeue_pointer(&mut self) {
        let cmd_ring_sz = TRB_SIZE as u64 * COMMAND_RING_LEN;
        let cmd_ring = self.allocator.borrow_mut().alloc(cmd_ring_sz);
        self.pci_dev
            .pci_bus
            .borrow()
            .test_state
            .borrow_mut()
            .memset(cmd_ring, cmd_ring_sz, &[0]);
        self.xhci.cmd_ring.init(cmd_ring, cmd_ring_sz);
        self.pci_dev.io_writeq(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_CMD_RING_CTRL as u64,
            cmd_ring,
        );
        // Read dequeue pointer return 0.
        let cmd_ring = self.pci_dev.io_readq(
            self.bar_addr,
            XHCI_PCI_OPER_OFFSET as u64 + XHCI_OPER_REG_CMD_RING_CTRL as u64,
        );
        assert_eq!(cmd_ring, 0);
    }

    pub fn init_interrupter(&mut self) {
        // init event ring.
        self.init_event_ring(
            PRIMARY_INTERRUPTER_ID,
            EVENT_RING_SEGMENT_TABLE_LEN,
            EVENT_RING_LEN as u32,
        );
        self.init_msix();
    }

    pub fn init_msix(&mut self) {
        self.pci_dev.enable_msix(Some(self.bar_addr));
        self.config_msix_entry = 0;
        // Random data, which is used only to check whether read and write data are consistent.
        self.config_msix_data = 0x12345678;
        self.config_msix_addr = self.allocator.borrow_mut().alloc(4);
        self.pci_dev.set_msix_vector(
            self.config_msix_entry,
            self.config_msix_addr,
            self.config_msix_data,
        );
    }

    pub fn reset_port(&mut self, port_id: u32) {
        assert!(port_id > 0);
        let port_offset =
            (XHCI_PCI_PORT_OFFSET + XHCI_PCI_PORT_LENGTH * (port_id - 1) as u32) as u64;
        self.pci_dev.io_writel(
            self.bar_addr,
            port_offset + XHCI_PORTSC_OFFSET,
            PORTSC_PR as u32,
        );
        self.oper_regs_write(XHCI_OPER_REG_USBSTS, USB_STS_PCD);
        let status = self.oper_regs_read(XHCI_OPER_REG_USBSTS);
        assert!(status & USB_STS_PCD != USB_STS_PCD);
    }

    pub fn no_op(&mut self) {
        let mut trb = TestNormalTRB::default();
        trb.set_interrupter_target(0);
        trb.set_trb_type(TRBType::CrNoop as u32);
        self.queue_command(&mut trb);
    }

    pub fn enable_slot(&mut self) {
        let mut trb = TestNormalTRB::default();
        trb.set_slot_id(0);
        trb.set_trb_type(TRBType::CrEnableSlot as u32);
        self.queue_command(&mut trb);
    }

    pub fn disable_slot(&mut self, slot_id: u32) {
        let mut trb = TestNormalTRB::default();
        trb.set_slot_id(slot_id);
        trb.set_trb_type(TRBType::CrDisableSlot as u32);
        self.queue_command(&mut trb);
    }

    // Return the address of input context to allow outside modify.
    pub fn address_device(&mut self, slot_id: u32, bsr: bool, port_number: u32) -> u64 {
        let output_ctx_addr = self.alloc_device_context();
        self.set_device_context_address(slot_id, output_ctx_addr);
        let input_ctx_addr = self.alloc_input_context();
        let mut input_ctx = XhciInputCtrlCtx::default();
        input_ctx.add_flags |= 0x3; // slot and ep0.
        self.mem_write_u32(input_ctx_addr, input_ctx.as_dwords());
        // Slot context
        let mut slot_ctx = XhciSlotCtx::default();
        slot_ctx.set_context_entry(1);
        slot_ctx.set_port_number(port_number);
        self.mem_write_u32(input_ctx_addr + 0x20, slot_ctx.as_dwords());
        // Endpoint 0 context
        let mut ep0_ctx = XhciEpCtx::default();
        let ep0_tr_ring = self
            .allocator
            .borrow_mut()
            .alloc(TRB_SIZE as u64 * TRANSFER_RING_LEN);
        ep0_ctx.set_tr_dequeue_pointer(ep0_tr_ring | 1);
        ep0_ctx.set_ep_state(0);
        ep0_ctx.set_ep_type(4);
        self.mem_write_u32(input_ctx_addr + 0x40, ep0_ctx.as_dwords());
        self.xhci.device_slot[slot_id as usize].endpoints[(CONTROL_ENDPOINT_ID - 1) as usize]
            .transfer_ring
            .init(ep0_tr_ring, TRB_SIZE as u64 * TRANSFER_RING_LEN);

        let mut trb = TestNormalTRB::default();
        trb.parameter = input_ctx_addr;
        trb.set_trb_type(TRBType::CrAddressDevice as u32);
        trb.set_slot_id(slot_id);
        trb.set_bsr(bsr);
        self.queue_command(&mut trb);
        input_ctx_addr
    }

    // Return the address of input context to allow outside modify.
    pub fn configure_endpoint(&mut self, slot_id: u32, dc: bool) -> u64 {
        let output_ctx_addr = self.get_device_context_address(slot_id);
        // Input context.
        let input_ctx_addr = self.alloc_input_context();
        let mut input_ctx = XhciInputCtrlCtx::default();
        input_ctx.add_flags |= 0x1 | 1 << HID_DEVICE_ENDPOINT_ID;
        input_ctx.drop_flags = 1 << HID_DEVICE_ENDPOINT_ID;
        self.mem_write_u32(input_ctx_addr, input_ctx.as_dwords());
        // Slot context.
        let mut slot_ctx = XhciSlotCtx::default();
        self.mem_read_u32(output_ctx_addr, slot_ctx.as_mut_dwords());
        slot_ctx.set_context_entry(4);
        self.mem_write_u32(input_ctx_addr + 0x20, slot_ctx.as_dwords());
        // Endpoint context.
        let mut ep_ctx = XhciEpCtx::default();
        let tr_ring_size = if *self
            .device_config
            .get("over_transfer_ring")
            .unwrap_or(&false)
        {
            TD_TRB_LIMIT
        } else {
            TRB_SIZE as u64 * TRANSFER_RING_LEN
        };
        let ep_tr_ring = self.allocator.borrow_mut().alloc(tr_ring_size);
        ep_ctx.set_tr_dequeue_pointer(ep_tr_ring | 1);
        ep_ctx.set_interval(10);
        ep_ctx.set_ep_state(0);
        ep_ctx.set_ep_type(7);
        self.mem_write_u32(input_ctx_addr + 0x80, ep_ctx.as_dwords());
        self.xhci.device_slot[slot_id as usize].endpoints[(HID_DEVICE_ENDPOINT_ID - 1) as usize]
            .transfer_ring
            .init(ep_tr_ring, tr_ring_size);

        let mut trb = TestNormalTRB::default();
        trb.parameter = input_ctx_addr;
        trb.set_trb_type(TRBType::CrConfigureEndpoint as u32);
        trb.set_slot_id(slot_id);
        trb.set_dc_flag(dc);
        self.queue_command(&mut trb);
        input_ctx_addr
    }

    pub fn evaluate_context(
        &mut self,
        slot_id: u32,
        max_exit_latency: u32,
        intr_target: u32,
        max_pkt_sz: u32,
    ) -> u64 {
        let input_ctx_addr = self.alloc_input_context();
        let mut input_ctx = XhciInputCtrlCtx::default();
        input_ctx.add_flags = 0x1 | 1 << CONTROL_ENDPOINT_ID;
        self.mem_write_u32(input_ctx_addr, input_ctx.as_dwords());
        // Slot context.
        let mut slot_ctx = XhciSlotCtx::default();
        slot_ctx.set_max_exit_latency(max_exit_latency);
        slot_ctx.set_interrupter_target(intr_target);
        self.mem_write_u32(input_ctx_addr + 0x20, slot_ctx.as_dwords());
        // Endpoint 0 context.
        let mut ep0_ctx = XhciEpCtx::default();
        ep0_ctx.set_max_packet_size(max_pkt_sz);
        self.mem_write_u32(input_ctx_addr + 0x40, ep0_ctx.as_dwords());

        let mut trb = TestNormalTRB::default();
        trb.set_pointer(input_ctx_addr);
        trb.set_slot_id(slot_id);
        trb.set_trb_type(TRBType::CrEvaluateContext as u32);
        self.queue_command(&mut trb);
        input_ctx_addr
    }

    pub fn stop_endpoint(&mut self, slot_id: u32, ep_id: u32) {
        let mut trb = TestNormalTRB::default();
        trb.set_slot_id(slot_id);
        trb.set_ep_id(ep_id);
        // NOTE: Suspend flag not supported.
        trb.set_trb_type(TRBType::CrStopEndpoint as u32);
        self.queue_command(&mut trb);
    }

    pub fn reset_endpoint(&mut self, slot_id: u32, ep_id: u32) {
        let mut trb = TestNormalTRB::default();
        trb.set_slot_id(slot_id);
        trb.set_ep_id(ep_id);
        // NOTE: TSP flag not supported.
        trb.set_trb_type(TRBType::CrResetEndpoint as u32);
        self.queue_command(&mut trb);
    }

    pub fn set_tr_dequeue(&mut self, ptr: u64, slot_id: u32, ep_id: u32) {
        let mut trb = TestNormalTRB::default();
        if self.get_cycle_bit(slot_id, ep_id) {
            trb.set_pointer(ptr | 1);
        } else {
            trb.set_pointer(ptr);
        }
        trb.set_slot_id(slot_id);
        trb.set_ep_id(ep_id);
        trb.set_trb_type(TRBType::CrSetTrDequeue as u32);
        self.queue_command(&mut trb);
        // update transfer dequeue pointer in the ring together.
        self.set_transfer_pointer(ptr, slot_id, ep_id);
    }

    pub fn reset_device(&mut self, slot_id: u32) {
        let mut trb = TestNormalTRB::default();
        trb.set_slot_id(slot_id);
        trb.set_trb_type(TRBType::CrResetDevice as u32);
        self.queue_command(&mut trb);
    }

    pub fn fetch_event(&mut self, intr_idx: usize) -> Option<TestXhciEvent> {
        const MSIX_LIMIT: u32 = 4;
        for _ in 0..MSIX_LIMIT {
            if self.has_msix(self.config_msix_addr, self.config_msix_data) {
                for _ in 0..EVENT_RING_LEN {
                    let ptr = self.xhci.interrupter[intr_idx].er_pointer;
                    let trb = self.read_event(ptr);
                    let event = trb.to_xhci_event();
                    if (event.flags & TRB_C == TRB_C) == self.xhci.interrupter[intr_idx].cycle_bit {
                        let event = trb.to_xhci_event();
                        self.increase_event_ring(intr_idx);
                        self.interrupter_regs_writeq(
                            intr_idx as u64,
                            XHCI_INTR_REG_ERDP_LO,
                            self.xhci.interrupter[intr_idx].er_pointer | ERDP_EHB as u64,
                        );
                        self.event_list.push_back(event);
                    } else {
                        break;
                    }
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.event_list.pop_front()
    }

    pub fn queue_device_reqeust(&mut self, slot_id: u32, device_req: &UsbDeviceRequest) {
        // Setup Stage.
        let mut setup_trb = TestNormalTRB::generate_setup_td(&device_req);
        self.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut setup_trb);
        // Data Stage.
        let ptr = self.allocator.borrow_mut().alloc(device_req.length as u64);
        let in_dir =
            device_req.request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
        let mut data_trb = TestNormalTRB::generate_data_td(ptr, device_req.length, in_dir);
        self.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut data_trb);
        // Status Stage.
        let mut status_trb = TestNormalTRB::generate_status_td(false);
        self.queue_trb(slot_id, CONTROL_ENDPOINT_ID, &mut status_trb);
    }

    // Queue TD with multi-TRB.
    pub fn queue_td_by_iovec(
        &mut self,
        slot_id: u32,
        ep_id: u32,
        iovecs: &mut Vec<TestIovec>,
        dir: bool,
    ) {
        for i in 0..iovecs.len() {
            let iovec = &mut iovecs[i];
            let mut trb = TestNormalTRB::default();
            if iovec.event_data {
                trb.set_pointer(iovec.io_base);
                trb.set_trb_type(TRBType::TrEvdata as u32);
            } else {
                if iovec.direct {
                    trb.set_idt_flag(true);
                    iovec.io_base = self.get_transfer_pointer(slot_id, ep_id);
                }
                trb.set_pointer(iovec.io_base);
                trb.set_trb_transfer_length(iovec.io_len as u32);
                trb.set_dir_flag(dir);
                trb.set_trb_type(TRBType::TrNormal as u32);
            }
            if i != iovecs.len() - 1 {
                trb.set_ch_flag(true);
            } else {
                trb.set_ioc_flag(true);
            }
            trb.set_cycle_bit(self.get_cycle_bit(slot_id, ep_id));
            let en_ptr = self.get_transfer_pointer(slot_id, ep_id);
            self.write_trb(en_ptr, &trb);
            self.increase_transfer_ring(slot_id, ep_id, 1);
        }
    }

    // Queue TD (single TRB) with IDT=1
    pub fn queue_direct_td(&mut self, slot_id: u32, ep_id: u32, len: u64) {
        let mut trb = TestNormalTRB::default();
        trb.set_ioc_flag(true);
        trb.set_isp_flag(true);
        trb.set_idt_flag(true);
        trb.set_trb_type(TRBType::TrNormal as u32);
        trb.set_trb_transfer_length(len as u32);
        self.queue_trb(slot_id, ep_id, &mut trb);
    }

    // Queue multi-TD  with IDT=1
    pub fn queue_multi_direct_td(&mut self, slot_id: u32, ep_id: u32, sz: u64, num: usize) {
        for _ in 0..num {
            self.queue_direct_td(slot_id, ep_id, sz);
        }
    }

    // Queue TD (single TRB)
    pub fn queue_indirect_td(&mut self, slot_id: u32, ep_id: u32, sz: u64) -> u64 {
        let mut trb = TestNormalTRB::default();
        let ptr = self.allocator.borrow_mut().alloc(sz);
        self.pci_dev
            .pci_bus
            .borrow()
            .test_state
            .borrow_mut()
            .memset(ptr, sz, &[0]);
        trb.set_pointer(ptr);
        trb.set_ioc_flag(true);
        trb.set_isp_flag(true);
        trb.set_trb_type(TRBType::TrNormal as u32);
        trb.set_trb_transfer_length(sz as u32);
        self.queue_trb(slot_id, ep_id, &mut trb);
        ptr
    }

    // Queue multi-TD
    pub fn queue_multi_indirect_td(&mut self, slot_id: u32, ep_id: u32, sz: u64, num: usize) {
        for _ in 0..num {
            self.queue_indirect_td(slot_id, ep_id, sz);
        }
    }

    pub fn get_transfer_data_by_iovec(&self, iovecs: &Vec<TestIovec>) -> Vec<u8> {
        let mut buf = Vec::new();
        for iov in iovecs.iter() {
            let tmp = self.mem_read(iov.io_base, iov.io_len);
            for e in tmp.iter() {
                buf.push(*e);
            }
        }
        buf
    }

    // Read data from parameter directly.
    pub fn get_transfer_data_direct(&self, addr: u64, len: u64) -> Vec<u8> {
        let buf = self.mem_read(addr, len as usize);
        buf
    }

    // Read data from parameter as address.
    pub fn get_transfer_data_indirect(&self, addr: u64, len: u64) -> Vec<u8> {
        let buf = self.mem_read(addr, 8);
        let mem = LittleEndian::read_u64(&buf);
        let buf = self.mem_read(mem, len as usize);
        buf
    }

    pub fn get_transfer_data_indirect_with_offset(
        &self,
        addr: u64,
        len: usize,
        offset: u64,
    ) -> Vec<u8> {
        let buf = self.mem_read(addr, 8);
        let mem = LittleEndian::read_u64(&buf);
        let buf = self.mem_read(mem + offset, len);
        buf
    }

    pub fn get_command_pointer(&self) -> u64 {
        self.xhci.cmd_ring.pointer
    }

    pub fn get_transfer_pointer(&self, slot_id: u32, ep_id: u32) -> u64 {
        self.xhci.device_slot[slot_id as usize].endpoints[(ep_id - 1) as usize]
            .transfer_ring
            .pointer
            & !0xf
    }

    pub fn get_event_pointer(&self, intr_idx: usize) -> u64 {
        self.xhci.interrupter[intr_idx].er_pointer
    }

    pub fn set_transfer_pointer(&mut self, ptr: u64, slot_id: u32, ep_id: u32) {
        self.xhci.device_slot[slot_id as usize].endpoints[(ep_id - 1) as usize]
            .transfer_ring
            .pointer = ptr;
    }

    pub fn get_slot_context(&self, slot_id: u32) -> XhciSlotCtx {
        let output_ctx_addr = self.get_device_context_address(slot_id);
        let mut slot_ctx = XhciSlotCtx::default();
        self.mem_read_u32(output_ctx_addr, slot_ctx.as_mut_dwords());
        slot_ctx
    }

    pub fn get_endpoint_context(&self, slot_id: u32, ep_id: u32) -> XhciEpCtx {
        let output_ctx_addr = self.get_device_context_address(slot_id);
        let mut ep_ctx = XhciEpCtx::default();
        self.mem_read_u32(
            output_ctx_addr + 0x20 * ep_id as u64,
            ep_ctx.as_mut_dwords(),
        );
        ep_ctx
    }

    /// Queue one TRB to command ring.
    pub fn queue_command(&mut self, trb: &mut TestNormalTRB) {
        trb.set_cycle_bit(self.xhci.cmd_ring.cycle_bit);
        self.write_trb(self.xhci.cmd_ring.pointer, trb);
        self.increase_command_ring();
        if *self
            .device_config
            .get("command_auto_doorbell")
            .unwrap_or(&false)
        {
            self.doorbell_write(0, 0);
        }
    }

    /// Queue one TRB to transfer ring.
    pub fn queue_trb(&mut self, slot_id: u32, ep_id: u32, trb: &mut TestNormalTRB) {
        if trb.force_cycle {
            trb.set_cycle_bit(!self.get_cycle_bit(slot_id, ep_id));
        } else {
            trb.set_cycle_bit(self.get_cycle_bit(slot_id, ep_id));
        }
        let en_ptr = self.get_transfer_pointer(slot_id, ep_id);
        self.write_trb(en_ptr, &trb);
        self.increase_transfer_ring(slot_id, ep_id, 1);
    }

    pub fn queue_link_trb(&mut self, slot_id: u32, ep_id: u32, ptr: u64, tc: bool) {
        let mut trb = TestNormalTRB::default();
        trb.parameter = ptr & !0xf;
        trb.set_trb_type(TRBType::TrLink as u32);
        trb.set_toggle_cycle(tc);
        // Command ring
        if slot_id == 0 {
            trb.set_cycle_bit(self.xhci.cmd_ring.cycle_bit);
            self.write_trb(self.xhci.cmd_ring.pointer, &trb);
            if tc {
                self.xhci.cmd_ring.cycle_bit = !self.xhci.cmd_ring.cycle_bit;
            }
            self.xhci.cmd_ring.update_pointer(trb.parameter);
        } else {
            trb.set_cycle_bit(
                self.xhci.device_slot[slot_id as usize].endpoints[(ep_id - 1) as usize]
                    .transfer_ring
                    .cycle_bit,
            );
            self.write_trb(self.get_transfer_pointer(slot_id, ep_id), &trb);
            if tc {
                self.xhci.device_slot[slot_id as usize].endpoints[(ep_id - 1) as usize]
                    .transfer_ring
                    .cycle_bit = !self.xhci.device_slot[slot_id as usize].endpoints
                    [(ep_id - 1) as usize]
                    .transfer_ring
                    .cycle_bit;
            }
            self.set_transfer_pointer(ptr, slot_id, ep_id);
        }
    }

    pub fn init_event_ring(&mut self, intr_idx: usize, erstsz: u32, ersz: u32) {
        // ERSTSZ
        self.interrupter_regs_write(intr_idx as u64, XHCI_INTR_REG_ERSTSZ, erstsz);
        self.xhci.interrupter[intr_idx].erstsz = erstsz;
        let data = self.interrupter_regs_read(intr_idx as u64, XHCI_INTR_REG_ERSTSZ);
        assert_eq!(data, erstsz);
        // ERSTBA
        let table_size = EVENT_RING_SEGMENT_TABLE_ENTRY_SIZE * erstsz;
        let evt_ring_seg_table = self.allocator.borrow_mut().alloc(table_size as u64);
        self.xhci.interrupter[intr_idx].erstba = evt_ring_seg_table;
        // NOTE: Only support one Segment now.
        let mut seg = TestEventRingSegment::new();
        let evt_ring_sz = (TRB_SIZE * ersz) as u64;
        let evt_ring = self.allocator.borrow_mut().alloc(evt_ring_sz);
        seg.init(evt_ring, ersz);
        self.pci_dev
            .pci_bus
            .borrow()
            .test_state
            .borrow_mut()
            .memset(evt_ring, evt_ring_sz, &[0]);

        let mut buf = [0_u8; TRB_SIZE as usize];
        LittleEndian::write_u64(&mut buf, seg.addr);
        LittleEndian::write_u32(&mut buf[8..], seg.size);
        LittleEndian::write_u32(&mut buf[12..], seg.reserved);
        self.mem_write(self.xhci.interrupter[intr_idx].erstba, &buf);
        // init event ring
        self.load_event_segment(intr_idx);
        self.xhci.interrupter[intr_idx].cycle_bit = true;

        // Write ERSTBA last, because write it will trigger reset event ring.
        self.interrupter_regs_writeq(intr_idx as u64, XHCI_INTR_REG_ERSTBA_LO, evt_ring_seg_table);
        let data = self.interrupter_regs_readq(intr_idx as u64, XHCI_INTR_REG_ERSTBA_LO);
        assert_eq!(data, evt_ring_seg_table & !0x3f);
        // Write ERDP
        self.interrupter_regs_writeq(
            intr_idx as u64,
            XHCI_INTR_REG_ERDP_LO,
            self.get_event_pointer(intr_idx),
        );
        let data = self.interrupter_regs_readq(intr_idx as u64, XHCI_INTR_REG_ERDP_LO);
        assert_eq!(data, self.get_event_pointer(intr_idx));

        // enable USB_CMD_INTE
        let value = self.oper_regs_read(XHCI_OPER_REG_USBCMD as u64);
        self.oper_regs_write(XHCI_OPER_REG_USBCMD, value | USB_CMD_INTE);
        // enable INTE
        let value = self.interrupter_regs_read(intr_idx as u64, XHCI_INTR_REG_IMAN);
        self.interrupter_regs_write(intr_idx as u64, XHCI_INTR_REG_IMAN, value | IMAN_IE);
    }

    // Fake init memory.
    fn init_memory(&mut self) {
        let page_size = self.oper_regs_read(XHCI_OPER_REG_PAGESIZE);
        assert_eq!(page_size, 1);
    }

    fn get_cycle_bit(&self, slot_id: u32, ep_id: u32) -> bool {
        self.xhci.device_slot[slot_id as usize].endpoints[(ep_id - 1) as usize]
            .transfer_ring
            .cycle_bit
    }

    fn increase_event_ring(&mut self, intr_idx: usize) {
        self.xhci.interrupter[intr_idx].trb_count -= 1;
        self.xhci.interrupter[intr_idx].er_pointer += TRB_SIZE as u64;
        if self.xhci.interrupter[intr_idx].trb_count == 0 {
            self.xhci.interrupter[intr_idx].segment_index += 1;
            if self.xhci.interrupter[intr_idx].segment_index
                == self.xhci.interrupter[intr_idx].erstsz
            {
                self.xhci.interrupter[intr_idx].cycle_bit =
                    !self.xhci.interrupter[intr_idx].cycle_bit;
                self.xhci.interrupter[intr_idx].segment_index = 0;
            }
            self.load_event_segment(intr_idx);
        }
    }

    fn load_event_segment(&mut self, intr_idx: usize) {
        let idx = self.xhci.interrupter[intr_idx].segment_index;
        let evt_seg = self.read_segment_entry(intr_idx, idx);
        self.xhci.interrupter[intr_idx].er_pointer = evt_seg.addr;
        self.xhci.interrupter[intr_idx].trb_count = evt_seg.size;
    }

    fn read_segment_entry(&self, intr_idx: usize, index: u32) -> TestEventRingSegment {
        assert!(index <= self.xhci.interrupter[intr_idx].erstsz);
        let addr = self.xhci.interrupter[intr_idx].erstba + (TRB_SIZE * index) as u64;
        let evt_seg_buf = self.mem_read(addr, TRB_SIZE as usize);
        let mut evt_seg = TestEventRingSegment::new();
        evt_seg.addr = LittleEndian::read_u64(&evt_seg_buf);
        evt_seg.size = LittleEndian::read_u32(&evt_seg_buf[8..]);
        evt_seg.reserved = LittleEndian::read_u32(&evt_seg_buf[12..]);
        evt_seg
    }

    fn set_devfn(&mut self, devfn: u8) {
        self.pci_dev.devfn = devfn;
    }

    fn find_pci_device(&mut self, devfn: u8) -> bool {
        self.set_devfn(devfn);
        if self.pci_dev.config_readw(PCI_VENDOR_ID) == 0xFFFF {
            return false;
        }
        true
    }

    fn set_device_context_address(&mut self, slot_id: u32, addr: u64) {
        let device_ctx_addr = self.xhci.dcbaap + (slot_id * DEVICE_CONTEXT_ENTRY_SIZE) as u64;
        let mut buf = [0_u8; 8];
        LittleEndian::write_u64(&mut buf, addr);
        self.mem_write(device_ctx_addr, &buf);
    }

    fn get_device_context_address(&self, slot_id: u32) -> u64 {
        let device_ctx_addr = self.xhci.dcbaap + (slot_id * DEVICE_CONTEXT_ENTRY_SIZE) as u64;
        let mut buf = self.mem_read(device_ctx_addr, 8);
        let addr = LittleEndian::read_u64(&mut buf);
        addr
    }

    fn has_msix(&mut self, msix_addr: u64, msix_data: u32) -> bool {
        self.pci_dev
            .pci_bus
            .borrow()
            .test_state
            .borrow()
            .query_msix(msix_addr, msix_data)
    }

    fn increase_command_ring(&mut self) {
        let cmd_ring = self.xhci.cmd_ring;
        if cmd_ring.pointer + TRB_SIZE as u64 >= cmd_ring.start + cmd_ring.size * TRB_SIZE as u64 {
            self.queue_link_trb(0, 0, cmd_ring.start, true);
        }
        self.xhci.cmd_ring.pointer += TRB_SIZE as u64;
    }

    fn increase_transfer_ring(&mut self, slot_id: u32, ep_id: u32, len: u64) {
        let tr_ring =
            self.xhci.device_slot[slot_id as usize].endpoints[(ep_id - 1) as usize].transfer_ring;
        if tr_ring.pointer + TRB_SIZE as u64 >= tr_ring.start + tr_ring.size * TRB_SIZE as u64 {
            self.queue_link_trb(slot_id, ep_id, tr_ring.start, true);
        }
        self.xhci.device_slot[slot_id as usize].endpoints[(ep_id - 1) as usize]
            .transfer_ring
            .increase_pointer(TRB_SIZE as u64 * len);
    }

    fn write_trb(&mut self, addr: u64, trb: &TestNormalTRB) {
        let mut buf = [0_u8; TRB_SIZE as usize];
        LittleEndian::write_u64(&mut buf, trb.parameter);
        LittleEndian::write_u32(&mut buf[8..], trb.status);
        LittleEndian::write_u32(&mut buf[12..], trb.control);
        self.mem_write(addr, &buf);
    }

    fn read_event(&self, addr: u64) -> TestNormalTRB {
        let buf = self.mem_read(addr, 16);
        let mut trb = TestNormalTRB::default();
        trb.parameter = LittleEndian::read_u64(&buf);
        trb.status = LittleEndian::read_u32(&buf[8..]);
        trb.control = LittleEndian::read_u32(&buf[12..]);
        trb
    }

    fn alloc_input_context(&mut self) -> u64 {
        let input_ctx_addr = self.allocator.borrow_mut().alloc(INPUT_CONTEXT_SIZE);
        input_ctx_addr
    }

    fn alloc_device_context(&mut self) -> u64 {
        let output_ctx_addr = self.allocator.borrow_mut().alloc(DEVICE_CONTEXT_SIZE);
        output_ctx_addr
    }
}

// Descriptor
impl TestXhciPciDevice {
    pub fn get_usb_descriptor(&mut self, slot_id: u32) {
        // device descriptor
        self.get_device_descriptor(slot_id);
        self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        let buf =
            self.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, USB_DT_DEVICE_SIZE as u64);
        // descriptor type
        assert_eq!(buf[1], USB_DESCRIPTOR_TYPE_DEVICE);
        // bcdUSB
        assert_eq!(buf[3..5], [1, 0]);
        // config descriptor
        self.get_config_descriptor(slot_id);
        self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        let addr = evt.ptr - TRB_SIZE as u64;
        let mut offset = 0;
        let buf =
            self.get_transfer_data_indirect_with_offset(addr, USB_DT_CONFIG_SIZE as usize, offset);
        // descriptor type
        assert_eq!(buf[1], USB_DESCRIPTOR_TYPE_CONFIG);
        // configure value
        assert_eq!(buf[5], 1);
        offset += USB_DT_CONFIG_SIZE as u64;
        let buf = self.get_transfer_data_indirect_with_offset(
            addr,
            USB_DT_INTERFACE_SIZE as usize,
            offset,
        );
        // descriptor type
        assert_eq!(buf[1], USB_DESCRIPTOR_TYPE_INTERFACE);
        // hid class
        assert_eq!(buf[5], 3);
        // hid descriptor
        offset += USB_DT_INTERFACE_SIZE as u64;
        if *self.device_config.get("tablet").unwrap_or(&false) {
            let buf = self.get_transfer_data_indirect_with_offset(addr, 9, offset);
            assert_eq!(buf, [0x9, 0x21, 0x01, 0x0, 0x0, 0x01, 0x22, 74, 0x0]);
        } else if *self.device_config.get("keyboard").unwrap_or(&false) {
            let buf = self.get_transfer_data_indirect_with_offset(addr, 9, offset);
            assert_eq!(buf, [0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x3f, 0]);
        }
        offset += 9;
        // endpoint descriptor
        let buf = self.get_transfer_data_indirect_with_offset(
            addr,
            USB_DT_ENDPOINT_SIZE as usize,
            offset,
        );
        // descriptor type
        assert_eq!(buf[1], USB_DESCRIPTOR_TYPE_ENDPOINT);
        // endpoint address
        assert_eq!(buf[2], USB_DIRECTION_DEVICE_TO_HOST | 0x1);
        // string descriptor
        self.get_string_descriptor(slot_id, 0);
        self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        let buf = self.get_transfer_data_indirect(evt.ptr - 16, 4);
        // Language ID
        assert_eq!(buf, [4, 3, 9, 4]);
        self.get_string_descriptor(slot_id, 3);
        self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::ShortPacket as u32);
        if *self.device_config.get("tablet").unwrap_or(&false) {
            let hid_str = "HID Tablet";
            let len = hid_str.len() * 2 + 2;
            let buf = self.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, len as u64);
            for i in 0..hid_str.len() {
                assert_eq!(buf[2 * i + 2], hid_str.as_bytes()[i]);
            }
        } else if *self.device_config.get("keyboard").unwrap_or(&false) {
            let hid_str = "HID Keyboard";
            let len = hid_str.len() * 2 + 2;
            let buf = self.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, len as u64);
            for i in 0..hid_str.len() {
                assert_eq!(buf[2 * i + 2], hid_str.as_bytes()[i]);
            }
        }
    }

    pub fn check_hid_report_descriptor(&mut self, slot_id: u32) {
        if *self.device_config.get("keyboard").unwrap_or(&false) {
            self.get_hid_report_descriptor(slot_id, 63);
            self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
            let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let buf = self.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, 63);
            assert_eq!(
                buf,
                [
                    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x75, 0x01, 0x95, 0x08, 0x05, 0x07, 0x19,
                    0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08,
                    0x81, 0x01, 0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91,
                    0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00,
                    0x25, 0xff, 0x05, 0x07, 0x19, 0x00, 0x29, 0xff, 0x81, 0x00, 0xc0
                ]
            );
        } else if *self.device_config.get("tablet").unwrap_or(&false) {
            self.get_hid_report_descriptor(slot_id, 74);
            self.doorbell_write(slot_id, CONTROL_ENDPOINT_ID);
            let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
            assert_eq!(evt.ccode, TRBCCode::Success as u32);
            let buf = self.get_transfer_data_indirect(evt.ptr - TRB_SIZE as u64, 74);
            assert_eq!(
                buf,
                [
                    0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09, 0x19,
                    0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02,
                    0x95, 0x01, 0x75, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15,
                    0x00, 0x26, 0xff, 0x7f, 0x35, 0x00, 0x46, 0xff, 0x7f, 0x75, 0x10, 0x95, 0x02,
                    0x81, 0x02, 0x05, 0x01, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x35, 0x00, 0x45,
                    0x00, 0x75, 0x08, 0x95, 0x01, 0x81, 0x06, 0xc0, 0xc0,
                ]
            );
        }
    }

    pub fn get_device_descriptor(&mut self, slot_id: u32) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_IN_REQUEST,
            request: USB_REQUEST_GET_DESCRIPTOR,
            value: (USB_DT_DEVICE as u16) << 8,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_config_descriptor(&mut self, slot_id: u32) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_IN_REQUEST,
            request: USB_REQUEST_GET_DESCRIPTOR,
            value: (USB_DT_CONFIGURATION as u16) << 8,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_string_descriptor(&mut self, slot_id: u32, index: u16) {
        let buf_len = 128;
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_IN_REQUEST,
            request: USB_REQUEST_GET_DESCRIPTOR,
            value: (USB_DT_STRING as u16) << 8 | index,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_status(&mut self, slot_id: u32) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_IN_REQUEST,
            request: USB_REQUEST_GET_STATUS,
            value: 0,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_configuration(&mut self, slot_id: u32) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_IN_REQUEST,
            request: USB_REQUEST_GET_CONFIGURATION,
            value: 0,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn set_configuration(&mut self, slot_id: u32, v: u16) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_OUT_REQUEST,
            request: USB_REQUEST_SET_CONFIGURATION,
            value: v,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn clear_feature(&mut self, slot_id: u32, v: u16) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_OUT_REQUEST,
            request: USB_REQUEST_CLEAR_FEATURE,
            value: v,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn set_feature(&mut self, slot_id: u32, v: u16) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_OUT_REQUEST,
            request: USB_REQUEST_SET_FEATURE,
            value: v,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_interface(&mut self, slot_id: u32, index: u16) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_IN_REQUEST,
            request: USB_REQUEST_GET_INTERFACE,
            value: 0,
            index: index,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn set_interface(&mut self, slot_id: u32, v: u16, index: u16) {
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_OUT_REQUEST,
            request: USB_REQUEST_SET_INTERFACE,
            value: v,
            index: index,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_hid_report_descriptor(&mut self, slot_id: u32, len: u16) {
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_IN_REQUEST,
            request: USB_REQUEST_GET_DESCRIPTOR,
            value: 0x22 << 8,
            index: 0,
            length: len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_report(&mut self, slot_id: u32) {
        let buf_len = 8;
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_CLASS_IN_REQUEST,
            request: HID_GET_REPORT,
            value: 0,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn set_report(&mut self, slot_id: u32, v: u16) {
        // NOTE: set with data, and keyboard not implement yet.
        let buf_len = 64;
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_CLASS_OUT_REQUEST,
            request: HID_SET_REPORT,
            value: v,
            index: 0,
            length: buf_len,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_protocol(&mut self, slot_id: u32) {
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_CLASS_IN_REQUEST,
            request: HID_GET_PROTOCOL,
            value: 0,
            index: 0,
            length: 1,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn set_protocol(&mut self, slot_id: u32, v: u16) {
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_CLASS_OUT_REQUEST,
            request: HID_SET_PROTOCOL,
            value: v,
            index: 0,
            length: 0,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn get_idle(&mut self, slot_id: u32) {
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_CLASS_IN_REQUEST,
            request: HID_GET_IDLE,
            value: 0,
            index: 0,
            length: 1,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }

    pub fn set_idle(&mut self, slot_id: u32, v: u16) {
        let device_req = UsbDeviceRequest {
            request_type: USB_INTERFACE_CLASS_OUT_REQUEST,
            request: HID_SET_IDLE,
            value: v,
            index: 0,
            length: 0,
        };
        self.queue_device_reqeust(slot_id, &device_req);
    }
}

// Device operation
impl TestXhciPciDevice {
    pub fn test_keyboard_event(&mut self, slot_id: u32, test_state: Rc<RefCell<TestState>>) {
        qmp_send_key_event(test_state.borrow_mut(), 57, true);
        qmp_send_key_event(test_state.borrow_mut(), 57, false);
        self.queue_multi_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_KEYBOARD_LEN, 2);
        self.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let buf = self.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
        assert_eq!(buf, [0, 0, 44, 0, 0, 0, 0, 0]);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let buf = self.get_transfer_data_indirect(evt.ptr, HID_KEYBOARD_LEN);
        assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    pub fn test_pointer_event(&mut self, slot_id: u32, test_state: Rc<RefCell<TestState>>) {
        qmp_send_pointer_event(test_state.borrow_mut(), 100, 200, 0);
        qmp_send_pointer_event(test_state.borrow_mut(), 200, 100, 1);
        self.queue_multi_indirect_td(slot_id, HID_DEVICE_ENDPOINT_ID, HID_POINTER_LEN, 2);
        self.doorbell_write(slot_id, HID_DEVICE_ENDPOINT_ID);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let buf = self.get_transfer_data_indirect(evt.ptr, HID_POINTER_LEN);
        assert_eq!(buf, [0, 100, 0, 200, 0, 0]);
        let evt = self.fetch_event(PRIMARY_INTERRUPTER_ID).unwrap();
        assert_eq!(evt.ccode, TRBCCode::Success as u32);
        let buf = self.get_transfer_data_indirect(evt.ptr, HID_POINTER_LEN);
        assert_eq!(buf, [1, 200, 0, 100, 0, 0]);
    }
}

// Memory operation
impl TestXhciPciDevice {
    pub fn mem_read_u32(&self, addr: u64, buf: &mut [u32]) {
        let vec_len = size_of::<u32>() * buf.len();
        let tmp = self.mem_read(addr, vec_len);
        for i in 0..buf.len() {
            buf[i] = LittleEndian::read_u32(&tmp[(size_of::<u32>() * i)..]);
        }
    }

    pub fn mem_write_u32(&self, addr: u64, buf: &[u32]) {
        let vec_len = size_of::<u32>() * buf.len();
        let mut vec = vec![0_u8; vec_len];
        let tmp = vec.as_mut_slice();
        for i in 0..buf.len() {
            LittleEndian::write_u32(&mut tmp[(size_of::<u32>() * i)..], buf[i]);
        }
        self.mem_write(addr, tmp);
    }

    pub fn mem_read(&self, addr: u64, len: usize) -> Vec<u8> {
        self.pci_dev
            .pci_bus
            .borrow()
            .test_state
            .borrow_mut()
            .memread(addr, len as u64)
    }

    pub fn mem_write(&self, addr: u64, buf: &[u8]) {
        self.pci_dev
            .pci_bus
            .borrow()
            .test_state
            .borrow_mut()
            .memwrite(addr, buf);
    }
}

pub struct TestUsbBuilder {
    args: Vec<String>,
    config: HashMap<String, bool>,
}

impl TestUsbBuilder {
    pub fn new() -> Self {
        let mut args = Vec::new();
        let machine: Vec<&str> = "-machine virt".split(' ').collect();
        let mut arg = machine.into_iter().map(|s| s.to_string()).collect();
        args.append(&mut arg);
        Self {
            args,
            config: HashMap::new(),
        }
    }

    pub fn with_xhci(mut self, id: &str) -> Self {
        let args = format!(
            "-device nec-usb-xhci,id={},bus=pcie.0,addr={}",
            id, XHCI_PCI_SLOT_NUM
        );
        let args: Vec<&str> = args[..].split(' ').collect();
        let mut args = args.into_iter().map(|s| s.to_string()).collect();
        self.args.append(&mut args);
        self
    }

    pub fn with_usb_keyboard(mut self, id: &str) -> Self {
        let args = format!("-device usb-kbd,id={}", id);
        let args: Vec<&str> = args[..].split(' ').collect();
        let mut args = args.into_iter().map(|s| s.to_string()).collect();
        self.args.append(&mut args);
        self.config.insert(String::from("keyboard"), true);
        self
    }

    pub fn with_usb_tablet(mut self, id: &str) -> Self {
        let args = format!("-device usb-tablet,id={}", id);
        let args: Vec<&str> = args[..].split(' ').collect();
        let mut args = args.into_iter().map(|s| s.to_string()).collect();
        self.args.append(&mut args);
        self.config.insert(String::from("tablet"), true);
        self
    }

    pub fn with_config(mut self, k: &str, v: bool) -> Self {
        self.config.insert(k.to_string(), v);
        self
    }

    pub fn build(
        &mut self,
    ) -> (
        Rc<RefCell<TestXhciPciDevice>>,
        Rc<RefCell<TestState>>,
        Rc<RefCell<GuestAllocator>>,
    ) {
        let args = self.args.iter().map(AsRef::as_ref).collect();
        let test_state = Rc::new(RefCell::new(test_init(args)));
        let machine = TestStdMachine::new(test_state.clone());
        let allocator = machine.allocator.clone();

        let xhci = Rc::new(RefCell::new(TestXhciPciDevice::new(
            machine.pci_bus,
            allocator.clone(),
        )));

        for (k, v) in self.config.iter() {
            xhci.borrow_mut().device_config.insert(k.clone(), *v);
        }

        if *self.config.get("auto_run").unwrap_or(&false) {
            // init host controller.
            let mut xhci = xhci.borrow_mut();
            xhci.init_host_controller(XHCI_PCI_SLOT_NUM, XHCI_PCI_FUN_NUM);
            xhci.run();
        } else {
            // only init pci, let testcase init controller.
            let mut xhci = xhci.borrow_mut();
            xhci.init_pci_device(XHCI_PCI_SLOT_NUM, XHCI_PCI_FUN_NUM);
        }

        (xhci, test_state, allocator)
    }
}

// Helper
pub fn qmp_send_key_event(test_state: RefMut<TestState>, v: u32, down: bool) {
    let value_str = format!("{},{}", v, if down { 1 } else { 0 });
    let mut str =
        "{\"execute\": \"input_event\", \"arguments\": { \"key\": \"keyboard\", \"value\":\""
            .to_string();
    str += &value_str;
    str += "\" }}";
    test_state.qmp(&str);
}

pub fn qmp_send_multi_key_event(test_state: Rc<RefCell<TestState>>, key_list: &[u32], down: bool) {
    for item in key_list {
        qmp_send_key_event(test_state.borrow_mut(), *item, down);
    }
}

pub fn qmp_send_pointer_event(test_state: RefMut<TestState>, x: i32, y: i32, btn: i32) {
    let value_str = format!("{},{},{}", x, y, btn);
    let mut str =
        "{\"execute\": \"input_event\", \"arguments\": { \"key\": \"pointer\", \"value\":\""
            .to_string();
    str += &value_str;
    str += "\" }}";
    test_state.qmp(&str);
}

pub fn clear_iovec(test_state: RefMut<TestState>, iovecs: &Vec<TestIovec>) {
    for iov in iovecs.iter() {
        test_state.memwrite(iov.io_base, &vec![0; iov.io_len as usize]);
    }
}
