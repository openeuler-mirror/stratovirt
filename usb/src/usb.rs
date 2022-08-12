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

use std::{
    collections::LinkedList,
    sync::{Arc, Mutex, Weak},
};

use super::errors::Result;
use crate::xhci::xhci_controller::XhciDevice;

/// USB packet return status.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UsbPacketStatus {
    Success,
    NoDev,
    Nak,
    Stall,
    Babble,
    IoError,
    Async,
}

/// USB packet setup state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SetupState {
    Idle,
    Setup,
    Data,
    Ack,
    Parameter,
}

/// USB device state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UsbDeviceState {
    Removed,
    Attached,
    Powered,
    Default,
    Address,
    Configured,
    Suspended,
}

/// USB request used to transfer to USB device.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UsbDeviceRequest {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

/// The data transmission channel.
#[derive(Default)]
pub struct UsbEndpoint {
    pub nr: u8,
    pub pid: u8,
    pub usb_type: u8,
    pub ifnum: u8,
    pub max_packet_size: u32,
    pub pipeline: bool,
    pub halted: bool,
    pub dev: Option<Weak<Mutex<dyn UsbDeviceOps>>>,
    pub queue: LinkedList<UsbPacket>,
}

impl UsbEndpoint {
    pub fn new(nr: u8, pid: u8, usb_type: u8, ifnum: u8, max_packet_size: u32) -> Self {
        Self {
            nr,
            pid,
            usb_type,
            ifnum,
            max_packet_size,
            pipeline: false,
            halted: false,
            dev: None,
            queue: LinkedList::new(),
        }
    }
}

/// USB port which can attached device.
pub struct UsbPort {
    pub dev: Option<Arc<Mutex<dyn UsbDeviceOps>>>,
    pub speed_mask: u32,
    pub path: String,
    pub index: u32,
}

impl UsbPort {
    pub fn new(index: u32) -> Self {
        Self {
            dev: None,
            speed_mask: 0,
            path: String::new(),
            index,
        }
    }

    /// If the USB port attached USB device.
    pub fn is_attached(&self) -> bool {
        if let Some(dev) = &self.dev {
            let locked_dev = dev.lock().unwrap();
            locked_dev.attached()
        } else {
            false
        }
    }
}

/// USB descriptor strings.
pub struct UsbDescString {
    pub index: u32,
    pub str: String,
}

/// USB packet state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UsbPacketState {
    Undefined = 0,
    Setup,
    Queued,
    Async,
    Complete,
    Canceled,
}

/// USB device common structure.
pub struct UsbDevice {
    pub port: Option<Weak<Mutex<UsbPort>>>,
    pub speed: u32,
    pub speed_mask: u32,
    pub addr: u8,
    pub product_desc: String,
    pub auto_attach: bool,
    pub attached: bool,
    pub state: UsbDeviceState,
    pub setup_buf: Vec<u8>,
    pub data_buf: Vec<u8>,
    pub remote_wakeup: u32,
    pub setup_state: SetupState,
    pub setup_len: u32,
    pub setup_index: u32,
    pub ep_ctl: Arc<Mutex<UsbEndpoint>>,
    pub ep_in: Vec<Arc<Mutex<UsbEndpoint>>>,
    pub ep_out: Vec<Arc<Mutex<UsbEndpoint>>>,
}

/// UsbDeviceOps is the interface for USB device.
/// Include device handle attach/detach and the transfer between controller and device.
pub trait UsbDeviceOps: Send + Sync {
    /// Handle the attach ops when attach device to controller.
    fn handle_attach(&mut self) -> Result<()>;

    /// Reset the USB device.
    fn reset(&mut self);

    /// Set the controller which the USB device attached.
    /// USB deivce need to kick controller in some cases.
    fn set_controller(&mut self, ctrl: Weak<Mutex<XhciDevice>>);

    /// Set the attached USB port.
    fn set_usb_port(&mut self, port: Option<Weak<Mutex<UsbPort>>>);

    /// Handle usb packet, used for controller to deliever packet to device.
    fn handle_packet(&mut self, packet: &mut UsbPacket);

    /// Handle control pakcet.
    fn handle_control(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
        data: &mut [u8],
    );

    /// Handle data pakcet.
    fn handle_data(&mut self, packet: &mut UsbPacket);

    /// Unique device id.
    fn device_id(&self) -> String;

    /// Get the UsbDevice.
    fn get_usb_device(&self) -> Arc<Mutex<UsbDevice>>;

    /// Get the mut UsbDevice.
    fn get_mut_usb_device(&mut self) -> Arc<Mutex<UsbDevice>>;

    /// Get the device speed.
    fn speed(&self) -> u32;

    /// If USB device is attached.
    fn attached(&self) -> bool;
}

/// Io vector which save the hva.
#[derive(Debug, Copy, Clone)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: usize,
}

impl Iovec {
    pub fn new(base: u64, len: usize) -> Self {
        Iovec {
            iov_base: base,
            iov_len: len,
        }
    }
}

/// Usb packet used for device transfer data.
#[derive(Clone)]
pub struct UsbPacket {
    /// USB packet id.
    pub pid: u32,
    pub id: u64,
    pub ep: Option<Weak<Mutex<UsbEndpoint>>>,
    pub iovecs: Vec<Iovec>,
    /// control transfer
    pub parameter: u64,
    pub short_not_ok: bool,
    pub int_req: bool,
    /// USB packet return status
    pub status: UsbPacketStatus,
    /// Actually transfer length
    pub actual_length: u32,
    pub state: UsbPacketState,
}

impl Default for UsbPacket {
    fn default() -> UsbPacket {
        UsbPacket {
            pid: 0,
            id: 0,
            ep: None,
            iovecs: Vec::new(),
            parameter: 0,
            short_not_ok: false,
            int_req: false,
            status: UsbPacketStatus::NoDev,
            actual_length: 0,
            state: UsbPacketState::Undefined,
        }
    }
}
