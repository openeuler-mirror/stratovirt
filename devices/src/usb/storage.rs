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

use std::sync::{Mutex, Weak};

use byteorder::{ByteOrder, LittleEndian};
use log::info;

use super::xhci::xhci_controller::XhciDevice;
use super::{UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket};

pub const GET_MAX_LUN: u8 = 0xfe;
pub const MASS_STORAGE_RESET: u8 = 0xff;

pub const CBW_SIGNATURE: u32 = 0x43425355;
pub const CSW_SIGNATURE: u32 = 0x53425355;
pub const CBW_FLAG_IN: u8 = 1 << 7;
pub const CBW_FLAG_OUT: u8 = 0;
pub const CBW_SIZE: u8 = 31;
pub const CSW_SIZE: u8 = 13;

#[allow(dead_code)]
struct UsbStorageState {
    mode: UsbMsdMode,
    cbw: UsbMsdCbw,
    csw: UsbMsdCsw,
}

impl UsbStorageState {
    fn new() -> Self {
        UsbStorageState {
            mode: UsbMsdMode::Cbw,
            cbw: UsbMsdCbw::default(),
            csw: UsbMsdCsw::new(),
        }
    }
}

/// USB storage device.
pub struct UsbStorage {
    id: String,
    usb_device: UsbDevice,
    state: UsbStorageState,
    /// USB controller used to notify controller to transfer data.
    cntlr: Option<Weak<Mutex<XhciDevice>>>,
}

#[allow(dead_code)]
#[derive(Debug)]
enum UsbMsdMode {
    Cbw,
    DataOut,
    DataIn,
    Csw,
}

#[allow(dead_code)]
enum UsbMsdCswStatus {
    Passed,
    Failed,
    PhaseError,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
struct UsbMsdCbw {
    sig: u32,
    tag: u32,
    data_len: u32,
    flags: u8,
    lun: u8,
    cmd_len: u8,
    cmd: [u8; 16],
}

#[allow(dead_code)]
impl UsbMsdCbw {
    fn convert(&mut self, data: &[u8]) {
        self.sig = LittleEndian::read_u32(&data[0..4]);
        self.tag = LittleEndian::read_u32(&data[4..8]);
        self.data_len = LittleEndian::read_u32(&data[8..12]);
        self.flags = data[12];
        self.lun = data[13];
        self.cmd_len = data[14];
        self.cmd.copy_from_slice(&data[15..31]);
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct UsbMsdCsw {
    sig: u32,
    tag: u32,
    residue: u32,
    status: u8,
}

#[allow(dead_code)]
impl UsbMsdCsw {
    fn new() -> Self {
        UsbMsdCsw {
            sig: CSW_SIGNATURE,
            tag: 0,
            residue: 0,
            status: 0,
        }
    }

    fn convert(&mut self, data: &mut [u8]) {
        LittleEndian::write_u32(&mut data[0..4], self.sig);
        LittleEndian::write_u32(&mut data[4..8], self.tag);
        LittleEndian::write_u32(&mut data[8..12], self.residue);
        data[12] = self.status;
    }
}

impl UsbStorage {
    pub fn new() -> Self {
        Self {
            id: "".to_string(),
            usb_device: UsbDevice::new(),
            state: UsbStorageState::new(),
            cntlr: None,
        }
    }
}

impl UsbDeviceOps for UsbStorage {
    fn reset(&mut self) {
        info!("Storage device reset");
        self.usb_device.remote_wakeup = 0;
        self.usb_device.addr = 0;
        self.state = UsbStorageState::new();
    }

    fn handle_control(&mut self, _packet: &mut UsbPacket, _device_req: &UsbDeviceRequest) {}

    fn handle_data(&mut self, _packet: &mut UsbPacket) {}

    fn device_id(&self) -> String {
        self.id.clone()
    }

    fn get_usb_device(&self) -> &UsbDevice {
        &self.usb_device
    }

    fn get_mut_usb_device(&mut self) -> &mut UsbDevice {
        &mut self.usb_device
    }

    fn set_controller(&mut self, cntlr: Weak<Mutex<XhciDevice>>) {
        self.cntlr = Some(cntlr);
    }

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        self.cntlr.clone()
    }

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.usb_device.get_endpoint(true, 1)
    }
}
