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
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use clap::Parser;
use log::{error, info, warn};
use once_cell::sync::Lazy;

use super::descriptor::{
    UsbConfigDescriptor, UsbDescConfig, UsbDescDevice, UsbDescEndpoint, UsbDescIface,
    UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor, UsbInterfaceDescriptor,
};
use super::xhci::xhci_controller::XhciDevice;
use super::{config::*, USB_DEVICE_BUFFER_DEFAULT_LEN};
use super::{UsbDevice, UsbDeviceBase, UsbDeviceRequest, UsbPacket, UsbPacketStatus};
use crate::ScsiBus::{
    get_scsi_key, ScsiBus, ScsiRequest, ScsiRequestOps, ScsiSense, ScsiXferMode, EMULATE_SCSI_OPS,
    GOOD, SCSI_CMD_BUF_SIZE,
};
use crate::ScsiDisk::{ScsiDevConfig, ScsiDevice};
use crate::{Bus, Device};
use machine_manager::config::{DriveConfig, DriveFile};
use util::aio::AioEngine;
use util::gen_base_func;

// Storage device descriptor
static DESC_DEVICE_STORAGE: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: USB_STORAGE_VENDOR_ID,
            idProduct: USB_PRODUCT_ID_STORAGE,
            bcdDevice: 0,
            iManufacturer: STR_MANUFACTURER_INDEX,
            iProduct: STR_PRODUCT_STORAGE_INDEX,
            iSerialNumber: STR_SERIAL_STORAGE_INDEX,
            bcdUSB: 0x0200,
            bDeviceClass: 0,
            bDeviceSubClass: 0,
            bDeviceProtocol: 0,
            bMaxPacketSize0: 64,
            bNumConfigurations: 1,
        },
        configs: vec![Arc::new(UsbDescConfig {
            config_desc: UsbConfigDescriptor {
                bLength: USB_DT_CONFIG_SIZE,
                bDescriptorType: USB_DT_CONFIGURATION,
                wTotalLength: 0,
                bNumInterfaces: 1,
                bConfigurationValue: 1,
                iConfiguration: STR_CONFIG_STORAGE_HIGH_INDEX,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_SELF_POWER,
                bMaxPower: 50,
            },
            iad_desc: vec![],
            interfaces: vec![DESC_IFACE_STORAGE.clone()],
        })],
    })
});

// Storage interface descriptor
static DESC_IFACE_STORAGE: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: 0,
            bAlternateSetting: 0,
            bNumEndpoints: 2,
            bInterfaceClass: USB_CLASS_MASS_STORAGE,
            bInterfaceSubClass: USB_SUBCLASS_SCSI,
            bInterfaceProtocol: USB_IFACE_PROTOCOL_BOT,
            iInterface: 0,
        },
        other_desc: vec![],
        endpoints: vec![
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | 0x01,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 512,
                    bInterval: 0,
                },
                extra: Vec::new(),
            }),
            Arc::new(UsbDescEndpoint {
                endpoint_desc: UsbEndpointDescriptor {
                    bLength: USB_DT_ENDPOINT_SIZE,
                    bDescriptorType: USB_DT_ENDPOINT,
                    bEndpointAddress: USB_DIRECTION_HOST_TO_DEVICE | 0x02,
                    bmAttributes: USB_ENDPOINT_ATTR_BULK,
                    wMaxPacketSize: 512,
                    bInterval: 0,
                },
                extra: Vec::new(),
            }),
        ],
    })
});

// CRC16 of "STRATOVIRT"
const USB_STORAGE_VENDOR_ID: u16 = 0xB74C;

// String descriptor index
const STR_MANUFACTURER_INDEX: u8 = 1;
const STR_PRODUCT_STORAGE_INDEX: u8 = 2;
const STR_SERIAL_STORAGE_INDEX: u8 = 3;
const STR_CONFIG_STORAGE_HIGH_INDEX: u8 = 5;

// String descriptor
const DESC_STRINGS: [&str; 7] = [
    "",
    "StratoVirt",
    "StratoVirt USB Storage",
    "3",
    "Full speed config (usb 1.1)",
    "High speed config (usb 2.0)",
    "Super speed config (usb 3.0)",
];

pub const GET_MAX_LUN: u8 = 0xfe;
pub const MASS_STORAGE_RESET: u8 = 0xff;

pub const CBW_SIGNATURE: u32 = 0x43425355;
pub const CSW_SIGNATURE: u32 = 0x53425355;
pub const CBW_FLAG_IN: u8 = 1 << 7;
pub const CBW_FLAG_OUT: u8 = 0;
pub const CBW_SIZE: u8 = 31;
pub const CSW_SIZE: u8 = 13;

// USB-storage has only target 0 and lun 0.
const USB_STORAGE_SCSI_LUN_ID: u8 = 0;

struct UsbStorageState {
    mode: UsbMsdMode,
    cbw: UsbMsdCbw,
    csw: UsbMsdCsw,
    cdb: Option<[u8; SCSI_CMD_BUF_SIZE]>,
    iovec_len: u32,
}

impl ScsiRequestOps for UsbMsdCsw {
    fn scsi_request_complete_cb(&mut self, status: u8, _: Option<ScsiSense>) -> Result<()> {
        if status != GOOD {
            self.status = UsbMsdCswStatus::Failed as u8;
        }
        Ok(())
    }
}

impl UsbStorageState {
    fn new() -> Self {
        UsbStorageState {
            mode: UsbMsdMode::Cbw,
            cbw: UsbMsdCbw::default(),
            csw: UsbMsdCsw::new(),
            cdb: None,
            iovec_len: 0,
        }
    }

    /// Check if there exists SCSI CDB.
    ///
    /// # Arguments
    ///
    /// `exist` - Expected existence status.
    ///
    /// Return Error if expected existence status is not equal to the actual situation.
    fn check_cdb_exist(&self, exist: bool) -> Result<()> {
        if exist {
            self.cdb.with_context(|| "No scsi CDB can be executed")?;
        } else if self.cdb.is_some() {
            bail!(
                "Another request has not been done! cdb {:x?}",
                self.cdb.unwrap()
            );
        }

        Ok(())
    }

    /// Check if Iovec is empty.
    ///
    /// # Arguments
    ///
    /// `empty` - Expected status. If true, expect empty iovec.
    ///
    /// Return Error if expected iovec status is not equal to the actual situation.
    fn check_iovec_empty(&self, empty: bool) -> Result<()> {
        if empty != (self.iovec_len == 0) {
            match empty {
                true => {
                    bail!(
                        "Another request has not been done! Data buffer length {}.",
                        self.iovec_len
                    );
                }
                false => {
                    bail!("Missing data buffer!");
                }
            };
        }

        Ok(())
    }
}

#[derive(Parser, Clone, Debug)]
#[command(no_binary_name(true))]
pub struct UsbStorageConfig {
    #[arg(long, value_parser = ["usb-storage"])]
    pub classtype: String,
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub drive: String,
    #[arg(long)]
    pub(super) bus: Option<String>,
    #[arg(long)]
    pub(super) port: Option<String>,
}

/// USB storage device.
pub struct UsbStorage {
    base: UsbDeviceBase,
    state: UsbStorageState,
    /// USB controller used to notify controller to transfer data.
    cntlr: Option<Weak<Mutex<XhciDevice>>>,
    /// Configuration of the USB storage device.
    pub dev_cfg: UsbStorageConfig,
    /// Configuration of the USB storage device's drive.
    pub drive_cfg: DriveConfig,
    /// Scsi bus attached to this usb-storage device.
    scsi_bus: Arc<Mutex<ScsiBus>>,
    /// Effective scsi backend.
    // Note: scsi device should attach to scsi bus. Logically, scsi device should not be placed in
    // UsbStorage. But scsi device is needed in processing scsi request. Because the three
    // (usb-storage/scsi bus/scsi device) correspond one-to-one, add scsi device member here
    // for the execution efficiency (No need to find a unique device from the hash table of the
    // unique bus).
    scsi_dev: Option<Arc<Mutex<ScsiDevice>>>,
    /// Drive backend files.
    drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
}

#[derive(Debug)]
enum UsbMsdMode {
    Cbw,
    DataOut,
    DataIn,
    Csw,
}

pub enum UsbMsdCswStatus {
    Passed,
    Failed,
    PhaseError,
}

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

#[derive(Debug, Copy, Clone)]
struct UsbMsdCsw {
    sig: u32,
    tag: u32,
    residue: u32,
    status: u8,
}

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
    pub fn new(
        dev_cfg: UsbStorageConfig,
        drive_cfg: DriveConfig,
        drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
    ) -> Result<Self> {
        if drive_cfg.aio != AioEngine::Off || drive_cfg.direct {
            bail!("USB-storage: \"aio=off,direct=false\" must be configured.");
        }

        Ok(Self {
            base: UsbDeviceBase::new(dev_cfg.id.clone(), USB_DEVICE_BUFFER_DEFAULT_LEN),
            state: UsbStorageState::new(),
            cntlr: None,
            dev_cfg,
            drive_cfg,
            scsi_bus: Arc::new(Mutex::new(ScsiBus::new("".to_string()))),
            scsi_dev: None,
            drive_files,
        })
    }

    pub fn do_realize(&mut self) -> Result<()> {
        self.base.reset_usb_endpoint();
        self.base.speed = USB_SPEED_HIGH;
        let mut s: Vec<String> = DESC_STRINGS.iter().map(|&s| s.to_string()).collect();
        let prefix = &s[STR_SERIAL_STORAGE_INDEX as usize];
        s[STR_SERIAL_STORAGE_INDEX as usize] = self.base.generate_serial_number(prefix);
        self.base.init_descriptor(DESC_DEVICE_STORAGE.clone(), s)?;

        // NOTE: "aio=off,direct=false" must be configured and other aio/direct values are not
        // supported.
        let scsidev_classtype = match self.drive_cfg.media.as_str() {
            "disk" => "scsi-hd".to_string(),
            _ => "scsi-cd".to_string(),
        };
        let scsi_dev_cfg = ScsiDevConfig {
            classtype: scsidev_classtype,
            drive: self.dev_cfg.drive.clone(),
            ..Default::default()
        };
        let scsi_device = ScsiDevice::new(
            scsi_dev_cfg,
            self.drive_cfg.clone(),
            self.drive_files.clone(),
            None,
            self.scsi_bus.clone(),
        );
        let realized_scsi = scsi_device.realize()?;
        self.scsi_dev = Some(realized_scsi.clone());

        self.scsi_bus
            .lock()
            .unwrap()
            .attach_child(get_scsi_key(0, 0), realized_scsi)
    }

    pub fn handle_control_packet(&mut self, packet: &mut UsbPacket, device_req: &UsbDeviceRequest) {
        match device_req.request_type {
            USB_ENDPOINT_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_CLEAR_FEATURE {
                    return;
                }
            }
            USB_INTERFACE_CLASS_OUT_REQUEST => {
                if device_req.request == MASS_STORAGE_RESET {
                    self.state.mode = UsbMsdMode::Cbw;
                    return;
                }
            }
            USB_INTERFACE_CLASS_IN_REQUEST => {
                if device_req.request == GET_MAX_LUN {
                    // TODO: Now only supports 1 LUN.
                    let maxlun = USB_STORAGE_SCSI_LUN_ID;
                    self.base.data_buf[0] = maxlun;
                    packet.actual_length = 1;
                    return;
                }
            }
            _ => {}
        }

        error!("Unhandled USB Storage request {}", device_req.request);
        packet.status = UsbPacketStatus::Stall;
    }

    fn handle_token_out(&mut self, packet: &mut UsbPacket) -> Result<()> {
        if packet.ep_number != 2 {
            bail!("Error ep_number {}!", packet.ep_number);
        }

        match self.state.mode {
            UsbMsdMode::Cbw => {
                if packet.get_iovecs_size() < u64::from(CBW_SIZE) {
                    bail!("Bad CBW size {}", packet.get_iovecs_size());
                }
                self.state.check_cdb_exist(false)?;

                let mut cbw_buf = [0_u8; CBW_SIZE as usize];
                packet.transfer_packet(&mut cbw_buf, CBW_SIZE as usize);
                self.state.cbw.convert(&cbw_buf);
                trace::usb_storage_handle_token_out(&self.state.cbw);

                if self.state.cbw.sig != CBW_SIGNATURE {
                    bail!("Bad signature {:x}", self.state.cbw.sig);
                }
                if self.state.cbw.lun != USB_STORAGE_SCSI_LUN_ID {
                    bail!(
                        "Bad lun id {:x}. Usb-storage only supports lun id 0!",
                        self.state.cbw.lun
                    );
                }

                self.state.cdb = Some(self.state.cbw.cmd);

                if self.state.cbw.data_len == 0 {
                    self.handle_scsi_request(packet)?;
                    self.state.mode = UsbMsdMode::Csw;
                } else if self.state.cbw.flags & CBW_FLAG_IN == CBW_FLAG_IN {
                    self.state.mode = UsbMsdMode::DataIn;
                } else {
                    self.state.mode = UsbMsdMode::DataOut;
                }
            }
            UsbMsdMode::DataOut => {
                self.handle_data_inout_packet(packet, UsbMsdMode::DataOut)?;
            }
            _ => {
                bail!(
                    "Unexpected token out. Expected mode {:?} packet.",
                    self.state.mode
                );
            }
        }
        Ok(())
    }

    fn handle_token_in(&mut self, packet: &mut UsbPacket) -> Result<()> {
        if packet.ep_number != 1 {
            bail!("Error ep_number {}!", packet.ep_number);
        }

        match self.state.mode {
            UsbMsdMode::DataOut => {
                bail!("Not supported usb packet(Token_in and data_out).");
            }
            UsbMsdMode::Csw => {
                if packet.get_iovecs_size() < u64::from(CSW_SIZE) {
                    bail!("Bad CSW size {}", packet.get_iovecs_size());
                }
                self.state.check_cdb_exist(true)?;
                self.state.check_iovec_empty(self.state.cbw.data_len == 0)?;

                let mut csw_buf = [0_u8; CSW_SIZE as usize];
                self.state.csw.tag = self.state.cbw.tag;
                self.state.csw.convert(&mut csw_buf);
                trace::usb_storage_handle_token_in(&self.state.csw);
                packet.transfer_packet(&mut csw_buf, CSW_SIZE as usize);

                // Reset UsbStorageState.
                self.state = UsbStorageState::new();
            }
            UsbMsdMode::DataIn => {
                self.handle_data_inout_packet(packet, UsbMsdMode::DataIn)?;
            }
            _ => {
                bail!(
                    "Unexpected token in. Expected mode {:?} packet.",
                    self.state.mode
                );
            }
        }
        Ok(())
    }

    fn handle_data_inout_packet(&mut self, packet: &mut UsbPacket, mode: UsbMsdMode) -> Result<()> {
        self.state.check_cdb_exist(true)?;
        self.state.check_iovec_empty(true)?;

        // Safety: iovecs are set in `setup_usb_packet` and iovec_len is no more than TRB_TR_LEN_MASK.
        let iovec_len = packet.get_iovecs_size() as u32;
        if iovec_len < self.state.cbw.data_len {
            bail!(
                "Insufficient transmission buffer, transfer size {}, buffer size {}, MSD mode {:?}!",
                self.state.cbw.data_len,
                iovec_len,
                mode,
            );
        }

        self.state.iovec_len = iovec_len;
        self.handle_scsi_request(packet)?;
        packet.actual_length = iovec_len;
        self.state.mode = UsbMsdMode::Csw;
        trace::usb_storage_handle_data_inout_packet(iovec_len);

        Ok(())
    }

    // Handle scsi request and save result in self.csw for next CSW packet.
    fn handle_scsi_request(&mut self, packet: &mut UsbPacket) -> Result<()> {
        self.state
            .cdb
            .with_context(|| "No scsi CDB can be executed")?;

        let csw = Box::new(UsbMsdCsw::new());
        let sreq = ScsiRequest::new(
            self.state.cdb.unwrap(),
            0,
            packet.iovecs.clone(),
            self.state.iovec_len,
            self.scsi_dev.as_ref().unwrap().clone(),
            csw,
        )
        .with_context(|| "Error in creating scsirequest.")?;

        if sreq.cmd.xfer > u64::from(sreq.datalen) && sreq.cmd.mode != ScsiXferMode::ScsiXferNone {
            // Wrong USB packet which doesn't provide enough datain/dataout buffer.
            bail!(
                "command {:x} requested data's length({}), provided buffer length({})",
                sreq.cmd.op,
                sreq.cmd.xfer,
                sreq.datalen
            );
        }

        let sreq_h = match sreq.opstype {
            EMULATE_SCSI_OPS => sreq.emulate_execute(),
            _ => sreq.execute(),
        }
        .with_context(|| "Error in executing scsi request.")?;

        let csw_h = &sreq_h.lock().unwrap().upper_req;
        let csw = csw_h.as_ref().as_any().downcast_ref::<UsbMsdCsw>().unwrap();
        self.state.csw = *csw;
        trace::usb_storage_handle_scsi_request(csw);

        Ok(())
    }
}

impl UsbDevice for UsbStorage {
    gen_base_func!(usb_device_base, usb_device_base_mut, UsbDeviceBase, base);

    fn realize(mut self) -> Result<Arc<Mutex<dyn UsbDevice>>> {
        self.do_realize()?;
        let storage: Arc<Mutex<UsbStorage>> = Arc::new(Mutex::new(self));
        Ok(storage)
    }

    fn cancel_packet(&mut self, _packet: &Arc<Mutex<UsbPacket>>) {}

    fn reset(&mut self) {
        info!("Storage device reset");
        self.base.remote_wakeup = 0;
        self.base.addr = 0;
        self.state = UsbStorageState::new();
    }

    fn handle_control(&mut self, packet: &Arc<Mutex<UsbPacket>>, device_req: &UsbDeviceRequest) {
        let mut locked_packet = packet.lock().unwrap();
        match self
            .base
            .handle_control_for_descriptor(&mut locked_packet, device_req)
        {
            Ok(handled) => {
                if handled {
                    trace::usb_storage_handle_control();
                    return;
                }
                self.handle_control_packet(&mut locked_packet, device_req)
            }
            Err(e) => {
                warn!("Received incorrect USB Storage descriptor message: {:?}", e);
                locked_packet.status = UsbPacketStatus::Stall;
            }
        }
    }

    fn handle_data(&mut self, packet: &Arc<Mutex<UsbPacket>>) {
        let mut locked_packet = packet.lock().unwrap();
        trace::usb_storage_handle_data(
            locked_packet.ep_number,
            locked_packet.pid,
            &self.state.mode,
        );

        let result = match locked_packet.pid as u8 {
            USB_TOKEN_OUT => self.handle_token_out(&mut locked_packet),
            USB_TOKEN_IN => self.handle_token_in(&mut locked_packet),
            _ => Err(anyhow!("Bad token!")),
        };

        if let Err(e) = result {
            warn!(
                "USB-storage {}: handle data error: {:?}",
                self.device_id(),
                e
            );
            locked_packet.status = UsbPacketStatus::Stall;
        }
    }

    fn set_controller(&mut self, cntlr: Weak<Mutex<XhciDevice>>) {
        self.cntlr = Some(cntlr);
    }

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        self.cntlr.clone()
    }
}
