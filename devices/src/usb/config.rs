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

/// USB Command
/// Run/Stop
pub const USB_CMD_RUN: u32 = 1 << 0;
/// Host Controller Reset
pub const USB_CMD_HCRST: u32 = 1 << 1;
/// Interrupter Enable
pub const USB_CMD_INTE: u32 = 1 << 2;
/// Host System Error Enable
pub const USB_CMD_HSEE: u32 = 1 << 3;
/// Light Host Controller Reset
pub const USB_CMD_LHCRST: u32 = 1 << 7;
/// Controller Save State
pub const USB_CMD_CSS: u32 = 1 << 8;
/// Controller Restore State
pub const USB_CMD_CRS: u32 = 1 << 9;
/// Enable Wrap Event
pub const USB_CMD_EWE: u32 = 1 << 10;
/// Enable U3 MFINDEX Stop
pub const USB_CMD_EU3S: u32 = 1 << 11;

/// USB status
/// HC Halted
pub const USB_STS_HCH: u32 = 1 << 0;
/// Host System Error
pub const USB_STS_HSE: u32 = 1 << 2;
/// Event Interrupt
pub const USB_STS_EINT: u32 = 1 << 3;
/// Port Change Detect
pub const USB_STS_PCD: u32 = 1 << 4;
/// Save State Status
pub const USB_STS_SSS: u32 = 1 << 8;
/// Restore State Status
pub const USB_STS_RSS: u32 = 1 << 9;
/// Save/Restore Error
pub const USB_STS_SRE: u32 = 1 << 10;
/// Controller Not Ready
pub const USB_STS_CNR: u32 = 1 << 11;
/// Host Controller Error
pub const USB_STS_HCE: u32 = 1 << 12;

/// Command Ring Control
/// Ring Cycle State
pub const CMD_RING_CTRL_RCS: u32 = 1 << 0;
/// Command Stop
pub const CMD_RING_CTRL_CS: u32 = 1 << 1;
/// Command Abort
pub const CMD_RING_CTRL_CA: u32 = 1 << 2;
/// Command Ring Running
pub const CMD_RING_CTRL_CRR: u32 = 1 << 3;
/// Interrupt Pending
pub const IMAN_IP: u32 = 1 << 0;
/// Interrupt Enable
pub const IMAN_IE: u32 = 1 << 1;
/// Event Handler Busy
pub const ERDP_EHB: u32 = 1 << 3;

/// Port Status and Control Register
/// Current Connect Status
pub const PORTSC_CCS: u32 = 1 << 0;
/// Port Enabled/Disabled
pub const PORTSC_PED: u32 = 1 << 1;
/// Over-current Active
pub const PORTSC_OCA: u32 = 1 << 3;
/// Port Reset
pub const PORTSC_PR: u32 = 1 << 4;
/// Port Power
pub const PORTSC_PP: u32 = 1 << 9;
/// Port Speed
pub const PORTSC_SPEED_SHIFT: u32 = 10;
pub const PORTSC_SPEED_FULL: u32 = 1 << PORTSC_SPEED_SHIFT;
pub const PORTSC_SPEED_LOW: u32 = 2 << PORTSC_SPEED_SHIFT;
pub const PORTSC_SPEED_HIGH: u32 = 3 << PORTSC_SPEED_SHIFT;
pub const PORTSC_SPEED_SUPER: u32 = 4 << PORTSC_SPEED_SHIFT;
/// Port Indicator Control
pub const PORTSC_PLS_SHIFT: u32 = 5;
pub const PORTSC_PLS_MASK: u32 = 0xf;
/// Port Link State Write Strobe
pub const PORTSC_LWS: u32 = 1 << 16;
/// Connect Status Change
pub const PORTSC_CSC: u32 = 1 << 17;
/// Port Enabled/Disabled Change
pub const PORTSC_PEC: u32 = 1 << 18;
/// Warm Port Reset Change
pub const PORTSC_WRC: u32 = 1 << 19;
/// Over-current Change
pub const PORTSC_OCC: u32 = 1 << 20;
/// Port Reset Change
pub const PORTSC_PRC: u32 = 1 << 21;
/// Port Link State Change
pub const PORTSC_PLC: u32 = 1 << 22;
/// Port Config Error Change
pub const PORTSC_CEC: u32 = 1 << 23;
/// Cold Attach Status
pub const PORTSC_CAS: u32 = 1 << 24;
/// Wake on Connect Enable
pub const PORTSC_WCE: u32 = 1 << 25;
/// Wake on Disconnect Enable
pub const PORTSC_WDE: u32 = 1 << 26;
/// Wake on Over-current Enable
pub const PORTSC_WOE: u32 = 1 << 27;
/// Device Removable
pub const PORTSC_DR: u32 = 1 << 30;
/// Warm Port Reset
pub const PORTSC_WPR: u32 = 1 << 31;
/// Port Link State
pub const PLS_U0: u32 = 0;
pub const PLS_U1: u32 = 1;
pub const PLS_U2: u32 = 2;
pub const PLS_U3: u32 = 3;
pub const PLS_DISABLED: u32 = 4;
pub const PLS_RX_DETECT: u32 = 5;
pub const PLS_INACTIVE: u32 = 6;
pub const PLS_POLLING: u32 = 7;
pub const PLS_RECOVERY: u32 = 8;
pub const PLS_HOT_RESET: u32 = 9;
pub const PLS_COMPILANCE_MODE: u32 = 10;
pub const PLS_TEST_MODE: u32 = 11;
pub const PLS_RESUME: u32 = 15;

/// USB speed
pub const USB_SPEED_LOW: u32 = 0;
pub const USB_SPEED_FULL: u32 = 1;
pub const USB_SPEED_HIGH: u32 = 2;
pub const USB_SPEED_SUPER: u32 = 3;
pub const USB_SPEED_MASK_LOW: u32 = 1 << USB_SPEED_LOW;
pub const USB_SPEED_MASK_FULL: u32 = 1 << USB_SPEED_FULL;
pub const USB_SPEED_MASK_HIGH: u32 = 1 << USB_SPEED_HIGH;
pub const USB_SPEED_MASK_SUPER: u32 = 1 << USB_SPEED_SUPER;

/// See the spec section 8.3.1 Packet Identifier Field.
pub const USB_TOKEN_SETUP: u8 = 0x2d;
pub const USB_TOKEN_IN: u8 = 0x69;
pub const USB_TOKEN_OUT: u8 = 0xe1;

/// See the spec section 9.3 USB Device Requests. Setup Data.
pub const USB_DIRECTION_HOST_TO_DEVICE: u8 = 0 << 7;
pub const USB_DIRECTION_DEVICE_TO_HOST: u8 = 0x80;
pub const USB_TYPE_STANDARD: u8 = 0x00 << 5;
pub const USB_TYPE_CLASS: u8 = 1 << 5;
pub const USB_TYPE_VENDOR: u8 = 2 << 5;
pub const USB_TYPE_RESERVED: u8 = 3 << 5;
pub const USB_RECIPIENT_DEVICE: u8 = 0;
pub const USB_RECIPIENT_INTERFACE: u8 = 1;
pub const USB_RECIPIENT_ENDPOINT: u8 = 2;
pub const USB_RECIPIENT_OTHER: u8 = 3;

/// USB device request combination
pub const USB_DEVICE_IN_REQUEST: u8 =
    USB_DIRECTION_DEVICE_TO_HOST | USB_TYPE_STANDARD | USB_RECIPIENT_DEVICE;
pub const USB_DEVICE_OUT_REQUEST: u8 =
    USB_DIRECTION_HOST_TO_DEVICE | USB_TYPE_STANDARD | USB_RECIPIENT_DEVICE;
pub const USB_INTERFACE_IN_REQUEST: u8 =
    USB_DIRECTION_DEVICE_TO_HOST | USB_TYPE_STANDARD | USB_RECIPIENT_INTERFACE;
pub const USB_INTERFACE_OUT_REQUEST: u8 =
    USB_DIRECTION_HOST_TO_DEVICE | USB_TYPE_STANDARD | USB_RECIPIENT_INTERFACE;
pub const USB_INTERFACE_CLASS_IN_REQUEST: u8 =
    USB_DIRECTION_DEVICE_TO_HOST | USB_TYPE_CLASS | USB_RECIPIENT_INTERFACE;
pub const USB_INTERFACE_CLASS_OUT_REQUEST: u8 =
    USB_DIRECTION_HOST_TO_DEVICE | USB_TYPE_CLASS | USB_RECIPIENT_INTERFACE;

/// USB Standard Request Code. 9.4 Standard Device Requests
pub const USB_REQUEST_GET_STATUS: u8 = 0;
pub const USB_REQUEST_CLEAR_FEATURE: u8 = 1;
pub const USB_REQUEST_SET_FEATURE: u8 = 3;
pub const USB_REQUEST_SET_ADDRESS: u8 = 5;
pub const USB_REQUEST_GET_DESCRIPTOR: u8 = 6;
pub const USB_REQUEST_SET_DESCRIPTOR: u8 = 7;
pub const USB_REQUEST_GET_CONFIGURATION: u8 = 8;
pub const USB_REQUEST_SET_CONFIGURATION: u8 = 9;
pub const USB_REQUEST_GET_INTERFACE: u8 = 10;
pub const USB_REQUEST_SET_INTERFACE: u8 = 11;
pub const USB_REQUEST_SYNCH_FRAME: u8 = 12;
pub const USB_REQUEST_SET_SEL: u8 = 48;
pub const USB_REQUEST_SET_ISOCH_DELAY: u8 = 49;

/// See the spec section 9.4.5 Get Status
pub const USB_DEVICE_SELF_POWERED: u32 = 0;
pub const USB_DEVICE_REMOTE_WAKEUP: u32 = 1;

/// USB Descriptor Type
pub const USB_DT_DEVICE: u8 = 1;
pub const USB_DT_CONFIGURATION: u8 = 2;
pub const USB_DT_STRING: u8 = 3;
pub const USB_DT_INTERFACE: u8 = 4;
pub const USB_DT_ENDPOINT: u8 = 5;
pub const USB_DT_INTERFACE_POWER: u8 = 8;
pub const USB_DT_OTG: u8 = 9;
pub const USB_DT_DEBUG: u8 = 10;
pub const USB_DT_INTERFACE_ASSOCIATION: u8 = 11;
pub const USB_DT_BOS: u8 = 15;
pub const USB_DT_DEVICE_CAPABILITY: u8 = 16;
pub const USB_DT_ENDPOINT_COMPANION: u8 = 48;

/// USB Descriptor size
pub const USB_DT_DEVICE_SIZE: u8 = 18;
pub const USB_DT_CONFIG_SIZE: u8 = 9;
pub const USB_DT_INTERFACE_SIZE: u8 = 9;
pub const USB_DT_ENDPOINT_SIZE: u8 = 7;

/// USB Endpoint Descriptor
pub const USB_ENDPOINT_ATTR_CONTROL: u8 = 0;
pub const USB_ENDPOINT_ATTR_ISOC: u8 = 1;
pub const USB_ENDPOINT_ATTR_BULK: u8 = 2;
pub const USB_ENDPOINT_ATTR_INT: u8 = 3;
pub const USB_ENDPOINT_ATTR_TRANSFER_TYPE_MASK: u8 = 0x3;
pub const USB_ENDPOINT_ATTR_INVALID: u8 = 255;
pub const USB_ENDPOINT_ADDRESS_NUMBER_MASK: u8 = 0xf;

///  See the spec section 9.6.3 Configuration. Standard Configuration Descriptor.
pub const USB_CONFIGURATION_ATTR_ONE: u8 = 1 << 7;
pub const USB_CONFIGURATION_ATTR_SELF_POWER: u8 = 1 << 6;
pub const USB_CONFIGURATION_ATTR_REMOTE_WAKEUP: u8 = 1 << 5;

// USB Class
pub const USB_CLASS_HID: u8 = 3;
