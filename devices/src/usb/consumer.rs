// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::sync::{Arc, Mutex, Weak};

use anyhow::Result;
use clap::Parser;
use log::{debug, info, warn};
use once_cell::sync::Lazy;

use super::descriptor::{
    UsbConfigDescriptor, UsbDescConfig, UsbDescDevice, UsbDescEndpoint, UsbDescIface, UsbDescOther,
    UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor, UsbInterfaceDescriptor,
};
use super::hid::{Hid, HidType, CONSUMER_REPORT_DESCRIPTOR, QUEUE_LENGTH, QUEUE_MASK};
use super::xhci::xhci_controller::{endpoint_number_to_id, XhciDevice};
use super::{config::*, USB_DEVICE_BUFFER_DEFAULT_LEN};
use super::{
    notify_controller, UsbDevice, UsbDeviceBase, UsbDeviceRequest, UsbPacket, UsbPacketStatus,
};
use machine_manager::config::valid_id;
use ui::input::{register_consumer, unregister_consumer, ConsumerOpts, CONSUMER_UP};
use util::gen_base_func;

/// Consumer device descriptor
static DESC_DEVICE_CONSUMER: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: USB_VENDOR_ID_STRATOVIRT,
            idProduct: USB_PRODUCT_ID_CONSUMER,
            bcdDevice: 0,
            iManufacturer: STR_MANUFACTURER_INDEX,
            iProduct: STR_PRODUCT_CONSUMER_INDEX,
            iSerialNumber: STR_SERIAL_CONSUMER_INDEX,
            bcdUSB: 0x0100,
            bDeviceClass: 0,
            bDeviceSubClass: 0,
            bDeviceProtocol: 0,
            bMaxPacketSize0: 8,
            bNumConfigurations: 1,
        },
        configs: vec![Arc::new(UsbDescConfig {
            config_desc: UsbConfigDescriptor {
                bLength: USB_DT_CONFIG_SIZE,
                bDescriptorType: USB_DT_CONFIGURATION,
                wTotalLength: 0,
                bNumInterfaces: 1,
                bConfigurationValue: 1,
                iConfiguration: STR_CONFIG_CONSUMER_INDEX,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_REMOTE_WAKEUP,
                bMaxPower: 50,
            },
            iad_desc: vec![],
            interfaces: vec![DESC_IFACE_CONSUMER.clone()],
        })],
    })
});

/// CONSUMER interface descriptor
static DESC_IFACE_CONSUMER: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: 0,
            bAlternateSetting: 0,
            bNumEndpoints: 1,
            bInterfaceClass: USB_CLASS_HID,
            bInterfaceSubClass: 0,
            bInterfaceProtocol: 0,
            iInterface: 0,
        },
        other_desc: vec![Arc::new(UsbDescOther {
            // HID descriptor
            data: vec![
                0x09,
                0x21,
                0x11,
                0x01,
                0x00,
                0x01,
                0x22,
                CONSUMER_REPORT_DESCRIPTOR.len() as u8,
                0,
            ],
        })],
        endpoints: vec![Arc::new(UsbDescEndpoint {
            endpoint_desc: UsbEndpointDescriptor {
                bLength: USB_DT_ENDPOINT_SIZE,
                bDescriptorType: USB_DT_ENDPOINT,
                bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | 0x1,
                bmAttributes: USB_ENDPOINT_ATTR_INT,
                wMaxPacketSize: 8,
                bInterval: 0xa,
            },
            extra: Vec::new(),
        })],
    })
});

/// String descriptor index
const STR_MANUFACTURER_INDEX: u8 = 1;
const STR_PRODUCT_CONSUMER_INDEX: u8 = 2;
const STR_CONFIG_CONSUMER_INDEX: u8 = 3;
const STR_SERIAL_CONSUMER_INDEX: u8 = 4;

/// String descriptor
const DESC_STRINGS: [&str; 5] = [
    "",
    "StratoVirt",
    "StratoVirt USB Consumer",
    "HID Consumer",
    "6",
];

#[derive(Parser, Clone, Debug, Default)]
#[command(no_binary_name(true))]
pub struct UsbConsumerConfig {
    #[arg(long)]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    id: String,
    #[arg(long)]
    bus: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

/// USB Consumer device.
pub struct UsbConsumer {
    base: UsbDeviceBase,
    hid: Hid,
    /// USB controller used to notify controller to transfer data.
    cntlr: Option<Weak<Mutex<XhciDevice>>>,
}

pub struct UsbConsumerAdapter {
    usb_consumer: Arc<Mutex<UsbConsumer>>,
}

impl ConsumerOpts for UsbConsumerAdapter {
    fn do_consumer_event(&mut self, keycode: u16, down: bool) -> Result<()> {
        trace::usb_consumer_event(&keycode, &down);

        let mut scan_code = keycode;
        if !down {
            scan_code |= CONSUMER_UP;
        }

        let mut locked_consumer = self.usb_consumer.lock().unwrap();
        if locked_consumer.hid.num >= QUEUE_LENGTH {
            trace::usb_consumer_queue_full();
            return Ok(());
        }

        let index = ((locked_consumer.hid.head + locked_consumer.hid.num) & QUEUE_MASK) as usize;
        locked_consumer.hid.num += 1;
        locked_consumer.hid.consumer.keycodes[index] = scan_code;
        drop(locked_consumer);
        let clone_consumer = self.usb_consumer.clone();
        let ep_id = endpoint_number_to_id(true, 1);
        notify_controller(&(clone_consumer as Arc<Mutex<dyn UsbDevice>>), ep_id)
    }
}

impl UsbConsumer {
    pub fn new(config: UsbConsumerConfig) -> Self {
        Self {
            base: UsbDeviceBase::new(config.id, USB_DEVICE_BUFFER_DEFAULT_LEN),
            hid: Hid::new(HidType::Consumer),
            cntlr: None,
        }
    }
}

impl UsbDevice for UsbConsumer {
    gen_base_func!(usb_device_base, usb_device_base_mut, UsbDeviceBase, base);

    fn realize(mut self) -> Result<Arc<Mutex<dyn UsbDevice>>> {
        self.base.reset_usb_endpoint();
        self.base.speed = USB_SPEED_FULL;
        let mut s: Vec<String> = DESC_STRINGS.iter().map(|&s| s.to_string()).collect();
        let prefix = &s[STR_SERIAL_CONSUMER_INDEX as usize];
        s[STR_SERIAL_CONSUMER_INDEX as usize] = self.base.generate_serial_number(prefix);
        self.base.init_descriptor(DESC_DEVICE_CONSUMER.clone(), s)?;
        let id = self.device_id().to_string();
        let consumer = Arc::new(Mutex::new(self));
        let consumer_adapter = Arc::new(Mutex::new(UsbConsumerAdapter {
            usb_consumer: consumer.clone(),
        }));
        register_consumer(&id, consumer_adapter);

        Ok(consumer)
    }

    fn unrealize(&mut self) -> Result<()> {
        unregister_consumer(self.device_id());
        Ok(())
    }

    fn cancel_packet(&mut self, _packet: &Arc<Mutex<UsbPacket>>) {}

    fn reset(&mut self) {
        info!("Consumer device reset");
        self.base.remote_wakeup = 0;
        self.base.addr = 0;
        self.hid.reset();
    }

    fn handle_control(&mut self, packet: &Arc<Mutex<UsbPacket>>, device_req: &UsbDeviceRequest) {
        let mut locked_packet = packet.lock().unwrap();
        match self
            .base
            .handle_control_for_descriptor(&mut locked_packet, device_req)
        {
            Ok(handled) => {
                if handled {
                    debug!("Consumer control handled by descriptor, return directly.");
                    return;
                }
            }
            Err(e) => {
                warn!(
                    "Received incorrect USB Consumer descriptor message: {:?}",
                    e
                );
                locked_packet.status = UsbPacketStatus::Stall;
                return;
            }
        }
        self.hid
            .handle_control_packet(&mut locked_packet, device_req, &mut self.base.data_buf);
    }

    fn handle_data(&mut self, p: &Arc<Mutex<UsbPacket>>) {
        let mut locked_p = p.lock().unwrap();
        self.hid.handle_data_packet(&mut locked_p);
    }

    fn set_controller(&mut self, cntlr: Weak<Mutex<XhciDevice>>) {
        self.cntlr = Some(cntlr);
    }

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        self.cntlr.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ui::input::MEDIA_PLAY_PAUSE;

    #[test]
    #[cfg(feature = "usb_consumer")]
    fn test_consumer_interface() {
        let hid_descriptor_data = &DESC_IFACE_CONSUMER.clone().other_desc[0].data;
        let data_len = hid_descriptor_data.len();
        assert_eq!(
            hid_descriptor_data[data_len - 2] as usize,
            CONSUMER_REPORT_DESCRIPTOR.len()
        );
        let interface_descriptor = &DESC_IFACE_CONSUMER.clone().interface_desc;
        // bInterfaceClass: 3(HID)
        assert_eq!(interface_descriptor.bInterfaceClass, 3);
        // bInterfaceSubClass: 0(No Subclass) 1(Boot Interface Subclass) 2-255(Reserved)
        assert_eq!(interface_descriptor.bInterfaceSubClass, 0);
        // bInterfaceProtocol: 0(None) 1(Keyboard) 2(Mouse) 3-255(Reserved)
        assert_eq!(interface_descriptor.bInterfaceProtocol, 0);
    }

    #[test]
    #[cfg(feature = "usb_consumer")]
    fn test_usb_device_method() {
        let mut consumer = UsbConsumer::new(UsbConsumerConfig {
            classtype: "usb-consumer".to_string(),
            id: "consumer".to_string(),
            bus: None,
            port: None,
        });

        let _ = &consumer.reset();
        let _ = &consumer.unrealize();
        let _ = &consumer.get_controller();
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_OUT_REQUEST,
            request: USB_REQUEST_SET_ADDRESS,
            value: 0,
            index: 0,
            length: 0,
        };
        let target_dev =
            Arc::downgrade(&Arc::new(Mutex::new(consumer))) as Weak<Mutex<dyn UsbDevice>>;
        let packet = Arc::new(Mutex::new(UsbPacket::new(
            1,
            u32::from(USB_TOKEN_OUT),
            0,
            0,
            Vec::new(),
            None,
            Some(target_dev),
        )));
        let mut consumer = UsbConsumer::new(UsbConsumerConfig {
            classtype: "usb-consumer".to_string(),
            id: "consumer".to_string(),
            bus: None,
            port: None,
        });
        let _ = &consumer.handle_control(&packet, &device_req);
        let _ = &consumer.handle_data(&packet);
        let _ = &consumer.cancel_packet(&packet);
        let _ = &consumer.realize();
    }

    #[test]
    #[cfg(feature = "usb_consumer")]
    fn test_consumer_event() {
        let mut usb_adapter = UsbConsumerAdapter {
            usb_consumer: Arc::new(Mutex::new(UsbConsumer::new(UsbConsumerConfig {
                classtype: "usb-consumer".to_string(),
                id: "consumer".to_string(),
                bus: None,
                port: None,
            }))),
        };
        let _ = usb_adapter.do_consumer_event(MEDIA_PLAY_PAUSE, true);
        let _ = usb_adapter.do_consumer_event(MEDIA_PLAY_PAUSE, false);
    }
}
