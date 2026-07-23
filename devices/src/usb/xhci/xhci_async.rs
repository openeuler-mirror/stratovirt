// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{Builder, JoinHandle};

use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use log::error;

use crate::usb::config::{
    PLS_U0, PORTSC_PED, PORTSC_PR, PORTSC_PRC, PORTSC_WRC, USB_SPEED_FULL, USB_SPEED_HIGH,
    USB_SPEED_LOW, USB_SPEED_SUPER,
};

use crate::usb::xhci::xhci_pci::XhciPciDevice;
use crate::usb::{UsbResp, XhciDevice, USB_DEL_RESP};
use crate::Device;

#[cfg(feature = "usb_host")]
use crate::usb::{
    usbhost::{UsbHost, UsbHostConfig, USBHOST_ADD_RESP},
    UsbDevice,
};

use machine_manager::{
    config::VmConfig,
    event,
    qmp::{
        qmp_channel::QmpChannel,
        qmp_schema::{DeviceClassSubType, VmNotifyEvent, DEVICE_CLASS_ID},
    },
};

static ASYNC_CMD_SENDER: OnceLock<Sender<XhciAsyncCmd>> = OnceLock::new();

pub enum XhciAsyncCmd {
    PortReset {
        xhci: Arc<Mutex<XhciDevice>>,
        port_id: u8,
        warm: bool,
    },
    DeviceDetach {
        id: String,
        parent_dev: Arc<Mutex<dyn Device + 'static>>,
        vm_config: Arc<Mutex<VmConfig>>,
    },
    #[cfg(feature = "usb_host")]
    UsbHostAdd {
        config: UsbHostConfig,
        parent_dev: Arc<Mutex<dyn Device + 'static>>,
        vm_config: Arc<Mutex<VmConfig>>,
    },
}

pub fn send_async_xhci_cmd(cmd: XhciAsyncCmd) -> Result<()> {
    let sender = ASYNC_CMD_SENDER
        .get()
        .ok_or_else(|| anyhow!("xhci async sender is not initialized"))?;

    sender
        .send(cmd)
        .map_err(|e| anyhow!("failed to send xhci async cmd: {:?}", e))
}

pub struct AsyncCmdHandler {
    reader: Receiver<XhciAsyncCmd>,
}

impl AsyncCmdHandler {
    pub fn init() -> Result<JoinHandle<()>> {
        let (cmd_tx, cmd_rx) = channel::<XhciAsyncCmd>();

        if ASYNC_CMD_SENDER.set(cmd_tx).is_err() {
            bail!("xhci async sender has already been initialized");
        }

        let handler = AsyncCmdHandler { reader: cmd_rx };
        Self::run_thread(handler)
    }

    fn run_thread(handler: Self) -> Result<JoinHandle<()>> {
        Builder::new()
            .name("xhci async worker".to_string())
            .spawn(move || {
                for cmd in &handler.reader {
                    if let Err(e) = match cmd {
                        XhciAsyncCmd::PortReset {
                            xhci,
                            port_id,
                            warm,
                        } => handler
                            .handle_port_reset(xhci, port_id, warm)
                            .with_context(|| "failed to hand port reset"),

                        XhciAsyncCmd::DeviceDetach {
                            id,
                            parent_dev,
                            vm_config,
                        } => handler
                            .handle_device_detach(id, parent_dev, vm_config)
                            .with_context(|| "failed to handle device detach"),

                        #[cfg(feature = "usb_host")]
                        XhciAsyncCmd::UsbHostAdd {
                            config,
                            parent_dev,
                            vm_config,
                        } => handler
                            .handle_usbhost_device_attach(config, parent_dev, vm_config)
                            .with_context(|| "failed to handle usbhost device attach"),
                    } {
                        error!("{:?}", e);
                    }
                }
            })
            .with_context(|| "failed to start xhci async thread")
    }

    fn handle_port_reset(
        &self,
        xhci: Arc<Mutex<XhciDevice>>,
        port_id: u8,
        warm: bool,
    ) -> Result<()> {
        if port_id == 0 || port_id as usize > xhci.lock().unwrap().usb_ports.len() {
            bail!("failed to reset port due to invalid port id");
        }

        let port = xhci.lock().unwrap().usb_ports[port_id as usize - 1].clone();
        trace::usb_xhci_port_reset(&port_id, &warm);

        let usb_dev = port.lock().unwrap().dev.clone();

        if let Some(ref dev) = usb_dev {
            dev.lock().unwrap().force_reset();
        } else {
            return Ok(());
        }

        {
            let mut locked_port = port.lock().unwrap();
            let speed = usb_dev.unwrap().lock().unwrap().speed();
            if speed == USB_SPEED_SUPER && warm {
                locked_port.portsc |= PORTSC_WRC;
            }
            match speed {
                USB_SPEED_LOW | USB_SPEED_FULL | USB_SPEED_HIGH | USB_SPEED_SUPER => {
                    locked_port.set_port_link_state(PLS_U0);
                    trace::usb_xhci_port_link(&locked_port.port_id, &PLS_U0);
                    locked_port.portsc |= PORTSC_PED;
                }
                _ => {
                    error!("Invalid speed {}", speed);
                }
            }
            locked_port.portsc &= !PORTSC_PR;
        }

        xhci.lock()
            .unwrap()
            .port_notify(&port, PORTSC_PRC)
            .with_context(|| "failed to notify port reset change, {:?}")
    }

    fn handle_device_detach(
        &self,
        id: String,
        parent_dev: Arc<Mutex<dyn Device + 'static>>,
        vm_config: Arc<Mutex<VmConfig>>,
    ) -> Result<()> {
        let detach_result = {
            let locked_parent_dev = parent_dev.lock().unwrap();
            let xhci_pci = locked_parent_dev
                .as_any()
                .downcast_ref::<XhciPciDevice>()
                .with_context(|| "PciDevOps can not downcast to XhciPciDevice")?;

            xhci_pci.detach_device(&id)
        };

        vm_config.lock().unwrap().del_device_by_id(&id);
        let state_msg = match detach_result {
            Ok(_) => "Detach usb device success".to_string(),
            Err(ref e) => {
                format!("Detach usb device failed: {:?}", e)
            }
        };

        let detail = UsbResp {
            device: Some(id.clone()),
            state_msg: Some(state_msg),
        };

        let message_str =
            serde_json::to_string(&detail).expect("failed to serialize usb host response detail");

        let resp = VmNotifyEvent {
            klass: DEVICE_CLASS_ID,
            type_t: DeviceClassSubType::USBHOST.into(),
            code: USB_DEL_RESP,
            message: Some(message_str),
        };
        event!(VmNotifyEvent; resp);
        detach_result.with_context(|| format!("failed to handle detach for device {}", id))
    }

    #[cfg(feature = "usb_host")]
    fn handle_usbhost_device_attach(
        &self,
        config: UsbHostConfig,
        parent_dev: Arc<Mutex<dyn Device + 'static>>,
        vm_config: Arc<Mutex<VmConfig>>,
    ) -> Result<()> {
        let dev_id = config.id.clone();

        let state_msg = match initialize_usb_host(config, parent_dev) {
            Ok(_) => "Add usb host device success".to_string(),
            Err(e) => {
                error!("Usb host device initialization failed: {:?}", e);
                vm_config.lock().unwrap().del_device_by_id(&dev_id);
                format!("Usb host device initialization failed: {:?}", e)
            }
        };

        let detail = UsbResp {
            device: Some(dev_id),
            state_msg: Some(state_msg),
        };

        let message_str =
            serde_json::to_string(&detail).expect("failed to serialize usb host response detail");

        let resp = VmNotifyEvent {
            klass: DEVICE_CLASS_ID,
            type_t: DeviceClassSubType::USBHOST.into(),
            code: USBHOST_ADD_RESP,
            message: Some(message_str),
        };

        event!(VmNotifyEvent; resp);

        Ok(())
    }
}

#[cfg(feature = "usb_host")]
fn initialize_usb_host(config: UsbHostConfig, parent_dev: Arc<Mutex<dyn Device>>) -> Result<()> {
    let usbhost = UsbHost::new(config).with_context(|| "failed to create usb host device")?;
    let usbhost = usbhost
        .realize()
        .with_context(|| "failed to realize usb host device")?;

    let parent = parent_dev.lock().unwrap();
    let xhci_pci = parent
        .as_any()
        .downcast_ref::<XhciPciDevice>()
        .ok_or_else(|| anyhow!("failed to downcast PciDevOps to XhciPciDevice"))?;

    xhci_pci
        .attach_device(&usbhost)
        .with_context(|| "failed to attach usb host device to xhci controller")
}
