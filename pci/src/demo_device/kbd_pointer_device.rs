// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// Demo keyboard-pointer device is a simple pci device. It can be used to test whether
// VNC can correctly receive the input from the client and transmit it to the keyboard and pointer device
// Users can write a rom address in the mmio configuration space of the device.
// Then if an input event occurs, the event information will be recorded to the corresponding memory by this device.

use address_space::{AddressSpace, GuestAddress};
use byteorder::{ByteOrder, LittleEndian};
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use vnc::input::{register_keyboard, register_pointer, KeyboardOpts, PointerOpts};

use anyhow::{bail, Result};

use crate::demo_dev::DeviceTypeOperation;
static MEM_ADDR: Lazy<Arc<Mutex<MemSpace>>> = Lazy::new(|| {
    Arc::new(Mutex::new(MemSpace {
        sys_mem: None,
        addr: None,
    }))
});

pub struct MemSpace {
    pub sys_mem: Option<Arc<AddressSpace>>,
    pub addr: Option<u64>,
}

impl MemSpace {
    pub fn send_kbdmouse_message(&mut self, msg: &PointerMessage) -> Result<()> {
        let sys_mem = match &self.sys_mem {
            Some(m) => m,
            None => {
                bail!("Memory space is not initialized!")
            }
        };
        let addr = match self.addr {
            Some(a) => a,
            None => {
                bail!("No memory allocated!")
            }
        };
        sys_mem.write_object(&(msg.event_type as u8), address_space::GuestAddress(addr))?;
        sys_mem.write_object(&msg.keycode, address_space::GuestAddress(addr + 1))?;
        sys_mem.write_object(&msg.down, address_space::GuestAddress(addr + 3))?;
        sys_mem.write_object(&msg.button, address_space::GuestAddress(addr + 4))?;
        sys_mem.write_object(&msg.x, address_space::GuestAddress(addr + 8))?;
        sys_mem.write_object(&msg.y, address_space::GuestAddress(addr + 12))?;

        Ok(())
    }
}

pub struct DemoKbdMouse {
    pub sys_mem: Arc<AddressSpace>,
    pub kbd_name: String,
    pub pointer_name: String,
    pub test_kbd: Arc<Mutex<dyn KeyboardOpts>>,
    pub test_pointer: Arc<Mutex<dyn PointerOpts>>,
}

impl DemoKbdMouse {
    pub fn new(sys_mem: Arc<AddressSpace>) -> Self {
        MEM_ADDR.lock().unwrap().sys_mem = Some(sys_mem.clone());
        Self {
            sys_mem,
            kbd_name: "test-pci-keyboard".to_string(),
            pointer_name: "test-pci-pointer".to_string(),
            test_kbd: Arc::new(Mutex::new(TestPciKbd {})),
            test_pointer: Arc::new(Mutex::new(TestPciPointer {})),
        }
    }
}

pub struct TestPciKbd {}

impl KeyboardOpts for TestPciKbd {
    fn do_key_event(&mut self, keycode: u16, down: bool) -> Result<()> {
        let msg = PointerMessage {
            event_type: InputEvent::KbdEvent,
            keycode,
            down: down as u8,
            ..Default::default()
        };
        MEM_ADDR.lock().unwrap().send_kbdmouse_message(&msg)
    }
}

pub struct TestPciPointer {}

impl PointerOpts for TestPciPointer {
    fn do_point_event(&mut self, button: u32, x: u32, y: u32) -> Result<()> {
        let msg = PointerMessage {
            event_type: InputEvent::PointerEvent,
            button: button as u32,
            x,
            y,
            ..Default::default()
        };
        MEM_ADDR.lock().unwrap().send_kbdmouse_message(&msg)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    KbdEvent = 0,
    PointerEvent = 1,
    InvalidEvent = 2,
}

impl Default for InputEvent {
    fn default() -> Self {
        InputEvent::InvalidEvent
    }
}

impl From<u8> for InputEvent {
    fn from(v: u8) -> Self {
        match v {
            0 => InputEvent::KbdEvent,
            1 => InputEvent::PointerEvent,
            _ => InputEvent::InvalidEvent,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PointerMessage {
    pub event_type: InputEvent,
    pub keycode: u16,
    pub down: u8,
    pub button: u32,
    pub x: u32,
    pub y: u32,
}

impl DeviceTypeOperation for DemoKbdMouse {
    fn read(&mut self, _data: &mut [u8], _addr: GuestAddress, _offset: u64) -> Result<()> {
        Ok(())
    }

    fn write(&mut self, data: &[u8], _addr: GuestAddress, _offset: u64) -> Result<()> {
        let mem_addr = LittleEndian::read_u64(data);
        MEM_ADDR.lock().unwrap().addr = Some(mem_addr);
        Ok(())
    }

    fn realize(&mut self) -> Result<()> {
        let test_kbd = self.test_kbd.clone();
        let test_pointer = self.test_pointer.clone();
        register_keyboard(&self.kbd_name, test_kbd);
        register_pointer(&self.pointer_name, test_pointer);
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }
}
