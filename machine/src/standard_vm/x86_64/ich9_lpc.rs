// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, Mutex, Weak,
};

use super::VENDOR_ID_INTEL;
use crate::standard_vm::Result;
use acpi::{AcpiPMTimer, AcpiPmCtrl, AcpiPmEvent};
use address_space::{AddressSpace, GuestAddress, Region, RegionOps};
use anyhow::Context;
use log::error;
use pci::config::CLASS_CODE_ISA_BRIDGE;
use pci::config::{
    PciConfig, DEVICE_ID, HEADER_TYPE, HEADER_TYPE_BRIDGE, HEADER_TYPE_MULTIFUNC,
    PCI_CONFIG_SPACE_SIZE, SUB_CLASS_CODE, VENDOR_ID,
};
use pci::Result as PciResult;
use pci::{le_write_u16, le_write_u32, ranges_overlap, PciBus, PciDevOps};
use util::byte_code::ByteCode;
use vmm_sys_util::eventfd::EventFd;

const DEVICE_ID_INTEL_ICH9: u16 = 0x2918;

const PM_BASE_OFFSET: u8 = 0x40;
const PM_TIMER_OFFSET: u8 = 8;
pub const PM_EVENT_OFFSET: u16 = 0x600;
pub const PM_CTRL_OFFSET: u16 = 0x604;
pub const SLEEP_CTRL_OFFSET: u16 = 0xCE9;
pub const RST_CTRL_OFFSET: u16 = 0xCF9;

/// LPC bridge of ICH9 (IO controller hub 9), Device 1F : Function 0
#[allow(clippy::upper_case_acronyms)]
pub struct LPCBridge {
    config: PciConfig,
    parent_bus: Weak<Mutex<PciBus>>,
    sys_io: Arc<AddressSpace>,
    pm_timer: Arc<Mutex<AcpiPMTimer>>,
    rst_ctrl: Arc<AtomicU8>,
    pm_evt: Arc<Mutex<AcpiPmEvent>>,
    pm_ctrl: Arc<Mutex<AcpiPmCtrl>>,
    /// Reset request trigged by ACPI PM1 Control Registers.
    pub reset_req: EventFd,
    pub shutdown_req: EventFd,
}

impl LPCBridge {
    pub fn new(parent_bus: Weak<Mutex<PciBus>>, sys_io: Arc<AddressSpace>) -> Self {
        Self {
            config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
            parent_bus,
            sys_io,
            pm_timer: Arc::new(Mutex::new(AcpiPMTimer::new())),
            pm_evt: Arc::new(Mutex::new(AcpiPmEvent::new())),
            pm_ctrl: Arc::new(Mutex::new(AcpiPmCtrl::new())),
            rst_ctrl: Arc::new(AtomicU8::new(0)),
            reset_req: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            shutdown_req: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }

    fn update_pm_base(&self) -> Result<()> {
        let cloned_pmtmr = self.pm_timer.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_pmtmr.lock().unwrap().read(data, addr, offset)
        };
        let write_ops = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool { false };
        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let pmtmr_region = Region::init_io_region(0x8, ops);

        let mut pm_base_addr = 0_u32;
        self.config
            .read(PM_BASE_OFFSET as usize, pm_base_addr.as_mut_bytes());
        self.sys_io
            .root()
            .add_subregion(pmtmr_region, pm_base_addr as u64 + PM_TIMER_OFFSET as u64)?;

        Ok(())
    }

    fn init_reset_ctrl_reg(&self) -> Result<()> {
        let cloned_rst_ctrl = self.rst_ctrl.clone();
        let read_ops = move |data: &mut [u8], _addr: GuestAddress, _offset: u64| -> bool {
            let ret_ctrl = cloned_rst_ctrl.load(Ordering::SeqCst);
            match data.len() {
                1 => data[0] = ret_ctrl,
                n => {
                    error!("Invalid data length {}", n);
                    return false;
                }
            }
            true
        };

        let cloned_rst_ctrl = self.rst_ctrl.clone();
        let cloned_reset_fd = self.reset_req.try_clone().unwrap();
        let write_ops = move |data: &[u8], _addr: GuestAddress, _offset: u64| -> bool {
            let value: u8 = match data.len() {
                1 => data[0],
                n => {
                    error!("Invalid data length {}", n);
                    return false;
                }
            };
            if value & 0x4_u8 != 0 {
                cloned_reset_fd.write(1).unwrap();
                return true;
            }
            cloned_rst_ctrl.store(value & 0xA, Ordering::SeqCst);
            true
        };

        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let rst_ctrl_region = Region::init_io_region(0x1, ops);
        self.sys_io
            .root()
            .add_subregion(rst_ctrl_region, RST_CTRL_OFFSET as u64)?;

        Ok(())
    }

    fn init_sleep_reg(&self) -> Result<()> {
        let read_ops = move |data: &mut [u8], _addr: GuestAddress, _offset: u64| -> bool {
            data.fill(0);
            true
        };

        let cloned_shutdown_fd = self.shutdown_req.try_clone().unwrap();
        let write_ops = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool {
            cloned_shutdown_fd.write(1).unwrap();
            true
        };

        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let sleep_reg_region = Region::init_io_region(0x1, ops);
        self.sys_io
            .root()
            .add_subregion(sleep_reg_region, SLEEP_CTRL_OFFSET as u64)?;
        Ok(())
    }

    fn init_pm_evt_reg(&self) -> Result<()> {
        let cloned_pmevt = self.pm_evt.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_pmevt.lock().unwrap().read(data, addr, offset)
        };

        let cloned_pmevt = self.pm_evt.clone();
        let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_pmevt.lock().unwrap().write(data, addr, offset)
        };

        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let pm_evt_region = Region::init_io_region(0x4, ops);
        self.sys_io
            .root()
            .add_subregion(pm_evt_region, PM_EVENT_OFFSET as u64)?;

        Ok(())
    }

    fn init_pm_ctrl_reg(&self) -> Result<()> {
        let clone_pmctrl = self.pm_ctrl.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            clone_pmctrl.lock().unwrap().read(data, addr, offset)
        };

        let clone_pmctrl = self.pm_ctrl.clone();
        let cloned_shutdown_fd = self.shutdown_req.try_clone().unwrap();
        let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
            if clone_pmctrl.lock().unwrap().write(data, addr, offset) {
                cloned_shutdown_fd.write(1).unwrap();
            }
            true
        };

        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let pm_ctrl_region = Region::init_io_region(0x4, ops);
        self.sys_io
            .root()
            .add_subregion(pm_ctrl_region, PM_CTRL_OFFSET as u64)?;

        Ok(())
    }
}

impl PciDevOps for LPCBridge {
    fn init_write_mask(&mut self) -> PciResult<()> {
        self.config.init_common_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> PciResult<()> {
        self.config.init_common_write_clear_mask()
    }

    fn realize(mut self) -> PciResult<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;

        le_write_u16(&mut self.config.config, VENDOR_ID as usize, VENDOR_ID_INTEL)?;
        le_write_u16(
            &mut self.config.config,
            DEVICE_ID as usize,
            DEVICE_ID_INTEL_ICH9,
        )?;
        le_write_u16(
            &mut self.config.config,
            SUB_CLASS_CODE as usize,
            CLASS_CODE_ISA_BRIDGE,
        )?;
        le_write_u32(&mut self.config.write_mask, PM_BASE_OFFSET as usize, 0xff80)?;
        le_write_u16(
            &mut self.config.config,
            HEADER_TYPE as usize,
            (HEADER_TYPE_BRIDGE | HEADER_TYPE_MULTIFUNC) as u16,
        )?;

        self.init_sleep_reg()
            .with_context(|| "Fail to init IO region for sleep control register")?;

        self.init_reset_ctrl_reg()
            .with_context(|| "Fail to init IO region for reset control register")?;

        self.init_pm_evt_reg()
            .with_context(|| "Fail to init IO region for PM events register")?;
        self.init_pm_ctrl_reg()
            .with_context(|| "Fail to init IO region for PM control register")?;

        let parent_bus = self.parent_bus.clone();
        parent_bus
            .upgrade()
            .unwrap()
            .lock()
            .unwrap()
            .devices
            .insert(0x1F << 3, Arc::new(Mutex::new(self)));
        Ok(())
    }

    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        self.config.read(offset, data);
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let end = offset + data.len();

        self.config.write(offset, data, 0, None, None);
        if ranges_overlap(
            offset,
            end,
            PM_BASE_OFFSET as usize,
            PM_BASE_OFFSET as usize + 4,
        ) {
            if let Err(e) = self.update_pm_base() {
                error!("Failed to update PM base addr: {:?}", e);
            }
        }
    }

    fn name(&self) -> String {
        "ICH9 LPC bridge".to_string()
    }
}
