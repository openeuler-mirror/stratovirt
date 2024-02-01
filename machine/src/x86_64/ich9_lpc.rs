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

use anyhow::{Context, Result};
use log::error;
use vmm_sys_util::eventfd::EventFd;

use crate::x86_64::standard::VENDOR_ID_INTEL;
use acpi::{AcpiPMTimer, AcpiPmCtrl, AcpiPmEvent};
use address_space::{AddressSpace, GuestAddress, Region, RegionOps};
use devices::pci::config::{
    PciConfig, CLASS_CODE_ISA_BRIDGE, DEVICE_ID, HEADER_TYPE, HEADER_TYPE_BRIDGE,
    HEADER_TYPE_MULTIFUNC, PCI_CONFIG_SPACE_SIZE, SUB_CLASS_CODE, VENDOR_ID,
};
use devices::pci::{le_write_u16, le_write_u32, PciBus, PciDevBase, PciDevOps};
use devices::{Device, DeviceBase};
use util::byte_code::ByteCode;
use util::num_ops::ranges_overlap;

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
    base: PciDevBase,
    sys_io: Arc<AddressSpace>,
    pm_timer: Arc<Mutex<AcpiPMTimer>>,
    rst_ctrl: Arc<AtomicU8>,
    pm_evt: Arc<Mutex<AcpiPmEvent>>,
    pm_ctrl: Arc<Mutex<AcpiPmCtrl>>,
    /// Reset request triggered by ACPI PM1 Control Registers.
    pub reset_req: Arc<EventFd>,
    pub shutdown_req: Arc<EventFd>,
}

impl LPCBridge {
    pub fn new(
        parent_bus: Weak<Mutex<PciBus>>,
        sys_io: Arc<AddressSpace>,
        reset_req: Arc<EventFd>,
        shutdown_req: Arc<EventFd>,
    ) -> Result<Self> {
        Ok(Self {
            base: PciDevBase {
                base: DeviceBase::new("ICH9 LPC bridge".to_string(), false),
                config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
                devfn: 0x1F << 3,
                parent_bus,
            },
            sys_io,
            pm_timer: Arc::new(Mutex::new(AcpiPMTimer::new())),
            pm_evt: Arc::new(Mutex::new(AcpiPmEvent::new())),
            pm_ctrl: Arc::new(Mutex::new(AcpiPmCtrl::new())),
            rst_ctrl: Arc::new(AtomicU8::new(0)),
            reset_req,
            shutdown_req,
        })
    }

    fn update_pm_base(&mut self) -> Result<()> {
        let cloned_pmtmr = self.pm_timer.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_pmtmr.lock().unwrap().read(data, addr, offset)
        };
        let write_ops = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool { false };
        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let pmtmr_region = Region::init_io_region(0x8, ops, "PmtmrRegion");

        let mut pm_base_addr = 0_u32;
        self.base
            .config
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
        let cloned_reset_fd = self.reset_req.clone();
        let write_ops = move |data: &[u8], _addr: GuestAddress, _offset: u64| -> bool {
            let value: u8 = match data.len() {
                1 => data[0],
                n => {
                    error!("Invalid data length {}", n);
                    return false;
                }
            };
            if value & 0x4_u8 != 0 {
                if cloned_reset_fd.write(1).is_err() {
                    error!("X86 standard vm write reset fd failed");
                    return false;
                }
                return true;
            }
            cloned_rst_ctrl.store(value & 0xA, Ordering::SeqCst);
            true
        };

        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let rst_ctrl_region = Region::init_io_region(0x1, ops, "RstCtrlRegion");
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

        let cloned_shutdown_fd = self.shutdown_req.clone();
        let write_ops = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool {
            if cloned_shutdown_fd.write(1).is_err() {
                error!("X86 standard vm write shutdown fd failed");
                return false;
            }
            true
        };

        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let sleep_reg_region = Region::init_io_region(0x1, ops, "SleepReg");
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
        let pm_evt_region = Region::init_io_region(0x4, ops, "PmEvtRegion");
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
        let cloned_shutdown_fd = self.shutdown_req.clone();
        let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
            if clone_pmctrl.lock().unwrap().write(data, addr, offset)
                && cloned_shutdown_fd.write(1).is_err()
            {
                error!("X86 standard vm write shutdown fd failed");
                return false;
            }
            true
        };

        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let pm_ctrl_region = Region::init_io_region(0x4, ops, "PmCtrl");
        self.sys_io
            .root()
            .add_subregion(pm_ctrl_region, PM_CTRL_OFFSET as u64)?;

        Ok(())
    }
}

impl Device for LPCBridge {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl PciDevOps for LPCBridge {
    fn pci_base(&self) -> &PciDevBase {
        &self.base
    }

    fn pci_base_mut(&mut self) -> &mut PciDevBase {
        &mut self.base
    }

    fn realize(mut self) -> Result<()> {
        self.init_write_mask(false)?;
        self.init_write_clear_mask(false)?;

        le_write_u16(
            &mut self.base.config.config,
            VENDOR_ID as usize,
            VENDOR_ID_INTEL,
        )?;
        le_write_u16(
            &mut self.base.config.config,
            DEVICE_ID as usize,
            DEVICE_ID_INTEL_ICH9,
        )?;
        le_write_u16(
            &mut self.base.config.config,
            SUB_CLASS_CODE as usize,
            CLASS_CODE_ISA_BRIDGE,
        )?;
        le_write_u32(
            &mut self.base.config.write_mask,
            PM_BASE_OFFSET as usize,
            0xff80,
        )?;
        le_write_u16(
            &mut self.base.config.config,
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

        let parent_bus = self.base.parent_bus.clone();
        parent_bus
            .upgrade()
            .unwrap()
            .lock()
            .unwrap()
            .devices
            .insert(0x1F << 3, Arc::new(Mutex::new(self)));
        Ok(())
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        self.base.config.write(offset, data, 0, None, None);
        // SAFETY: offset is no more than 0xfff.
        if ranges_overlap(offset, data.len(), PM_BASE_OFFSET as usize, 4).unwrap() {
            if let Err(e) = self.update_pm_base() {
                error!("Failed to update PM base addr: {:?}", e);
            }
        }
    }
}
