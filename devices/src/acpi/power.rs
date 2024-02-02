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

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use log::info;

use crate::acpi::ged::{AcpiEvent, Ged};
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysRes};
use crate::{Device, DeviceBase};
use acpi::{
    AcpiError, AmlAddressSpaceType, AmlBuilder, AmlDevice, AmlField, AmlFieldAccessType,
    AmlFieldLockRule, AmlFieldUnit, AmlFieldUpdateRule, AmlIndex, AmlInteger, AmlMethod, AmlName,
    AmlNameDecl, AmlOpRegion, AmlPackage, AmlReturn, AmlScopeBuilder, AmlStore, AmlString, AmlZero,
};
use address_space::GuestAddress;
use machine_manager::event_loop::EventLoop;
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::num_ops::write_data_u32;

const AML_ACAD_REG: &str = "ADPM";
const AML_ACAD_ONLINE: &str = "ADPO";

const AML_ACAD_REG_SZ: u64 = 4;

const AML_BAT0_REG: &str = "BATM";
const AML_BAT0_DESIGN_CAP: &str = "DCAP";
const AML_BAT0_LAST_FULL_CAP: &str = "LFC";
const AML_BAT0_DESIGN_VOLTAGE: &str = "DV";
const AML_BAT0_STATE: &str = "ST";
const AML_BAT0_PRESENT_RATE: &str = "PRT";
const AML_BAT0_REM_CAP: &str = "RCAP";
const AML_BAT0_PRES_VOLT: &str = "PV";

const POWERDEV_REGS_SIZE: usize = 8;
const REG_IDX_ACAD_ON: usize = 0;
const REG_IDX_BAT_DCAP: usize = 1;
const REG_IDX_BAT_FCAP: usize = 2;
const REG_IDX_BAT_DVOLT: usize = 3;
const REG_IDX_BAT_STATE: usize = 4;
const REG_IDX_BAT_PRATE: usize = 5;
const REG_IDX_BAT_RCAP: usize = 6;
const REG_IDX_BAT_PVOLT: usize = 7;

const ACPI_BATTERY_STATE_DISCHARGING: u32 = 0x1;
const ACPI_BATTERY_STATE_CHARGING: u32 = 0x2;

const ACAD_SYSFS_DIR: &str = "/sys/class/power_supply/Mains";
const BAT_SYSFS_DIR: &str = "/sys/class/power_supply/Battery";

#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
struct PowerDevState {
    last_acad_st: u32,
    last_bat_st: u32,
    last_bat_lvl: u32,
}

#[derive(Clone)]
pub struct PowerDev {
    base: SysBusDevBase,
    regs: Vec<u32>,
    state: PowerDevState,
    ged: Arc<Mutex<Ged>>,
}

impl PowerDev {
    pub fn new(ged_dev: Arc<Mutex<Ged>>) -> Self {
        Self {
            base: SysBusDevBase::default(),
            regs: vec![0; POWERDEV_REGS_SIZE],
            state: PowerDevState {
                last_acad_st: 1,
                last_bat_st: ACPI_BATTERY_STATE_CHARGING,
                last_bat_lvl: 0xffffffff,
            },
            ged: ged_dev,
        }
    }

    fn read_sysfs_power_props(
        &self,
        dir_name: &str,
        sysfs_props: &Vec<&str>,
        pdev_props: &mut [u32],
    ) -> Result<()> {
        for i in 0..sysfs_props.len() {
            let df = format!("{}/{}", dir_name, sysfs_props[i]);
            let path = Path::new(&df);
            let sprop = std::fs::read_to_string(path).with_context(|| {
                format!("Can't read power device property: {}", path.display(),)
            })?;
            let prop = sprop[..sprop.len() - 1].parse::<i64>().with_context(|| {
                format!(
                    "Can't parse power device property: {} value: {}",
                    path.display(),
                    sprop
                )
            })?;
            // All the values except "online" property is multiplicated by 1000.
            // Only "online" property starts with 'o' character.
            pdev_props[i] = if sysfs_props[i].starts_with('o') {
                prop.unsigned_abs() as u32
            } else {
                (prop.abs() / 1000) as u32
            };
        }
        Ok(())
    }

    fn power_battery_init_info(&mut self) -> Result<()> {
        let bat_sysfs_props = vec!["energy_full_design", "energy_full", "voltage_max_design"];
        let mut props: Vec<u32> = vec![0; bat_sysfs_props.len()];
        self.read_sysfs_power_props(BAT_SYSFS_DIR, &bat_sysfs_props, &mut props)?;
        self.regs[REG_IDX_BAT_DCAP] = props[0];
        self.regs[REG_IDX_BAT_FCAP] = props[1];
        self.regs[REG_IDX_BAT_DVOLT] = props[2];
        Ok(())
    }

    fn power_status_read(&mut self) -> Result<()> {
        let acad_props = vec!["online"];
        let bat_sysfs_props = vec!["online", "current_now", "energy_now", "voltage_now"];
        let mut props: Vec<u32> = vec![0; bat_sysfs_props.len()];

        self.read_sysfs_power_props(ACAD_SYSFS_DIR, &acad_props, &mut props)?;
        self.regs[REG_IDX_ACAD_ON] = props[0];

        self.read_sysfs_power_props(BAT_SYSFS_DIR, &bat_sysfs_props, &mut props)?;
        self.regs[REG_IDX_BAT_STATE] = if props[0] == 1 {
            ACPI_BATTERY_STATE_CHARGING
        } else {
            ACPI_BATTERY_STATE_DISCHARGING
        };
        // unit: mA
        self.regs[REG_IDX_BAT_PRATE] = props[1];
        self.regs[REG_IDX_BAT_RCAP] = props[2];
        self.regs[REG_IDX_BAT_PVOLT] = props[3];
        // unit: mW
        self.regs[REG_IDX_BAT_PRATE] =
            (self.regs[REG_IDX_BAT_PRATE] * self.regs[REG_IDX_BAT_PVOLT]) / 1000;
        Ok(())
    }

    fn power_load_static_status(&mut self) {
        info!("Load static power devices status");
        self.regs[REG_IDX_ACAD_ON] = 1;
        self.regs[REG_IDX_BAT_DCAP] = 0xffffffff;
        self.regs[REG_IDX_BAT_FCAP] = 0xffffffff;
        self.regs[REG_IDX_BAT_DVOLT] = 0xffffffff;
        self.regs[REG_IDX_BAT_STATE] = ACPI_BATTERY_STATE_CHARGING;
        self.regs[REG_IDX_BAT_PRATE] = 0;
        self.regs[REG_IDX_BAT_RCAP] = 0xffffffff;
        self.regs[REG_IDX_BAT_PVOLT] = 0xffffffff;
    }

    fn send_power_event(&self, evt: AcpiEvent) {
        self.ged.lock().unwrap().inject_acpi_event(evt);
    }
}

impl PowerDev {
    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
    ) -> Result<()> {
        self.set_sys_resource(sysbus, region_base, region_size)
            .with_context(|| AcpiError::Alignment(region_size as u32))?;

        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size, "PowerDev")?;

        let pdev_available: bool;
        {
            let mut pdev = dev.lock().unwrap();
            pdev_available = pdev.power_battery_init_info().is_ok();
            if pdev_available {
                pdev.send_power_event(AcpiEvent::BatteryInf);
            }
        }
        if pdev_available {
            power_status_update(&dev.clone());
        } else {
            let mut pdev = dev.lock().unwrap();
            pdev.power_load_static_status();
        }
        Ok(())
    }
}

impl StateTransfer for PowerDev {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        Ok(self.state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        self.state.as_mut_bytes().copy_from_slice(state);
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&PowerDevState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for PowerDev {
    fn resume(&mut self) -> Result<()> {
        self.send_power_event(AcpiEvent::AcadSt);
        self.send_power_event(AcpiEvent::BatterySt);
        Ok(())
    }
}

impl Device for PowerDev {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for PowerDev {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let reg_idx: u64 = offset / 4;
        if reg_idx >= self.regs.len() as u64 {
            return false;
        }
        let value = self.regs[reg_idx as usize];
        write_data_u32(data, value)
    }

    fn write(&mut self, _data: &[u8], _base: GuestAddress, _offset: u64) -> bool {
        true
    }

    fn get_sys_resource_mut(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.base.res)
    }
}

impl AmlBuilder for PowerDev {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut acpi_acad_dev = AmlDevice::new("ACAD");
        acpi_acad_dev.append_child(AmlNameDecl::new("_HID", AmlString("ACPI0003".to_string())));

        acpi_acad_dev.append_child(AmlOpRegion::new(
            AML_ACAD_REG,
            AmlAddressSpaceType::SystemMemory,
            self.base.res.region_base,
            AML_ACAD_REG_SZ,
        ));

        let mut field = AmlField::new(
            AML_ACAD_REG,
            AmlFieldAccessType::DWord,
            AmlFieldLockRule::NoLock,
            AmlFieldUpdateRule::WriteAsZeros,
        );

        field.append_child(AmlFieldUnit::new(Some(AML_ACAD_ONLINE), 32));
        acpi_acad_dev.append_child(field);

        let mut pcl_pkg = AmlPackage::new(1);
        pcl_pkg.append_child(AmlName("\\_SB".to_string()));
        acpi_acad_dev.append_child(AmlNameDecl::new("_PCL", pcl_pkg));

        let mut method = AmlMethod::new("_STA", 0, false);
        method.append_child(AmlReturn::with_value(AmlInteger(0x0F)));

        acpi_acad_dev.append_child(method);

        method = AmlMethod::new("_PSR", 0, false);
        method.append_child(AmlReturn::with_value(AmlName(AML_ACAD_ONLINE.to_string())));
        acpi_acad_dev.append_child(method);

        let mut acpi_bat_dev = AmlDevice::new("BAT0");
        acpi_bat_dev.append_child(AmlNameDecl::new("_HID", AmlString("PNP0C0A".to_string())));

        acpi_bat_dev.append_child(AmlOpRegion::new(
            AML_BAT0_REG,
            AmlAddressSpaceType::SystemMemory,
            self.base.res.region_base + AML_ACAD_REG_SZ,
            self.base.res.region_size - AML_ACAD_REG_SZ,
        ));

        field = AmlField::new(
            AML_BAT0_REG,
            AmlFieldAccessType::DWord,
            AmlFieldLockRule::NoLock,
            AmlFieldUpdateRule::WriteAsZeros,
        );
        field.append_child(AmlFieldUnit::new(Some(AML_BAT0_DESIGN_CAP), 32));
        field.append_child(AmlFieldUnit::new(Some(AML_BAT0_LAST_FULL_CAP), 32));
        field.append_child(AmlFieldUnit::new(Some(AML_BAT0_DESIGN_VOLTAGE), 32));
        field.append_child(AmlFieldUnit::new(Some(AML_BAT0_STATE), 32));
        field.append_child(AmlFieldUnit::new(Some(AML_BAT0_PRESENT_RATE), 32));
        field.append_child(AmlFieldUnit::new(Some(AML_BAT0_REM_CAP), 32));
        field.append_child(AmlFieldUnit::new(Some(AML_BAT0_PRES_VOLT), 32));
        acpi_bat_dev.append_child(field);

        pcl_pkg = AmlPackage::new(1);
        pcl_pkg.append_child(AmlName("\\_SB".to_string()));
        acpi_bat_dev.append_child(AmlNameDecl::new("_PCL", pcl_pkg));

        method = AmlMethod::new("_STA", 0, false);
        method.append_child(AmlInteger(0x1F));
        acpi_bat_dev.append_child(method);

        let mut bif_pkg = AmlPackage::new(13);
        bif_pkg.append_child(AmlInteger(0x0));
        bif_pkg.append_child(AmlInteger(0xFFFFFFFF));
        bif_pkg.append_child(AmlInteger(0xFFFFFFFF));
        bif_pkg.append_child(AmlInteger(0x1));
        bif_pkg.append_child(AmlInteger(0xFFFFFFFF));
        bif_pkg.append_child(AmlInteger(0x00000100));
        bif_pkg.append_child(AmlInteger(0x00000050));
        bif_pkg.append_child(AmlInteger(1));
        bif_pkg.append_child(AmlInteger(1));
        bif_pkg.append_child(AmlString("SVBATM1".to_string()));
        bif_pkg.append_child(AmlString("000001".to_string()));
        bif_pkg.append_child(AmlString("LI-ON".to_string()));
        bif_pkg.append_child(AmlString("SVIRT".to_string()));
        acpi_bat_dev.append_child(AmlNameDecl::new("PBIF", bif_pkg));

        method = AmlMethod::new("_BIF", 0, false);
        method.append_child(AmlStore::new(
            AmlName(AML_BAT0_DESIGN_CAP.to_string()),
            AmlIndex::new(AmlName("PBIF".to_string()), AmlInteger(1), AmlZero),
        ));
        method.append_child(AmlStore::new(
            AmlName(AML_BAT0_LAST_FULL_CAP.to_string()),
            AmlIndex::new(AmlName("PBIF".to_string()), AmlInteger(2), AmlZero),
        ));
        method.append_child(AmlStore::new(
            AmlName(AML_BAT0_DESIGN_VOLTAGE.to_string()),
            AmlIndex::new(AmlName("PBIF".to_string()), AmlInteger(4), AmlZero),
        ));
        method.append_child(AmlReturn::with_value(AmlName("PBIF".to_string())));
        acpi_bat_dev.append_child(method);

        let mut bst_pkg = AmlPackage::new(4);
        bst_pkg.append_child(AmlInteger(ACPI_BATTERY_STATE_CHARGING as u64));
        bst_pkg.append_child(AmlInteger(0xFFFFFFFF));
        bst_pkg.append_child(AmlInteger(0xFFFFFFFF));
        bst_pkg.append_child(AmlInteger(0xFFFFFFFF));
        acpi_bat_dev.append_child(AmlNameDecl::new("PBST", bst_pkg));

        method = AmlMethod::new("_BST", 0, false);
        method.append_child(AmlStore::new(
            AmlName(AML_BAT0_STATE.to_string()),
            AmlIndex::new(AmlName("PBST".to_string()), AmlInteger(0), AmlZero),
        ));
        method.append_child(AmlStore::new(
            AmlName(AML_BAT0_PRESENT_RATE.to_string()),
            AmlIndex::new(AmlName("PBST".to_string()), AmlInteger(1), AmlZero),
        ));
        method.append_child(AmlStore::new(
            AmlName(AML_BAT0_REM_CAP.to_string()),
            AmlIndex::new(AmlName("PBST".to_string()), AmlInteger(2), AmlZero),
        ));
        method.append_child(AmlStore::new(
            AmlName(AML_BAT0_PRES_VOLT.to_string()),
            AmlIndex::new(AmlName("PBST".to_string()), AmlInteger(3), AmlZero),
        ));
        method.append_child(AmlReturn::with_value(AmlName("PBST".to_string())));
        acpi_bat_dev.append_child(method);

        acpi_acad_dev
            .aml_bytes()
            .into_iter()
            .chain(acpi_bat_dev.aml_bytes().into_iter())
            .collect()
    }
}

fn power_status_update(dev: &Arc<Mutex<PowerDev>>) {
    let cdev = dev.clone();
    let update_func = Box::new(move || {
        power_status_update(&cdev);
    });

    let mut pdev = dev.lock().unwrap();

    if pdev.power_status_read().is_ok() {
        let step2notify: u32 = pdev.regs[REG_IDX_BAT_FCAP] / 100;
        let bdiff: u32 = pdev.regs[REG_IDX_BAT_RCAP].abs_diff(pdev.state.last_bat_lvl);

        if pdev.state.last_acad_st != pdev.regs[REG_IDX_ACAD_ON] {
            pdev.send_power_event(AcpiEvent::AcadSt);
            pdev.state.last_acad_st = pdev.regs[REG_IDX_ACAD_ON];
        }
        if pdev.state.last_bat_st != pdev.regs[REG_IDX_BAT_STATE] || bdiff >= step2notify {
            pdev.send_power_event(AcpiEvent::BatterySt);
            pdev.state.last_bat_st = pdev.regs[REG_IDX_BAT_STATE];
            pdev.state.last_bat_lvl = pdev.regs[REG_IDX_BAT_RCAP];
        }

        EventLoop::get_ctx(None)
            .unwrap()
            .timer_add(update_func, Duration::from_secs(5));
    } else {
        pdev.power_load_static_status();
    }
}
