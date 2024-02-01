// Copyright (c) 2023 China Telecom Co.,Ltd. All rights reserved.
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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use log::{error, info};
use vmm_sys_util::eventfd::EventFd;

use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysRes};
use crate::{Device, DeviceBase};
use acpi::{
    AcpiError, AcpiLocalApic, AmlAcquire, AmlAddressSpaceType, AmlArg, AmlBuffer, AmlBuilder,
    AmlCallWithArgs1, AmlCallWithArgs2, AmlCallWithArgs4, AmlDevice, AmlEisaId, AmlEqual, AmlField,
    AmlFieldAccessType, AmlFieldLockRule, AmlFieldUnit, AmlFieldUpdateRule, AmlIf, AmlInteger,
    AmlLocal, AmlMethod, AmlMutex, AmlName, AmlNameDecl, AmlNotify, AmlOne, AmlOpRegion,
    AmlQWordDesc, AmlRelease, AmlResTemplate, AmlReturn, AmlScopeBuilder, AmlStore, AmlString,
    AmlZero,
};
use address_space::GuestAddress;
use cpu::{CPUBootConfig, CPUInterface, CPUTopology, CpuLifecycleState, CPU};
use migration::MigrationManager;

const CPU_ENABLE_FLAG: u8 = 1;
const CPU_INSERTING_FLAG: u8 = 2;
const CPU_REMOVING_FLAG: u8 = 4;
const CPU_EJECT_FLAG: u8 = 8;

const CPU_SELECTION_OFFSET: u64 = 0;
const CPU_STATUS_OFFSET: u64 = 1;
const CPU_EVENT_CODE_OFFSET: u64 = 2;

const MADT_CPU_ENABLE_FLAG: usize = 0;

#[derive(Clone)]
pub struct CpuConfig {
    // Boot config.
    boot_config: CPUBootConfig,
    // Cpu topology.
    cpu_topology: CPUTopology,
}

impl CpuConfig {
    pub fn new(boot_config: CPUBootConfig, cpu_topology: CPUTopology) -> Self {
        CpuConfig {
            boot_config,
            cpu_topology,
        }
    }
}

#[derive(Clone, Default)]
pub struct CpuController {
    base: SysBusDevBase,
    max_cpus: u8,
    // Hotplug options:
    //  true - hotplug a vcpu.
    //  false - hotunplug a vcpu.
    //  None  - nothing.
    hotplug: Option<Arc<AtomicBool>>,
    // Device id of vcpu need to hotplug.
    device_id: String,
    // Vcpu id need to hotplug or hotunplug.
    vcpu_id: Arc<AtomicU8>,
    // Map of hotplug vcpu id and device id.
    id_map: HashMap<u8, String>,
    // Map of all vcpu id and vcpu of vm.
    vcpu_map: HashMap<u8, Arc<CPU>>,
    // Acpi selected cpu id (for status check).
    selected_cpu: u8,
    // Cpu config information.
    cpu_config: Option<CpuConfig>,
    // Hotplug cpu request.
    hotplug_cpu_req: Option<Arc<EventFd>>,
}

impl CpuController {
    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        max_cpus: u8,
        region_base: u64,
        region_size: u64,
        cpu_config: CpuConfig,
        hotplug_cpu_req: Arc<EventFd>,
    ) -> Result<Arc<Mutex<CpuController>>> {
        self.max_cpus = max_cpus;
        self.cpu_config = Some(cpu_config);
        self.hotplug_cpu_req = Some(hotplug_cpu_req);
        self.set_sys_resource(sysbus, region_base, region_size)
            .with_context(|| AcpiError::Alignment(region_size.try_into().unwrap()))?;
        let dev = Arc::new(Mutex::new(self));
        let ret_dev = dev.clone();
        sysbus.attach_device(&dev, region_base, region_size, "CPUController")?;
        Ok(ret_dev)
    }

    fn eject_cpu(&mut self, vcpu_id: u8) -> Result<()> {
        let vcpu = self.vcpu_map.get(&vcpu_id).unwrap();
        vcpu.destroy()?;
        self.id_map.insert(vcpu_id, "".to_string());
        Ok(())
    }

    fn get_cpu_state(&self, vcpu_id: u8) -> Result<CpuLifecycleState> {
        if let Some(vcpu) = self.vcpu_map.get(&vcpu_id) {
            let (vcpu_state, _) = vcpu.state();
            Ok(*vcpu_state.lock().unwrap())
        } else {
            Ok(CpuLifecycleState::Stopped)
        }
    }

    pub fn check_id_existed(&self, input_device_id: &str, input_vcpu_id: u8) -> Result<()> {
        for (vcpu_id, id) in &self.id_map {
            if id == input_device_id {
                bail!("Device id {} already existed.", input_device_id)
            }
            // If vcpu id exist and device id is not empty, this vcpu is running.
            if vcpu_id == &input_vcpu_id && !id.is_empty() {
                bail!("Cpu-id {} is running, device id is {}.", input_vcpu_id, id)
            }
        }
        Ok(())
    }

    pub fn find_cpu_by_device_id(&self, input_device_id: &str) -> Option<u8> {
        for (vcpu_id, id) in &self.id_map {
            if id == input_device_id {
                return Some(*vcpu_id);
            }
        }
        None
    }

    pub fn find_reusable_vcpu(&mut self) -> Option<Arc<CPU>> {
        // If vcpu id exist and device id is empty, this vcpu is hotunplugged, can be reused.
        let input_vcpu_id = self.vcpu_id.load(Ordering::SeqCst);
        for (vcpu_id, device_id) in &self.id_map {
            if vcpu_id == &input_vcpu_id && device_id.is_empty() {
                let vcpu = self.vcpu_map.get(vcpu_id).unwrap().clone();
                return Some(vcpu);
            }
        }
        None
    }

    pub fn get_boot_config(&self) -> &CPUBootConfig {
        &self.cpu_config.as_ref().unwrap().boot_config
    }

    pub fn get_hotplug_cpu_info(&self) -> (String, u8) {
        let device_id = self.device_id.clone();
        let vcpu_id = self.vcpu_id.load(Ordering::SeqCst);
        (device_id, vcpu_id)
    }

    pub fn set_hotplug_cpu_info(&mut self, device_id: String, vcpu_id: u8) -> Result<()> {
        self.device_id = device_id;
        self.vcpu_id.store(vcpu_id, Ordering::SeqCst);
        Ok(())
    }

    pub fn get_topology_config(&self) -> &CPUTopology {
        &self.cpu_config.as_ref().unwrap().cpu_topology
    }

    pub fn setup_reuse_vcpu(&mut self, vcpu: Arc<CPU>) -> Result<()> {
        let device_id = self.device_id.clone();
        let vcpu_id = self.vcpu_id.load(Ordering::SeqCst);
        let (state, _) = vcpu.state();
        let mut vcpu_state = state.lock().unwrap();
        *vcpu_state = CpuLifecycleState::Created;
        drop(vcpu_state);

        MigrationManager::register_cpu_instance(cpu::ArchCPU::descriptor(), vcpu, vcpu_id);
        if let Some(plug) = &self.hotplug {
            plug.store(true, Ordering::SeqCst);
        } else {
            self.hotplug = Some(Arc::new(AtomicBool::new(true)));
        }
        self.id_map.insert(vcpu_id, device_id);
        Ok(())
    }

    pub fn set_boot_vcpu(&mut self, boot_vcpus: Vec<Arc<CPU>>) -> Result<()> {
        for (k, v) in boot_vcpus.iter().enumerate() {
            self.vcpu_map.insert(k.try_into().unwrap(), v.clone());
        }
        Ok(())
    }

    pub fn setup_hotplug_vcpu(
        &mut self,
        device_id: String,
        vcpu_id: u8,
        vcpu: Arc<CPU>,
    ) -> Result<()> {
        // Register vcpu instance.
        MigrationManager::register_cpu_instance(cpu::ArchCPU::descriptor(), vcpu.clone(), vcpu_id);
        // Set operate.
        if let Some(plug) = &self.hotplug {
            plug.store(true, Ordering::SeqCst);
        } else {
            self.hotplug = Some(Arc::new(AtomicBool::new(true)));
        }
        self.id_map.insert(vcpu_id, device_id);
        self.vcpu_map.insert(vcpu_id, vcpu);
        Ok(())
    }

    pub fn set_hotunplug_cpu(&mut self, vcpu_id: u8) -> Result<()> {
        if let Some(plug) = &self.hotplug {
            plug.store(false, Ordering::SeqCst);
        } else {
            self.hotplug = Some(Arc::new(AtomicBool::new(false)));
        }
        self.vcpu_id.store(vcpu_id, Ordering::SeqCst);
        Ok(())
    }

    pub fn trigger_hotplug_cpu(&mut self) -> Result<()> {
        self.hotplug_cpu_req
            .as_ref()
            .unwrap()
            .write(1)
            .with_context(|| "Failed to write cpu hotplug request.")?;
        Ok(())
    }
}

impl Device for CpuController {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for CpuController {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        data[0] = 0;
        match offset {
            CPU_SELECTION_OFFSET => {
                let vcpu_id = self.vcpu_id.load(Ordering::SeqCst);
                data[0] = vcpu_id;
            }
            CPU_STATUS_OFFSET => {
                let state = self.get_cpu_state(self.selected_cpu).unwrap();
                if state == CpuLifecycleState::Running {
                    data[0] |= CPU_ENABLE_FLAG;
                }

                if let Some(hotplug) = &self.hotplug {
                    if hotplug.load(Ordering::SeqCst) {
                        data[0] |= CPU_INSERTING_FLAG;
                    } else {
                        data[0] |= CPU_REMOVING_FLAG;
                    }
                }
            }
            _ => {
                error!("Unexpected offset for accessing CpuController: {}", offset);
                return false;
            }
        }
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            CPU_SELECTION_OFFSET => self.selected_cpu = data[0],
            CPU_STATUS_OFFSET => {
                match data[0] {
                    // Reset hotplug flag after cpu inserting notified.
                    CPU_INSERTING_FLAG => self.hotplug = None,

                    // Reset hotplug flag after cpu removing notified.
                    CPU_REMOVING_FLAG => self.hotplug = None,

                    // Eject vcpu after guest os eject cpu device.
                    CPU_EJECT_FLAG => {
                        let vcpu_id = self.vcpu_id.load(Ordering::SeqCst);
                        if let Err(_e) = self.eject_cpu(vcpu_id) {
                            error!("Eject cpu-{} failed", vcpu_id)
                        }
                    }
                    _ => {
                        error!(
                            "Unexpected data[0] value for cpu status offset: {}",
                            data[0]
                        );
                        return false;
                    }
                }
            }
            CPU_EVENT_CODE_OFFSET => {
                info!("Receive _OST event code {}", data[0]);
            }
            _ => {
                error!(
                    "Unexpected offset for write CpuController device: {}",
                    offset
                );
                return false;
            }
        }
        true
    }

    fn get_sys_resource_mut(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.base.res)
    }
}

impl AmlBuilder for CpuController {
    fn aml_bytes(&self) -> Vec<u8> {
        let res = self.base.res;
        let mut cpu_hotplug_controller = AmlDevice::new("PRES");
        cpu_hotplug_controller.append_child(AmlNameDecl::new("_HID", AmlEisaId::new("PNP0A06")));
        cpu_hotplug_controller.append_child(AmlNameDecl::new(
            "_UID",
            AmlString("CPU Hotplug Controller".into()),
        ));
        cpu_hotplug_controller.append_child(AmlMutex::new("CPLK", 0));
        let mut crs = AmlResTemplate::new();
        crs.append_child(AmlQWordDesc::new_memory(
            acpi::AmlAddressSpaceDecode::Positive,
            acpi::AmlCacheable::Cacheable,
            acpi::AmlReadAndWrite::ReadWrite,
            0,
            res.region_base,
            res.region_base + res.region_size - 1,
            0,
            res.region_size,
        ));
        cpu_hotplug_controller.append_child(AmlNameDecl::new("_CRS", crs));
        let prst = AmlOpRegion::new(
            "PRST",
            AmlAddressSpaceType::SystemMemory,
            res.region_base,
            res.region_size,
        );
        cpu_hotplug_controller.append_child(prst);

        let mut prst_field = AmlField::new(
            "PRST",
            AmlFieldAccessType::Byte,
            AmlFieldLockRule::NoLock,
            AmlFieldUpdateRule::WriteAsZeros,
        );

        prst_field.append_child(AmlFieldUnit::new("CPID".into(), 8));
        prst_field.append_child(AmlFieldUnit::new("CPEN".into(), 1));
        prst_field.append_child(AmlFieldUnit::new("CINS".into(), 1));
        prst_field.append_child(AmlFieldUnit::new("CRMV".into(), 1));
        prst_field.append_child(AmlFieldUnit::new("CEJ_".into(), 1));
        prst_field.append_child(AmlFieldUnit::new(None, 4));
        prst_field.append_child(AmlFieldUnit::new("CEVC".into(), 8));

        cpu_hotplug_controller.append_child(prst_field);
        cpu_hotplug_controller.append_child(AmlCpuStatusMethod {});
        cpu_hotplug_controller.append_child(AmlCpuStatusIndicationMethod {});
        cpu_hotplug_controller.append_child(AmlCpuEjectMethod {});
        cpu_hotplug_controller.append_child(AmlCpuNotifyMethod {
            cpus_count: self.max_cpus,
        });
        cpu_hotplug_controller.append_child(AmlCpuResizeMethod {});

        for cpu_id in 0..self.max_cpus {
            cpu_hotplug_controller.append_child(AmlCpu {
                cpu_id,
                dynamic: true,
            })
        }
        cpu_hotplug_controller.aml_bytes()
    }
}

pub struct AmlCpu {
    pub cpu_id: u8,
    pub dynamic: bool,
}

impl AmlCpu {
    fn generate_mat(&self) -> Vec<u8> {
        let lapic = AcpiLocalApic {
            type_id: 0,
            length: 8,
            processor_uid: self.cpu_id,
            apic_id: self.cpu_id,
            flags: 1 << MADT_CPU_ENABLE_FLAG,
        };

        let mut mat_data: Vec<u8> = Vec::new();
        mat_data.resize(std::mem::size_of_val(&lapic), 0);
        // SAFETY: mat_data is large enough to hold lapic.
        unsafe { *(mat_data.as_mut_ptr() as *mut AcpiLocalApic) = lapic };

        mat_data
    }

    fn sta_method(&self, return_value: Option<u64>) -> AmlMethod {
        let mut sta_method = AmlMethod::new("_STA", 0, false);
        if let Some(value) = return_value {
            sta_method.append_child(AmlReturn::with_value(AmlInteger(value)));
        } else {
            let call_method_csta = AmlCallWithArgs1::new("CSTA", AmlInteger(self.cpu_id.into()));
            sta_method.append_child(AmlReturn::with_value(call_method_csta));
        }
        sta_method
    }

    fn mat_name(&self) -> AmlNameDecl {
        let mat_buffer = AmlBuffer(self.generate_mat());
        AmlNameDecl::new("_MAT", mat_buffer)
    }

    fn ost_method(&self) -> AmlMethod {
        let mut ost_method = AmlMethod::new("_OST", 3, false);
        ost_method.append_child(AmlReturn::with_value(AmlCallWithArgs4::new(
            "COST",
            AmlInteger(self.cpu_id.into()),
            AmlArg(0),
            AmlArg(1),
            AmlArg(2),
        )));
        ost_method
    }

    fn ej0_method(&self) -> AmlMethod {
        let mut ej0_method = AmlMethod::new("_EJ0", 1, false);
        ej0_method.append_child(AmlCallWithArgs1::new(
            "CEJ0",
            AmlInteger(self.cpu_id.into()),
        ));
        ej0_method
    }
}

impl AmlBuilder for AmlCpu {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut cpu_device = AmlDevice::new(format!("C{:03}", self.cpu_id).as_str());
        cpu_device.append_child(AmlNameDecl::new("_HID", AmlString("ACPI0007".into())));
        cpu_device.append_child(AmlNameDecl::new("_UID", AmlInteger(self.cpu_id.into())));
        cpu_device.append_child(AmlNameDecl::new("_PXM", AmlInteger(0u64)));
        if self.dynamic {
            {
                cpu_device.append_child(self.sta_method(None));
                cpu_device.append_child(self.mat_name());
                cpu_device.append_child(self.ost_method());
                cpu_device.append_child(self.ej0_method());
            }
        } else {
            cpu_device.append_child(self.sta_method(Some(0xfu64)));
            cpu_device.append_child(self.mat_name());
        }
        cpu_device.aml_bytes()
    }
}

pub struct AmlCpuStatusIndicationMethod {}

impl AmlBuilder for AmlCpuStatusIndicationMethod {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut cpu_status_indication_method = AmlMethod::new("COST", 4, false);
        cpu_status_indication_method
            .append_child(AmlAcquire::new(AmlName("\\_SB.PRES.CPLK".into()), 0xffff));
        cpu_status_indication_method
            .append_child(AmlStore::new(AmlArg(2), AmlName("\\_SB.PRES.CEVC".into())));
        cpu_status_indication_method
            .append_child(AmlRelease::new(AmlName("\\_SB.PRES.CPLK".to_string())));
        cpu_status_indication_method.aml_bytes()
    }
}

pub struct AmlCpuNotifyMethod {
    pub cpus_count: u8,
}

impl AmlBuilder for AmlCpuNotifyMethod {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut cpu_notify_method = AmlMethod::new("CTFY", 2, true);
        for cpu_id in 0..self.cpus_count {
            let mut if_scope = AmlIf::new(AmlEqual::new(AmlArg(0), AmlInteger(cpu_id.into())));
            if_scope.append_child(AmlNotify::new(
                AmlName(format!("C{:03}", cpu_id)),
                AmlArg(1),
            ));
            cpu_notify_method.append_child(if_scope);
        }
        cpu_notify_method.aml_bytes()
    }
}

pub struct AmlCpuStatusMethod {}

impl AmlBuilder for AmlCpuStatusMethod {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut csta_method = AmlMethod::new("CSTA", 1, true);
        csta_method.append_child(AmlAcquire::new(AmlName("\\_SB.PRES.CPLK".into()), 0xffff));
        csta_method.append_child(AmlStore::new(AmlZero, AmlLocal(0)));
        csta_method.append_child(AmlStore::new(AmlArg(0), AmlName("\\_SB.PRES.CPID".into())));

        let mut if_scope = AmlIf::new(AmlEqual::new(AmlName("\\_SB.PRES.CPEN".into()), AmlOne));
        if_scope.append_child(AmlStore::new(AmlInteger(0xfu64), AmlLocal(0)));
        csta_method.append_child(if_scope);
        csta_method.append_child(AmlRelease::new(AmlName("\\_SB.PRES.CPLK".to_string())));
        csta_method.append_child(AmlReturn::with_value(AmlLocal(0)));
        csta_method.aml_bytes()
    }
}

pub struct AmlCpuEjectMethod {}

impl AmlBuilder for AmlCpuEjectMethod {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut eject_method = AmlMethod::new("CEJ0", 1, true);
        eject_method.append_child(AmlAcquire::new(AmlName("\\_SB.PRES.CPLK".into()), 0xffff));
        eject_method.append_child(AmlStore::new(AmlOne, AmlName("\\_SB.PRES.CEJ_".into())));
        eject_method.append_child(AmlRelease::new(AmlName("\\_SB.PRES.CPLK".to_string())));
        eject_method.aml_bytes()
    }
}

pub struct AmlCpuResizeMethod {}

impl AmlBuilder for AmlCpuResizeMethod {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut cscn_method = AmlMethod::new("CSCN", 1, true);
        cscn_method.append_child(AmlAcquire::new(AmlName("\\_SB.PRES.CPLK".into()), 0xffff));
        cscn_method.append_child(AmlStore::new(
            AmlName("\\_SB.PRES.CPID".into()),
            AmlLocal(0),
        ));

        let mut if_plug_scope =
            AmlIf::new(AmlEqual::new(AmlName("\\_SB.PRES.CINS".into()), AmlOne));
        if_plug_scope.append_child(AmlCallWithArgs2::new("CTFY", AmlLocal(0), AmlOne));
        if_plug_scope.append_child(AmlStore::new(AmlOne, AmlName("\\_SB.PRES.CINS".into())));
        cscn_method.append_child(if_plug_scope);

        let mut if_unplug_scope =
            AmlIf::new(AmlEqual::new(AmlName("\\_SB.PRES.CRMV".into()), AmlOne));
        if_unplug_scope.append_child(AmlCallWithArgs2::new("CTFY", AmlLocal(0), AmlInteger(3u64)));
        if_unplug_scope.append_child(AmlStore::new(AmlOne, AmlName("\\_SB.PRES.CRMV".into())));
        cscn_method.append_child(if_unplug_scope);

        cscn_method.append_child(AmlRelease::new(AmlName("\\_SB.PRES.CPLK".to_string())));
        cscn_method.aml_bytes()
    }
}
