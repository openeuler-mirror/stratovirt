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

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};

use super::TpmInterfaceType;
use crate::legacy::error::LegacyError;
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType};
use crate::{convert_bus_mut, Device, DeviceBase, MUT_SYS_BUS};
use acpi::{
    AmlBuilder, AmlDevice, AmlInteger, AmlMemory32Fixed, AmlNameDecl, AmlReadAndWrite,
    AmlResTemplate, AmlScopeBuilder, AmlString,
};
use address_space::GuestAddress;
use tpm::{
    emulator::{Emulator, Result as EmulatorResult},
    OnComplete, TPM_CRB_BUFFER_MAX,
};
use util::gen_base_func;

const CRB_DATA_BUFFER: u32 = 0x80;

const TPM_CRB_R_MAX: usize = CRB_DATA_BUFFER as usize;

#[allow(dead_code)]
pub struct TpmCrb {
    base: SysBusDevBase,
    emulator: Emulator<TpmCrb>,
    regs: [u32; TPM_CRB_R_MAX],
    backend_buff_size: usize,
    data_buff: [u8; TPM_CRB_BUFFER_MAX],
    data_buff_len: usize,
}

impl TpmCrb {
    pub fn new(
        sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let emulator = Emulator::new(path)
            .map_err(|e| anyhow!("Failed while initializing tpm Emulator: {e:?}"))?;
        let mutex_emulator =
            Arc::try_unwrap(emulator).map_err(|_| anyhow!("not the only owner"))?;
        let inner_emulator = mutex_emulator.into_inner().map_err(|_| anyhow!("poison"))?;

        let mut tpm = TpmCrb {
            base: SysBusDevBase::new(SysBusDevType::Tpm(TpmInterfaceType::Crb)),
            emulator: inner_emulator,
            regs: [0; TPM_CRB_R_MAX],
            backend_buff_size: TPM_CRB_BUFFER_MAX,
            data_buff: [0; TPM_CRB_BUFFER_MAX],
            data_buff_len: 0,
        };

        tpm.set_sys_resource(sysbus, region_base, region_size, "TPM-CRB")
            .with_context(|| LegacyError::SetSysResErr)?;
        tpm.set_parent_bus(sysbus.clone());

        Ok(tpm)
    }
}

impl OnComplete for TpmCrb {
    fn on_complete(&mut self, _r: EmulatorResult<usize>, _b: Vec<u8>) {}
}

impl Device for TpmCrb {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn realize(self) -> Result<Arc<Mutex<Self>>> {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        MUT_SYS_BUS!(parent_bus, locked_bus, sysbus);
        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev)?;

        Ok(dev)
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        Ok(())
    }
}

impl SysBusDevOps for TpmCrb {
    gen_base_func!(sysbusdev_base, sysbusdev_base_mut, SysBusDevBase, base);

    /// Read data from registers by guest
    fn read(&mut self, _data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
        true
    }

    /// Write data to registers by guest
    fn write(&mut self, _data: &[u8], _base: GuestAddress, _offset: u64) -> bool {
        true
    }
}

impl AmlBuilder for TpmCrb {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut tpm2_dev = AmlDevice::new("TPM2");
        tpm2_dev.append_child(AmlNameDecl::new("_HID", AmlString("MSFT0101".to_string())));
        tpm2_dev.append_child(AmlNameDecl::new("_STA", AmlInteger(0xF)));

        let mut res = AmlResTemplate::new();
        res.append_child(AmlMemory32Fixed::new(
            AmlReadAndWrite::ReadWrite,
            self.base.res.region_base as u32,
            self.base.res.region_size as u32,
        ));
        tpm2_dev.append_child(AmlNameDecl::new("_CRS", res));

        tpm2_dev.aml_bytes()
    }
}
