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

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::legacy::error::LegacyError;
use crate::misc::tpm::TpmInterfaceType;
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType};
use crate::{convert_bus_mut, Device, DeviceBase, MUT_SYS_BUS};
use acpi::{
    AmlActiveLevel, AmlBuilder, AmlDevice, AmlEdgeLevel, AmlExtendedInterrupt, AmlIntShare,
    AmlInteger, AmlMemory32Fixed, AmlNameDecl, AmlReadAndWrite, AmlResTemplate, AmlResourceUsage,
    AmlScopeBuilder, AmlString,
};
#[cfg(target_arch = "aarch64")]
use acpi::{INTERRUPT_PPIS_COUNT, INTERRUPT_SGIS_COUNT};
use address_space::GuestAddress;
use tpm::{
    emulator::{Emulator, Result as EmulatorResult},
    OnComplete, TPM_TIS_BUFFER_MAX,
};
use util::gen_base_func;

pub const TPM_TIS_NUM_LOCALITIES: usize = 5;
pub const TPM_TIS_NO_LOCALITY: u8 = 0xff;
pub const TPM_TIS_LOCALITY_SHIFT: u8 = 12;

pub const TPM_TIS_ACCESS_TPM_REG_VALID_STS: u8 = 1 << 7;
pub const TPM_TIS_STS_TPM_FAMILY2_0: u32 = 1 << 26;

pub const TPM_TIS_CAP_INTERRUPT_LOW_LEVEL: u32 = 1 << 4;
pub const TPM_TIS_CAP_BURST_COUNT_DYNAMIC: u32 = 0 << 8;
pub const TPM_TIS_CAP_DATA_TRANSFER_64B: u32 = 3 << 9;
pub const TPM_TIS_CAP_INTERFACE_VERSION1_3_FOR_TPM2_0: u32 = 3 << 28;
pub const TPM_TIS_CAPABILITIES_SUPPORTED2_0: u32 = TPM_TIS_CAP_INTERRUPT_LOW_LEVEL
    | TPM_TIS_CAP_BURST_COUNT_DYNAMIC
    | TPM_TIS_CAP_DATA_TRANSFER_64B
    | TPM_TIS_CAP_INTERFACE_VERSION1_3_FOR_TPM2_0
    | TPM_TIS_INTERRUPTS_SUPPORTED;

pub const TPM_TIS_IFACE_ID_INTERFACE_TIS1_3: u32 = 0xf;
pub const TPM_TIS_IFACE_ID_INTERFACE_FIFO: u32 = 0x0;
pub const TPM_TIS_IFACE_ID_INTERFACE_VER_FIFO: u32 = 0 << 4;
pub const TPM_TIS_IFACE_ID_CAP_5_LOCALITIES: u32 = 1 << 8;
pub const TPM_TIS_IFACE_ID_CAP_TIS_SUPPORTED: u32 = 1 << 13;
pub const TPM_TIS_IFACE_ID_INT_SEL_LOCK: u32 = 1 << 19;

pub const TPM_TIS_IFACE_ID_SUPPORTED_FLAGS2_0: u32 = TPM_TIS_IFACE_ID_INTERFACE_FIFO
    | TPM_TIS_IFACE_ID_INTERFACE_VER_FIFO
    | TPM_TIS_IFACE_ID_CAP_5_LOCALITIES
    | TPM_TIS_IFACE_ID_CAP_TIS_SUPPORTED;

pub const TPM_TIS_INT_POLARITY_LOW_LEVEL: u32 = 1 << 3;

pub const TPM_TIS_STS_SELFTEST_DONE: u32 = 1 << 2;
pub const TPM_TIS_STS_TPM_FAMILY_MASK: u32 = 0x3 << 26;
pub const TPM_TIS_STS_COMMAND_CANCEL: u32 = 1 << 24;
pub const TPM_TIS_STS_RESET_ESTABLISHMENT: u32 = 1 << 25;
pub const TPM_TIS_STS_TPM_GO: u32 = 1 << 5;
pub const TPM_TIS_STS_RESPONSE_RETRY: u32 = 1 << 1;

pub const TPM_ST_NO_SESSION: u16 = 0x8001;
pub const TPM_RC_FAILURE: u32 = 0x0101;

pub const TPM_TIS_STS_VALID: u32 = 1 << 7;
pub const TPM_TIS_STS_DATA_AVAILABLE: u32 = 1 << 4;
pub const TPM_TIS_STS_COMMAND_READY: u32 = 1 << 6;
pub const TPM_TIS_INT_DATA_AVAILABLE: u32 = 1 << 0;
pub const TPM_TIS_INT_STS_VALID: u32 = 1 << 1;
pub const TPM_TIS_STS_EXPECT: u32 = 1 << 3;
pub const TPM_TIS_INT_GLOBAL_INT_ENABLE: u32 = 1 << 31;
pub const TPM_TIS_INT_COMMAND_READY: u32 = 1 << 7;

pub const TPM_TIS_ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
pub const TPM_TIS_ACCESS_BEEN_SEIZED: u8 = 1 << 4;
pub const TPM_TIS_ACCESS_SEIZE: u8 = 1 << 3;
pub const TPM_TIS_ACCESS_REQUEST_USE: u8 = 1 << 1;

pub const TPM_TIS_INT_LOCALITY_CHANGED: u32 = 1 << 2;

pub const TPM_TIS_NO_DATA_BYTE: u8 = 0xFF;

pub const TPM_TIS_REG_ACCESS: u16 = 0x00;
pub const TPM_TIS_REG_INT_ENABLE: u16 = 0x08;
pub const TPM_TIS_REG_INT_VECTOR: u16 = 0x0C;
pub const TPM_TIS_REG_INT_STATUS: u16 = 0x10;
pub const TPM_TIS_REG_INTF_CAPABILITY: u16 = 0x14;
pub const TPM_TIS_REG_STS: u16 = 0x18;
pub const TPM_TIS_REG_DATA_FIFO: u16 = 0x24;
pub const TPM_TIS_REG_INTERFACE_ID: u16 = 0x30;
pub const TPM_TIS_REG_DID_VID: u16 = 0xF00;
pub const TPM_TIS_REG_RID: u16 = 0xF04;
pub const TPM_TIS_REG_DATA_XFIFO: u16 = 0x80;
pub const TPM_TIS_REG_DATA_XFIFO_END: u16 = 0xBC;

pub const TPM_TIS_ACCESS_PENDING_REQUEST: u8 = 1 << 2;
pub const TPM_TIS_ACCESS_TPM_ESTABLISHMENT: u8 = 1 << 0;

pub const TPM_TIS_TPM_VID: u32 = 0x1014;
pub const TPM_TIS_TPM_DID: u32 = 0x0001;
pub const TPM_TIS_TPM_RID: u32 = 0x0001;

pub const TPM_TIS_BURST_COUNT_SHIFT: u32 = 8;

pub const TPM_TIS_INT_POLARITY_MASK: u32 = 3 << 3;
pub const TPM_TIS_INTERRUPTS_SUPPORTED: u32 = TPM_TIS_INT_LOCALITY_CHANGED
    | TPM_TIS_INT_DATA_AVAILABLE
    | TPM_TIS_INT_STS_VALID
    | TPM_TIS_INT_COMMAND_READY;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum TpmTisState {
    #[default]
    Idle = 0,
    Ready,
    Completion,
    Execution,
    Reception,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TpmLocality {
    state: TpmTisState,
    access: u8,
    sts: u32,
    iface_id: u32,
    inte: u32,
    ints: u32,
}

impl TpmLocality {
    pub fn set_state(&mut self, state: TpmTisState) {
        self.state = state;
    }

    pub fn set_sts(&mut self, flags: u32) {
        self.sts &= TPM_TIS_STS_SELFTEST_DONE | TPM_TIS_STS_TPM_FAMILY_MASK;
        self.sts |= flags;
    }
}

#[allow(dead_code)]
pub struct TpmTis {
    base: SysBusDevBase,
    buffer: Option<Vec<u8>>,
    rw_offset: u16,
    active_locty: u8,
    aborting_locty: u8,
    next_locty: u8,
    loc: [TpmLocality; TPM_TIS_NUM_LOCALITIES],
    pub emulator: Arc<Mutex<Emulator<TpmTis>>>,
    backend_buff_size: usize,
}

impl TpmTis {
    pub fn new(
        sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let emulator = Emulator::new(path)
            .map_err(|e| anyhow!("Failed while initializing tpm Emulator: {e:?}"))?;

        let mut tpm = TpmTis {
            base: SysBusDevBase::new(SysBusDevType::Tpm(TpmInterfaceType::Tis)),
            buffer: Some(vec![0; TPM_TIS_BUFFER_MAX]),
            rw_offset: 0,
            active_locty: 0,
            aborting_locty: 0,
            next_locty: 0,
            loc: [TpmLocality::default(); TPM_TIS_NUM_LOCALITIES],
            emulator,
            backend_buff_size: TPM_TIS_BUFFER_MAX,
        };
        tpm.set_sys_resource(sysbus, region_base, region_size, "TPM-TIS")
            .with_context(|| LegacyError::SetSysResErr)?;
        tpm.set_parent_bus(sysbus.clone());

        Ok(tpm)
    }
}

impl OnComplete for TpmTis {
    fn on_complete(&mut self, _r: EmulatorResult<usize>, _b: Vec<u8>) {}
}

impl Device for TpmTis {
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

impl SysBusDevOps for TpmTis {
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

impl AmlBuilder for TpmTis {
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

        // interrupt setting
        if self.base.res.irq != -1 {
            // SPI start at interrupt number 32 on aarch64 platform.
            #[cfg(target_arch = "aarch64")]
            let irq_base = INTERRUPT_PPIS_COUNT + INTERRUPT_SGIS_COUNT;
            #[cfg(target_arch = "x86_64")]
            let irq_base = 0;
            res.append_child(AmlExtendedInterrupt::new(
                AmlResourceUsage::Consumer,
                AmlEdgeLevel::Level,
                AmlActiveLevel::High,
                AmlIntShare::Exclusive,
                vec![self.base.res.irq as u32 + irq_base],
            ));
        }

        tpm2_dev.append_child(AmlNameDecl::new("_CRS", res));

        tpm2_dev.aml_bytes()
    }
}
