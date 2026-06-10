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

use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{cmp, thread};

use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use crate::legacy::error::LegacyError;
use crate::misc::tpm::{TpmInterfaceType, TPM_DISCONNECTED_NOTIFY_CODE};
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
use machine_manager::{
    event,
    qmp::qmp_channel::QmpChannel,
    qmp::qmp_schema::{DeviceClassSubType, VmNotifyEvent, DEVICE_CLASS_ID},
};
use migration::{
    snapshot::TPMTIS_SNAPSHOT_ID, DeviceStateDesc, MigrationHook, MigrationManager, StateTransfer,
};
use migration_derive::DescSerde;
use tpm::{
    aio::{
        self, deliver_request, register_async_ctrl_notifier, unregister_async_ctrl_notifier,
        AioError, AsyncMsg, OnComplete,
    },
    emulator::{Emulator, EmulatorError, TPM_RSP_HDR_SIZE, TPM_RSP_PS_OFFSET, TPM_RSP_RC_OFFSET},
    TpmBackend, TpmMigration, TPM_TIS_BUFFER_MAX,
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

#[inline]
fn locality_from_addr(addr: u64) -> u8 {
    let locty = ((addr >> TPM_TIS_LOCALITY_SHIFT) & 0x7) as u8;

    debug_assert!(
        locty < TPM_TIS_NUM_LOCALITIES as u8,
        "Invalid TPM locality parsed from address: {:#x} (locty: {})",
        addr,
        locty
    );

    locty
}

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

#[derive(Clone, Deserialize, Serialize, DescSerde)]
#[desc_version(current_version = "0.1.0")]
pub struct TpmTisSnapshot {
    pub valid_buffer_data: Vec<u8>,
    pub rw_offset: u16,
    pub active_locty: u8,
    pub aborting_locty: u8,
    pub next_locty: u8,
    pub loc_states: [TpmLocality; TPM_TIS_NUM_LOCALITIES],
    pub backend_buff_size: usize,
    pub swtpm_blob: Vec<u8>,
}

pub struct TpmTis {
    base: SysBusDevBase,
    buffer: Option<Vec<u8>>,
    rw_offset: u16,
    active_locty: u8,
    aborting_locty: u8,
    next_locty: u8,
    loc: [TpmLocality; TPM_TIS_NUM_LOCALITIES],
    emulator: Arc<Mutex<Emulator>>,
    backend_buff_size: usize,
    backend_disconnected: bool,
    iothread: Option<String>,
    async_ctrl_evt: Option<Arc<EventFd>>,
}

impl TpmTis {
    pub fn new(
        sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
        path: impl AsRef<Path>,
        iothread: Option<String>,
    ) -> Result<Self> {
        let emulator =
            Arc::new(Mutex::new(Emulator::new(path).map_err(|e| {
                anyhow!("Failed while initializing tpm Emulator: {e:?}")
            })?));

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
            backend_disconnected: false,
            iothread,
            async_ctrl_evt: None,
        };
        tpm.set_sys_resource(sysbus, region_base, region_size, "TPM-TIS")
            .with_context(|| LegacyError::SetSysResErr)?;
        tpm.set_parent_bus(sysbus.clone());

        tpm.reset()?;
        tpm.get_established_flag()?;

        Ok(tpm)
    }

    pub fn reconnect(&mut self, path: impl AsRef<Path>) -> Result<()> {
        info!("Reconnecting vTPM to: {:?}", path.as_ref());

        let new_emulator =
            Arc::new(Mutex::new(Emulator::new(path).map_err(|e| {
                anyhow::anyhow!("Reconnect to swtpm failed: {}", e)
            })?));

        let cur_buff_size = new_emulator.lock().unwrap().get_buffer_size();
        self.backend_buff_size = cmp::min(cur_buff_size, TPM_TIS_BUFFER_MAX);

        if let Err(e) = new_emulator
            .lock()
            .unwrap()
            .startup_tpm(self.backend_buff_size, false)
        {
            return Err(anyhow!("Failed while running Startup TPM. Error: {e:?}"));
        }

        self.emulator = new_emulator;
        self.backend_disconnected = false;

        if let Some(ref evt) = self.async_ctrl_evt {
            evt.write(1)?;
        }

        info!("vTPM reconnect sequence completed successfully.");
        Ok(())
    }

    fn register_update_event(handler: Arc<Mutex<TpmTis>>) -> Result<()> {
        let iothread = handler.lock().unwrap().iothread.clone();
        let async_ctrl_evt = register_async_ctrl_notifier(handler.clone(), iothread)?;
        handler.lock().unwrap().async_ctrl_evt = Some(async_ctrl_evt);
        Ok(())
    }

    fn write_fatal_error_response(&mut self) {
        // TPM 2.0 Error Response Header (10 bytes total)
        // [0..1] Tag: TPM_ST_NO_SESSIONS (0x8001)
        // [2..5] Size: 10 bytes (0x0000000A)
        // [6..9] Response Code: TPM_RC_FAILURE (0x0101) - Hardware error
        if let Some(buffer) = self.buffer.as_mut() {
            if buffer.len() >= 10 {
                buffer[0..TPM_RSP_PS_OFFSET].copy_from_slice(&TPM_ST_NO_SESSION.to_be_bytes());
                buffer[TPM_RSP_PS_OFFSET..TPM_RSP_RC_OFFSET]
                    .copy_from_slice(&(TPM_RSP_HDR_SIZE as u32).to_be_bytes());
                buffer[TPM_RSP_RC_OFFSET..TPM_RSP_HDR_SIZE]
                    .copy_from_slice(&TPM_RC_FAILURE.to_be_bytes());

                self.rw_offset = 10;
            }
        }
    }

    fn raise_irq(&mut self, locty: u8, irq_mask: u32) {
        let locty_idx = locty as usize;

        if locty_idx >= TPM_TIS_NUM_LOCALITIES {
            error!("Attempted to raise IRQ for invalid locality: {}", locty);
            return;
        }

        let loc = &mut self.loc[locty_idx];

        let is_global_enabled = (loc.inte & TPM_TIS_INT_GLOBAL_INT_ENABLE) != 0;
        let is_specific_enabled = (loc.inte & irq_mask) != 0;

        if is_global_enabled && is_specific_enabled {
            loc.ints |= irq_mask;
            if let Err(e) = self.sysbusdev_base().irq_state.raise_irq() {
                error!("Failed to raise irq, {e:?}");
            }
        }
    }

    fn new_active_locality(&mut self, new_active_locty: u8) {
        let change = self.active_locty != new_active_locty;

        if change && self.active_locty < TPM_TIS_NUM_LOCALITIES as u8 {
            let old_locty_idx = self.active_locty as usize;

            let is_seize = new_active_locty < TPM_TIS_NUM_LOCALITIES as u8
                && (self.loc[new_active_locty as usize].access & TPM_TIS_ACCESS_SEIZE) != 0;

            let mask = if is_seize {
                !TPM_TIS_ACCESS_ACTIVE_LOCALITY
            } else {
                !(TPM_TIS_ACCESS_ACTIVE_LOCALITY | TPM_TIS_ACCESS_REQUEST_USE)
            };

            self.loc[old_locty_idx].access &= mask;

            if is_seize {
                self.loc[old_locty_idx].access |= TPM_TIS_ACCESS_BEEN_SEIZED;
            }
        }

        self.active_locty = new_active_locty;

        if new_active_locty < TPM_TIS_NUM_LOCALITIES as u8 {
            let new_locty_idx = new_active_locty as usize;
            self.loc[new_locty_idx].access |= TPM_TIS_ACCESS_ACTIVE_LOCALITY;
            self.loc[new_locty_idx].access &= !(TPM_TIS_ACCESS_REQUEST_USE | TPM_TIS_ACCESS_SEIZE);
        }

        if change {
            self.raise_irq(self.active_locty, TPM_TIS_INT_LOCALITY_CHANGED);
        }
    }

    pub fn abort(&mut self) {
        self.rw_offset = 0;

        debug!("TPM TIS aborting, next locality: {}", self.next_locty);

        if self.aborting_locty == self.next_locty
            && self.aborting_locty < TPM_TIS_NUM_LOCALITIES as u8
        {
            let locty_idx = self.aborting_locty as usize;

            self.loc[locty_idx].set_state(TpmTisState::Ready);
            self.loc[locty_idx].set_sts(TPM_TIS_STS_COMMAND_READY);

            self.raise_irq(self.aborting_locty, TPM_TIS_INT_COMMAND_READY);
        }

        self.new_active_locality(self.next_locty);

        self.next_locty = TPM_TIS_NO_LOCALITY;
        self.aborting_locty = TPM_TIS_NO_LOCALITY;
    }

    pub fn request_completed(&mut self, is_success: bool) {
        let locty = self.active_locty as usize;

        if locty >= TPM_TIS_NUM_LOCALITIES {
            error!(
                "TPM request_completed called with invalid active_locty: {}",
                self.active_locty
            );
            return;
        }

        if is_success {
            for loc in self.loc.iter_mut() {
                loc.sts |= TPM_TIS_STS_SELFTEST_DONE;
            }
        }

        self.loc[locty].set_sts(TPM_TIS_STS_VALID | TPM_TIS_STS_DATA_AVAILABLE);
        self.loc[locty].set_state(TpmTisState::Completion);
        self.rw_offset = 0;

        if self.next_locty < TPM_TIS_NUM_LOCALITIES as u8 {
            self.abort();
        }

        self.raise_irq(
            locty as u8,
            TPM_TIS_INT_DATA_AVAILABLE | TPM_TIS_INT_STS_VALID,
        );
    }

    fn send_request_async(&mut self, locty: u8) -> Result<()> {
        self.loc[locty as usize].set_state(TpmTisState::Execution);

        let cmd_buf = match self.buffer.take() {
            Some(buf) => buf,
            None => {
                error!("TPM executed but buffer is None!");
                self.write_fatal_error_response();
                self.request_completed(false);
                return Err(anyhow::anyhow!("TPM buffer is None on execution"));
            }
        };
        let cmd_len = cmp::min(self.rw_offset as usize, TPM_TIS_BUFFER_MAX);

        deliver_request(AsyncMsg::Request {
            cmd_buf,
            cmd_len,
            locty,
        });

        Ok(())
    }

    fn check_request_use_except(&self, locty: u8) -> bool {
        self.loc.iter().enumerate().any(|(i, loc)| {
            if i == locty as usize {
                false
            } else {
                (loc.access & TPM_TIS_ACCESS_REQUEST_USE) != 0
            }
        })
    }

    fn prep_abort(&mut self, locty: u8, newlocty: u8) -> Result<(), EmulatorError> {
        if newlocty >= TPM_TIS_NUM_LOCALITIES as u8 {
            warn!("prep_abort called with invalid newlocty: {}", newlocty);
            return Ok(());
        }

        self.aborting_locty = locty;
        self.next_locty = newlocty;

        let is_backend_busy = self
            .loc
            .iter()
            .any(|loc| loc.state == TpmTisState::Execution);

        if is_backend_busy {
            debug!("TPM backend is busy executing. Sending cancel request...");
            if let Err(e) = self.emulator.lock().unwrap().cancel_cmd() {
                warn!("Failed to send cancel command to TPM backend: {:?}", e);
                return Err(e);
            }
        }

        self.abort();
        Ok(())
    }

    fn data_read(&mut self, locty: u8) -> u8 {
        let locty_idx = locty as usize;
        let mut ret = TPM_TIS_NO_DATA_BYTE;

        if (self.loc[locty_idx].sts & TPM_TIS_STS_DATA_AVAILABLE) != 0 {
            if let Some(buffer) = self.buffer.as_ref() {
                let mut expected_len = 0;
                if buffer.len() >= 6 {
                    expected_len =
                        BigEndian::read_u32(&buffer[TPM_RSP_PS_OFFSET..TPM_RSP_RC_OFFSET]) as usize;
                }

                let len = std::cmp::min(expected_len, self.backend_buff_size);

                if (self.rw_offset as usize) < len {
                    ret = buffer[self.rw_offset as usize];
                    self.rw_offset += 1;
                }

                if (self.rw_offset as usize) >= len {
                    debug!("TPM TIS: Last byte read, clearing DATA_AVAIL state.");

                    self.loc[locty_idx].set_sts(TPM_TIS_STS_VALID);
                    self.raise_irq(locty, TPM_TIS_INT_STS_VALID);
                }
            }
        } else {
            debug!(
                "TPM TIS: Attempted to read empty FIFO at locality {}",
                locty
            );
        }

        ret
    }

    fn get_established_flag(&mut self) -> Result<bool, EmulatorError> {
        self.emulator.lock().unwrap().get_established_flag()
    }

    fn reset(&mut self) -> Result<()> {
        let cur_buff_size = self.emulator.lock().unwrap().get_buffer_size();
        self.backend_buff_size = cmp::min(cur_buff_size, TPM_TIS_BUFFER_MAX);

        self.active_locty = TPM_TIS_NO_LOCALITY;
        self.next_locty = TPM_TIS_NO_LOCALITY;
        self.aborting_locty = TPM_TIS_NO_LOCALITY;
        self.rw_offset = 0;

        for loc in self.loc.iter_mut() {
            loc.access = TPM_TIS_ACCESS_TPM_REG_VALID_STS;
            loc.sts = TPM_TIS_STS_TPM_FAMILY2_0;
            loc.iface_id = TPM_TIS_IFACE_ID_SUPPORTED_FLAGS2_0;
            loc.inte = TPM_TIS_INT_POLARITY_LOW_LEVEL;
            loc.ints = 0;
            loc.set_state(TpmTisState::Idle);
        }

        if let Some(buffer) = self.buffer.as_mut() {
            buffer.fill(0);
        }

        if let Err(e) = self
            .emulator
            .lock()
            .unwrap()
            .startup_tpm(self.backend_buff_size, false)
        {
            if matches!(
                e,
                EmulatorError::Disconnected
                    | EmulatorError::ControlSocket(tpm::socket::Error::NotConnected)
            ) {
                warn!("TpmTis device reset while in disconnected state");
                return Ok(());
            }
            return Err(anyhow!("Failed while running Startup TPM. Error: {e:?}"));
        }
        Ok(())
    }
}

impl OnComplete for TpmTis {
    type T = Emulator;

    fn on_complete(&mut self, res: aio::Result<()>, buffer: Vec<u8>) {
        self.buffer = Some(buffer);

        match res {
            Ok(_) => {
                self.request_completed(true);
            }
            Err(e) => {
                if matches!(e, AioError::Disconnected) {
                    if self.backend_disconnected {
                        return;
                    }
                    self.backend_disconnected = true;

                    let disconnected_msg = VmNotifyEvent {
                        klass: DEVICE_CLASS_ID,
                        type_t: DeviceClassSubType::TPM.into(),
                        code: TPM_DISCONNECTED_NOTIFY_CODE,
                        message: None,
                    };
                    event!(VmNotifyEvent; disconnected_msg);
                }

                error!("TPM async request failed: {:?}", e);
                self.write_fatal_error_response();
                self.request_completed(false);
            }
        }
    }

    fn get_async_handler(&self) -> Arc<Mutex<Self::T>> {
        self.emulator.clone()
    }
}

impl Device for TpmTis {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn realize(self) -> Result<Arc<Mutex<Self>>> {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        let dev = Arc::new(Mutex::new(self));
        MUT_SYS_BUS!(parent_bus, locked_bus, sysbus);
        sysbus.attach_device(&dev)?;

        Self::register_update_event(dev.clone())?;
        dev.lock()
            .unwrap()
            .async_ctrl_evt
            .as_ref()
            .unwrap()
            .write(1)?;

        MigrationManager::register_device_instance(
            TpmTisSnapshot::descriptor(),
            TpmTisMigration::new(dev.clone()),
            TPMTIS_SNAPSHOT_ID,
        );

        Ok(dev)
    }

    fn unrealize(&mut self) -> Result<()> {
        if let Err(e) = self.emulator.lock().unwrap().shutdown_tpm() {
            return Err(anyhow!("Failed while running Shutdown TPM. Error: {e:?}"));
        }

        if let Some(evt) = self.async_ctrl_evt.take() {
            unregister_async_ctrl_notifier(evt.as_raw_fd(), self.iothread.as_ref());
        }

        MigrationManager::unregister_device_instance(
            TpmTisSnapshot::descriptor(),
            TPMTIS_SNAPSHOT_ID,
        );

        Ok(())
    }

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        self.reset()
    }
}

impl SysBusDevOps for TpmTis {
    gen_base_func!(sysbusdev_base, sysbusdev_base_mut, SysBusDevBase, base);

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let locty_u8 = locality_from_addr(offset);
        let locty_usize = locty_u8 as usize;

        let reg_offset = (offset & 0xFFC) as u16;
        let shift = (offset & 0x3) as usize;
        let copy_len = std::cmp::min(data.len(), 4 - shift);
        let mut val: u32 = 0xFFFFFFFF;

        match reg_offset {
            TPM_TIS_REG_ACCESS => {
                let mut access = self.loc[locty_usize].access & !TPM_TIS_ACCESS_SEIZE;
                if self.check_request_use_except(locty_u8) {
                    access |= TPM_TIS_ACCESS_PENDING_REQUEST;
                }

                if !self.backend_disconnected {
                    match self.get_established_flag() {
                        Ok(is_established) => {
                            if !is_established {
                                access |= TPM_TIS_ACCESS_TPM_ESTABLISHMENT;
                            }
                            val = access as u32;
                        }
                        Err(e) => {
                            error!("FATAL: Failed to read TPM established flag: {:?}", e);
                            if matches!(e, EmulatorError::Disconnected)
                                && !self.backend_disconnected
                            {
                                self.backend_disconnected = true;

                                let disconnected_msg = VmNotifyEvent {
                                    klass: DEVICE_CLASS_ID,
                                    type_t: DeviceClassSubType::TPM.into(),
                                    code: TPM_DISCONNECTED_NOTIFY_CODE,
                                    message: None,
                                };
                                event!(VmNotifyEvent; disconnected_msg);
                            }
                        }
                    }
                }
            }
            TPM_TIS_REG_INT_ENABLE => {
                val = self.loc[locty_usize].inte;
            }
            TPM_TIS_REG_INT_VECTOR => {
                val = self.sysbusdev_base().irq_state.irq;
            }
            TPM_TIS_REG_INT_STATUS => {
                val = self.loc[locty_usize].ints;
            }
            TPM_TIS_REG_INTF_CAPABILITY => {
                val = TPM_TIS_CAPABILITIES_SUPPORTED2_0;
            }
            TPM_TIS_REG_STS => {
                if self.active_locty == locty_u8 {
                    let mut burst_count: u32 = 0;
                    if (self.loc[locty_usize].sts & TPM_TIS_STS_DATA_AVAILABLE) != 0 {
                        if let Some(buffer) = self.buffer.as_ref() {
                            let mut expected_len = 0;
                            if buffer.len() >= 6 {
                                expected_len = BigEndian::read_u32(
                                    &buffer[TPM_RSP_PS_OFFSET..TPM_RSP_RC_OFFSET],
                                ) as usize;
                            }
                            let len = std::cmp::min(expected_len, self.backend_buff_size);
                            burst_count = len.saturating_sub(self.rw_offset as usize) as u32;
                        }
                    } else {
                        let mut avail = self
                            .backend_buff_size
                            .saturating_sub(self.rw_offset as usize)
                            as u32;
                        if data.len() == 1 && avail > 0xFF {
                            avail = 0xFF;
                        }
                        burst_count = avail;
                    }
                    val = (burst_count << TPM_TIS_BURST_COUNT_SHIFT) | self.loc[locty_usize].sts;
                }
            }
            TPM_TIS_REG_DATA_FIFO | TPM_TIS_REG_DATA_XFIFO..=TPM_TIS_REG_DATA_XFIFO_END => {
                if self.active_locty == locty_u8 {
                    for byte in data.iter_mut().take(copy_len) {
                        if self.loc[locty_usize].state == TpmTisState::Completion {
                            *byte = self.data_read(locty_u8);
                        } else {
                            *byte = TPM_TIS_NO_DATA_BYTE;
                        }
                    }
                }
                return true;
            }
            TPM_TIS_REG_INTERFACE_ID => {
                val = self.loc[locty_usize].iface_id;
            }
            TPM_TIS_REG_DID_VID => {
                val = (TPM_TIS_TPM_DID << 16) | TPM_TIS_TPM_VID;
            }
            TPM_TIS_REG_RID => {
                val = TPM_TIS_TPM_RID;
            }
            _ => {}
        }

        let val_bytes = val.to_le_bytes();
        data[..copy_len].copy_from_slice(&val_bytes[shift..shift + copy_len]);

        if reg_offset != TPM_TIS_REG_STS {
            debug!(
                "Tpm Tis Read: offset {:#X} len {:?} val = {:02X?}",
                offset,
                data.len(),
                data
            );
        }

        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        if (offset & 0xFFC) as u16 != TPM_TIS_REG_DATA_FIFO {
            debug!(
                "Tpm Tis Write: offset {:#X} len {:?} input data {:02X?}",
                offset,
                data.len(),
                data
            );
        }

        let locty_u8 = locality_from_addr(offset);
        let locty_usize = locty_u8 as usize;

        let reg_offset = (offset & 0xFFC) as u16;
        let shift = (offset & 0x3) as usize;
        let copy_len = std::cmp::min(data.len(), 4 - shift);

        if locty_usize == 4 || locty_usize >= TPM_TIS_NUM_LOCALITIES {
            return true;
        }

        let mut write_bytes = [0u8; 4];
        write_bytes[shift..shift + copy_len].copy_from_slice(&data[..copy_len]);
        let write_val = u32::from_le_bytes(write_bytes);
        let mut write_val_u8 = write_val as u8;

        match reg_offset {
            TPM_TIS_REG_ACCESS => {
                if (write_val_u8 & TPM_TIS_ACCESS_SEIZE) != 0 {
                    write_val_u8 &= !(TPM_TIS_ACCESS_REQUEST_USE | TPM_TIS_ACCESS_ACTIVE_LOCALITY);
                }
                let mut active_locty = self.active_locty;
                let mut set_new_locty = true;

                if (write_val_u8 & TPM_TIS_ACCESS_ACTIVE_LOCALITY) != 0 {
                    if self.active_locty == locty_u8 {
                        let mut newlocty = TPM_TIS_NO_LOCALITY;
                        if let Some(idx) = self
                            .loc
                            .iter()
                            .rposition(|loc| (loc.access & TPM_TIS_ACCESS_REQUEST_USE) != 0)
                        {
                            newlocty = idx as u8;
                        }
                        if newlocty < TPM_TIS_NUM_LOCALITIES as u8 {
                            set_new_locty = false;
                            if let Err(EmulatorError::Disconnected) =
                                self.prep_abort(locty_u8, newlocty)
                            {
                                if !self.backend_disconnected {
                                    self.backend_disconnected = true;

                                    let disconnected_msg = VmNotifyEvent {
                                        klass: DEVICE_CLASS_ID,
                                        type_t: DeviceClassSubType::TPM.into(),
                                        code: TPM_DISCONNECTED_NOTIFY_CODE,
                                        message: None,
                                    };
                                    event!(VmNotifyEvent; disconnected_msg);
                                }
                            };
                        } else {
                            active_locty = TPM_TIS_NO_LOCALITY;
                        }
                    } else {
                        self.loc[locty_usize].access &= !TPM_TIS_ACCESS_REQUEST_USE;
                    }
                }

                if (write_val_u8 & TPM_TIS_ACCESS_BEEN_SEIZED) != 0 {
                    self.loc[locty_usize].access &= !TPM_TIS_ACCESS_BEEN_SEIZED;
                }

                if (write_val_u8 & TPM_TIS_ACCESS_SEIZE) != 0 {
                    let is_active_valid = self.active_locty < TPM_TIS_NUM_LOCALITIES as u8;

                    if !is_active_valid || (locty_u8 > self.active_locty) {
                        let already_seizing =
                            (self.loc[locty_usize].access & TPM_TIS_ACCESS_SEIZE) != 0;

                        let higher_seize = (locty_usize + 1..TPM_TIS_NUM_LOCALITIES)
                            .any(|l| (self.loc[l].access & TPM_TIS_ACCESS_SEIZE) != 0);

                        if !already_seizing && !higher_seize {
                            for l in 0..locty_usize {
                                self.loc[l].access &= !TPM_TIS_ACCESS_SEIZE;
                            }

                            self.loc[locty_usize].access |= TPM_TIS_ACCESS_SEIZE;
                            set_new_locty = false;

                            if let Err(EmulatorError::Disconnected) =
                                self.prep_abort(self.active_locty, locty_u8)
                            {
                                if !self.backend_disconnected {
                                    self.backend_disconnected = true;

                                    let disconnected_msg = VmNotifyEvent {
                                        klass: DEVICE_CLASS_ID,
                                        type_t: DeviceClassSubType::TPM.into(),
                                        code: TPM_DISCONNECTED_NOTIFY_CODE,
                                        message: None,
                                    };
                                    event!(VmNotifyEvent; disconnected_msg);
                                }
                            };
                        }
                    }
                }

                if (write_val_u8 & TPM_TIS_ACCESS_REQUEST_USE) != 0 && self.active_locty != locty_u8
                {
                    if self.active_locty < TPM_TIS_NUM_LOCALITIES as u8 {
                        self.loc[locty_usize].access |= TPM_TIS_ACCESS_REQUEST_USE;
                    } else {
                        active_locty = locty_u8;
                    }
                }

                if set_new_locty {
                    self.new_active_locality(active_locty);
                }
            }
            TPM_TIS_REG_INT_ENABLE => {
                let mut current_bytes = self.loc[locty_usize].inte.to_le_bytes();
                current_bytes[shift..shift + copy_len].copy_from_slice(&data[..copy_len]);
                let new_inte = u32::from_le_bytes(current_bytes);

                let allowed_mask = TPM_TIS_INT_GLOBAL_INT_ENABLE
                    | TPM_TIS_INT_POLARITY_MASK
                    | TPM_TIS_INTERRUPTS_SUPPORTED;

                self.loc[locty_usize].inte = new_inte & allowed_mask;
            }
            TPM_TIS_REG_INT_VECTOR => {}
            TPM_TIS_REG_INT_STATUS => {
                let clear_mask = write_val & TPM_TIS_INTERRUPTS_SUPPORTED;
                if clear_mask != 0
                    && (self.loc[locty_usize].ints & TPM_TIS_INTERRUPTS_SUPPORTED) != 0
                {
                    self.loc[locty_usize].ints &= !clear_mask;
                    if self.loc[locty_usize].ints == 0 {
                        let _ = self.sysbusdev_base().irq_state.lower_irq();
                        debug!("All TPM interrupts cleared, lowering IRQ.");
                    }
                }
            }
            TPM_TIS_REG_STS => {
                if self.active_locty != locty_u8 {
                    return true;
                }

                if (write_val & TPM_TIS_STS_COMMAND_CANCEL) != 0
                    && self.loc[locty_usize].state == TpmTisState::Execution
                {
                    if let Err(e) = self.emulator.lock().unwrap().cancel_cmd() {
                        if matches!(e, EmulatorError::Disconnected) && !self.backend_disconnected {
                            self.backend_disconnected = true;

                            let disconnected_msg = VmNotifyEvent {
                                klass: DEVICE_CLASS_ID,
                                type_t: DeviceClassSubType::TPM.into(),
                                code: TPM_DISCONNECTED_NOTIFY_CODE,
                                message: None,
                            };
                            event!(VmNotifyEvent; disconnected_msg);
                        }
                        warn!("Tpm backend cancel command failed: {:?}", e);
                    }
                }
                if (write_val & TPM_TIS_STS_RESET_ESTABLISHMENT) != 0
                    && (3..=4_u8).contains(&locty_u8)
                {
                    if let Err(e) = self
                        .emulator
                        .lock()
                        .unwrap()
                        .reset_established_flag(locty_u8)
                    {
                        if matches!(e, EmulatorError::Disconnected) && !self.backend_disconnected {
                            self.backend_disconnected = true;

                            let disconnected_msg = VmNotifyEvent {
                                klass: DEVICE_CLASS_ID,
                                type_t: DeviceClassSubType::TPM.into(),
                                code: TPM_DISCONNECTED_NOTIFY_CODE,
                                message: None,
                            };
                            event!(VmNotifyEvent; disconnected_msg);
                        }
                        warn!("Tpm backend cancel command failed: {:?}", e);
                    }
                }

                let core_cmd = write_val
                    & (TPM_TIS_STS_COMMAND_READY | TPM_TIS_STS_TPM_GO | TPM_TIS_STS_RESPONSE_RETRY);

                if core_cmd == TPM_TIS_STS_COMMAND_READY {
                    match self.loc[locty_usize].state {
                        TpmTisState::Ready => {
                            self.rw_offset = 0;
                        }
                        TpmTisState::Idle => {
                            self.loc[locty_usize].set_sts(TPM_TIS_STS_COMMAND_READY);
                            self.loc[locty_usize].state = TpmTisState::Ready;
                            self.raise_irq(locty_u8, TPM_TIS_INT_COMMAND_READY);
                        }
                        TpmTisState::Execution | TpmTisState::Reception => {
                            if let Err(EmulatorError::Disconnected) =
                                self.prep_abort(locty_u8, locty_u8)
                            {
                                if !self.backend_disconnected {
                                    self.backend_disconnected = true;

                                    let disconnected_msg = VmNotifyEvent {
                                        klass: DEVICE_CLASS_ID,
                                        type_t: DeviceClassSubType::TPM.into(),
                                        code: TPM_DISCONNECTED_NOTIFY_CODE,
                                        message: None,
                                    };
                                    event!(VmNotifyEvent; disconnected_msg);
                                }
                            };
                        }
                        TpmTisState::Completion => {
                            self.rw_offset = 0;
                            self.loc[locty_usize].state = TpmTisState::Ready;
                            if (self.loc[locty_usize].sts & TPM_TIS_STS_COMMAND_READY) == 0 {
                                self.loc[locty_usize].set_sts(TPM_TIS_STS_COMMAND_READY);
                                self.raise_irq(locty_u8, TPM_TIS_INT_COMMAND_READY);
                            }
                            self.loc[locty_usize].sts &= !TPM_TIS_STS_DATA_AVAILABLE;
                        }
                    }
                } else if core_cmd == TPM_TIS_STS_TPM_GO {
                    let is_reception = self.loc[locty_usize].state == TpmTisState::Reception;
                    let is_expected = (self.loc[locty_usize].sts & TPM_TIS_STS_EXPECT) == 0;
                    if is_reception && is_expected && !self.backend_disconnected {
                        if let Err(e) = self.send_request_async(locty_u8) {
                            error!("Tpm send request failed: {:?}", e);
                        }
                    }
                } else if core_cmd == TPM_TIS_STS_RESPONSE_RETRY
                    && self.loc[locty_usize].state == TpmTisState::Completion
                {
                    self.rw_offset = 0;
                    self.loc[locty_usize].set_sts(TPM_TIS_STS_VALID | TPM_TIS_STS_DATA_AVAILABLE);
                }
            }
            TPM_TIS_REG_DATA_FIFO | TPM_TIS_REG_DATA_XFIFO..=TPM_TIS_REG_DATA_XFIFO_END => {
                if self.active_locty != locty_u8 {
                    return true;
                }

                match self.loc[locty_usize].state {
                    TpmTisState::Idle | TpmTisState::Execution | TpmTisState::Completion => {
                        return true;
                    }
                    TpmTisState::Ready => {
                        self.loc[locty_usize].state = TpmTisState::Reception;
                        self.loc[locty_usize].set_sts(TPM_TIS_STS_EXPECT | TPM_TIS_STS_VALID);
                    }
                    _ => {}
                }

                for &byte in data[..copy_len].iter() {
                    if (self.loc[locty_usize].sts & TPM_TIS_STS_EXPECT) != 0 {
                        if (self.rw_offset as usize) < self.backend_buff_size {
                            if let Some(buffer) = self.buffer.as_mut() {
                                buffer[self.rw_offset as usize] = byte;
                                self.rw_offset += 1;
                            }
                        } else {
                            self.loc[locty_usize].set_sts(TPM_TIS_STS_VALID);
                        }
                    }
                }

                if self.rw_offset > 5 && (self.loc[locty_usize].sts & TPM_TIS_STS_EXPECT) != 0 {
                    let need_irq = (self.loc[locty_usize].sts & TPM_TIS_STS_VALID) == 0;
                    let expected_len = self
                        .buffer
                        .as_ref()
                        .map(|buffer| {
                            BigEndian::read_u32(&buffer[TPM_RSP_PS_OFFSET..TPM_RSP_RC_OFFSET])
                        })
                        .unwrap_or(0);

                    if expected_len > self.rw_offset as u32 {
                        self.loc[locty_usize].set_sts(TPM_TIS_STS_EXPECT | TPM_TIS_STS_VALID);
                    } else {
                        self.loc[locty_usize].set_sts(TPM_TIS_STS_VALID);
                    }

                    if need_irq {
                        self.raise_irq(locty_u8, TPM_TIS_INT_STS_VALID);
                    }
                }
                return true;
            }
            TPM_TIS_REG_INTERFACE_ID => {
                if (write_val & TPM_TIS_IFACE_ID_INT_SEL_LOCK) != 0 {
                    for loc in self.loc.iter_mut() {
                        loc.iface_id |= TPM_TIS_IFACE_ID_INT_SEL_LOCK;
                    }
                }
            }
            _ => {}
        }

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

struct TpmTisMigration {
    tpm: Arc<Mutex<TpmTis>>,
}

impl TpmTisMigration {
    fn new(tpm: Arc<Mutex<TpmTis>>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self { tpm }))
    }

    fn wait_for_async_cmd(&self) -> Result<()> {
        let mut tried = 0;

        loop {
            if self.tpm.lock().unwrap().buffer.is_some() {
                return Ok(());
            }

            thread::sleep(Duration::from_micros(200));
            tried += 1;

            if tried >= 1000 {
                return Err(anyhow::anyhow!(
                    "vTPM is busy for too long time. Failed to migrate."
                ));
            }
        }
    }
}

impl StateTransfer for TpmTisMigration {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        self.wait_for_async_cmd()?;

        let tpm = self.tpm.lock().unwrap();

        let state_blob = tpm
            .emulator
            .lock()
            .unwrap()
            .get_state()
            .map_err(|e| anyhow::anyhow!("Failed to fetch swtpm state blobs: {:?}", e))?;

        let snapshot = TpmTisSnapshot {
            valid_buffer_data: tpm.buffer.clone().unwrap(),
            rw_offset: tpm.rw_offset,
            active_locty: tpm.active_locty,
            aborting_locty: tpm.aborting_locty,
            next_locty: tpm.next_locty,
            loc_states: tpm.loc,
            backend_buff_size: tpm.backend_buff_size,
            swtpm_blob: state_blob,
        };

        Ok(serde_json::to_vec(&snapshot)?)
    }

    fn set_state_mut(&mut self, state: &[u8], _version: u32) -> Result<()> {
        let snapshot: TpmTisSnapshot = serde_json::from_slice(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("TpmTis"))?;

        let mut tpm = self.tpm.lock().unwrap();

        tpm.buffer = Some(snapshot.valid_buffer_data);
        tpm.rw_offset = snapshot.rw_offset;
        tpm.active_locty = snapshot.active_locty;
        tpm.aborting_locty = snapshot.aborting_locty;
        tpm.next_locty = snapshot.next_locty;
        tpm.backend_buff_size = snapshot.backend_buff_size;
        tpm.loc = snapshot.loc_states;
        tpm.backend_disconnected = false;

        // set state blob to swtpm
        tpm.emulator
            .lock()
            .unwrap()
            .set_state(snapshot.swtpm_blob)
            .map_err(|e| anyhow::anyhow!("Failed to restore swtpm state blobs: {:?}", e))?;

        tpm.emulator
            .lock()
            .unwrap()
            .startup_tpm(0, true)
            .map_err(|e| anyhow::anyhow!("Failed to startup swtpm in resume mode: {:?}", e))?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&TpmTisSnapshot::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for TpmTisMigration {}
