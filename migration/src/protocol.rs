// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::cmp::Ordering;
use std::io::{Read, Write};
use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use anyhow::{anyhow, bail, Context, Result};
use kvm_ioctls::Kvm;
use serde::{Deserialize, Serialize};

use crate::MigrationError;
use util::byte_code::ByteCode;

/// This status for migration in migration process.
///
/// # Notes
///
/// State transfer:
/// None -----------> Setup: set up migration resource.
/// Setup ----------> Active: migration is ready.
/// Active ---------> Completed: migration is successful.
/// Completed ------> Active: make migration become ready again.
/// Failed ---------> Setup: reset migration resource.
/// Any ------------> Failed: something wrong in migration.
/// Any ------------> Canceled: cancel migration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Migration resource is not prepared all
    None,
    /// Migration resource(desc_db, device instance, ...) is setup.
    Setup,
    /// Migration is active.
    Active,
    /// Migration completed.
    Completed,
    /// Migration failed.
    Failed,
    /// Migration canceled.
    Canceled,
}

impl std::fmt::Display for MigrationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MigrationStatus::None => "none",
                MigrationStatus::Setup => "setup",
                MigrationStatus::Active => "active",
                MigrationStatus::Completed => "completed",
                MigrationStatus::Failed => "failed",
                MigrationStatus::Canceled => "canceled",
            }
        )
    }
}

impl MigrationStatus {
    // Check and transfer migration status after convert migration operations.
    pub fn transfer(self, new_status: MigrationStatus) -> Result<MigrationStatus> {
        match self {
            MigrationStatus::None => match new_status {
                MigrationStatus::Setup => Ok(new_status),
                _ => Err(anyhow!(MigrationError::InvalidStatusTransfer(
                    self, new_status
                ))),
            },
            MigrationStatus::Setup => match new_status {
                MigrationStatus::Active | MigrationStatus::Failed | MigrationStatus::Canceled => {
                    Ok(new_status)
                }
                _ => Err(anyhow!(MigrationError::InvalidStatusTransfer(
                    self, new_status
                ))),
            },
            MigrationStatus::Active => match new_status {
                MigrationStatus::Completed
                | MigrationStatus::Failed
                | MigrationStatus::Canceled => Ok(new_status),
                _ => Err(anyhow!(MigrationError::InvalidStatusTransfer(
                    self, new_status
                ))),
            },
            MigrationStatus::Completed => match new_status {
                MigrationStatus::Active => Ok(new_status),
                _ => Err(anyhow!(MigrationError::InvalidStatusTransfer(
                    self, new_status
                ))),
            },
            MigrationStatus::Failed => match new_status {
                MigrationStatus::Setup | MigrationStatus::Active => Ok(new_status),
                _ => Err(anyhow!(MigrationError::InvalidStatusTransfer(
                    self, new_status
                ))),
            },
            MigrationStatus::Canceled => Ok(new_status),
        }
    }
}

/// Structure defines the transmission protocol between the source with destination VM.
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum TransStatus {
    /// Active migration.
    Active,
    /// Vm configuration.
    VmConfig,
    /// Processing memory data stage in migration.
    Memory,
    /// Processing device state stage in migration.
    State,
    /// Complete migration.
    Complete,
    /// Cancel migration.
    Cancel,
    /// Everything is ok in migration .
    Ok,
    /// Something error in migration .
    Error,
    /// Unknown status in migration .
    Unknown,
}

impl Default for TransStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for TransStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TransStatus::Active => "Active",
                TransStatus::VmConfig => "VmConfig",
                TransStatus::Memory => "Memory",
                TransStatus::State => "State",
                TransStatus::Complete => "Complete",
                TransStatus::Cancel => "Cancel",
                TransStatus::Ok => "Ok",
                TransStatus::Error => "Error",
                TransStatus::Unknown => "Unknown",
            }
        )
    }
}

/// Structure is used to save request protocol from source VM.
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Request {
    /// Length of data to be sent.
    pub length: u64,
    /// The status need to sync to destination.
    pub status: TransStatus,
}

impl ByteCode for Request {}

impl Request {
    /// Send request message to socket file descriptor.
    ///
    /// # Arguments
    ///
    /// * `fd` - Socket file descriptor between source with destination.
    /// * `status` - The transmission status of request.
    /// * `length` - The length that data need to send.
    ///
    /// # Errors
    ///
    /// The socket file descriptor is broken.
    pub fn send_msg(fd: &mut dyn Write, status: TransStatus, length: u64) -> Result<()> {
        let request = Request { length, status };
        let data =
            // SAFETY: The pointer of request can be guaranteed not null.
            unsafe { from_raw_parts(&request as *const Self as *const u8, size_of::<Self>()) };
        fd.write_all(data)
            .with_context(|| format!("Failed to write request data {:?}", data))?;

        Ok(())
    }

    /// Receive request message from socket file descriptor.
    ///
    /// # Arguments
    ///
    /// * `fd` - Socket file descriptor between source with destination.
    ///
    /// # Errors
    ///
    /// The socket file descriptor is broken.
    pub fn recv_msg(fd: &mut dyn Read) -> Result<Request> {
        let mut request = Request::default();
        let data =
        // SAFETY: The pointer of request can be guaranteed not null.
        unsafe {
            from_raw_parts_mut(&mut request as *mut Request as *mut u8, size_of::<Self>())
        };
        fd.read_exact(data)
            .with_context(|| format!("Failed to read request data {:?}", data))?;

        Ok(request)
    }
}

/// Structure is used to save response protocol from destination VM.
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Response {
    /// The status need to response to source.
    pub status: TransStatus,
}

impl ByteCode for Response {}

impl Response {
    /// Send response message to socket file descriptor.
    ///
    /// # Arguments
    ///
    /// * `fd` - Socket file descriptor between source and destination.
    /// * `status` - The transmission status of response.
    ///
    /// # Errors
    ///
    /// The socket file descriptor is broken.
    pub fn send_msg(fd: &mut dyn Write, status: TransStatus) -> Result<()> {
        let response = Response { status };
        let data =
            // SAFETY: The pointer of response can be guaranteed not null.
            unsafe { from_raw_parts(&response as *const Self as *const u8, size_of::<Self>()) };
        fd.write_all(data)
            .with_context(|| format!("Failed to write response data {:?}", data))?;

        Ok(())
    }

    /// Receive response message from socket file descriptor.
    ///
    /// # Arguments
    ///
    /// * `fd` - Socket file descriptor between source and destination.
    ///
    /// # Errors
    ///
    /// The socket file descriptor is broken.
    pub fn recv_msg(fd: &mut dyn Read) -> Result<Response> {
        let mut response = Response::default();
        let data =
        // SAFETY: The pointer of response can be guaranteed not null.
        unsafe {
            from_raw_parts_mut(&mut response as *mut Response as *mut u8, size_of::<Self>())
        };
        fd.read_exact(data)
            .with_context(|| format!("Failed to read response data {:?}", data))?;

        Ok(response)
    }

    /// Check the status from response is not OK.
    pub fn is_err(&self) -> bool {
        self.status != TransStatus::Ok
    }
}

/// Structure is used to save guest physical address and length of
/// memory block that needs to send.
#[repr(C)]
#[derive(Clone, Default)]
pub struct MemBlock {
    /// Guest address.
    pub gpa: u64,
    /// Size of memory.
    pub len: u64,
}

/// Magic number for migration header. Those bytes represent "STRATOVIRT".
const MAGIC_NUMBER: [u8; 16] = [
    0x53, 0x54, 0x52, 0x41, 0x54, 0x4f, 0x56, 0x49, 0x52, 0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];
const MAJOR_VERSION: u32 = 2;
const MINOR_VERSION: u32 = 2;
const CURRENT_VERSION: u32 = MAJOR_VERSION << 12 | MINOR_VERSION & 0b1111;
const COMPAT_VERSION: u32 = CURRENT_VERSION;
#[cfg(target_arch = "x86_64")]
const EAX_VENDOR_INFO: u32 = 0x0;
/// The length of `MigrationHeader` part occupies bytes in snapshot file.
pub const HEADER_LENGTH: usize = 4096;

/// Format type for migration.
/// Different file format will have different file layout.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileFormat {
    Device,
    MemoryFull,
}

/// The endianness of byte order.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
enum EndianType {
    Little = 1,
    Big = 2,
}

impl EndianType {
    fn get_endian_type() -> EndianType {
        if cfg!(target_endian = "big") {
            EndianType::Big
        } else {
            EndianType::Little
        }
    }
}

/// Get host cpu model as bytes.
#[cfg(target_arch = "x86_64")]
fn cpu_model() -> [u8; 16] {
    use core::arch::x86_64::__cpuid_count;

    // SAFETY: We only use cpuid for cpu info in x86_64.
    let result = unsafe { __cpuid_count(EAX_VENDOR_INFO, 0) };
    let vendor_slice = [result.ebx, result.edx, result.ecx];

    // SAFETY: We known those brand string length.
    let vendor_array = unsafe {
        let brand_string_start = vendor_slice.as_ptr() as *const u8;
        std::slice::from_raw_parts(brand_string_start, 3 * 4)
    };

    let mut buffer = [0u8; 16];
    if vendor_array.len() > 16 {
        buffer.copy_from_slice(&vendor_array[0..15]);
    } else {
        buffer[0..vendor_array.len()].copy_from_slice(vendor_array);
    }
    buffer
}

/// Structure used to mark some message in migration.
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct MigrationHeader {
    /// Magic number for migration file/stream.
    magic_num: [u8; 16],
    /// Compatible version of migration.
    compat_version: u32,
    /// Arch identifier.
    arch: [u8; 8],
    /// Endianness of byte order.
    byte_order: EndianType,
    /// The version of hypervisor.
    hypervisor_version: u32,
    /// The type of CPU model.
    #[cfg(target_arch = "x86_64")]
    cpu_model: [u8; 16],
    /// Operation system type.
    os_type: [u8; 8],
    /// File format of migration file/stream.
    pub format: FileFormat,
    /// The length of `DeviceStateDesc`.
    pub desc_len: usize,
}

impl ByteCode for MigrationHeader {}

impl Default for MigrationHeader {
    fn default() -> Self {
        MigrationHeader {
            magic_num: MAGIC_NUMBER,
            compat_version: COMPAT_VERSION,
            format: FileFormat::Device,
            byte_order: EndianType::Little,
            hypervisor_version: Kvm::new().unwrap().get_api_version() as u32,
            #[cfg(target_arch = "x86_64")]
            cpu_model: cpu_model(),
            #[cfg(target_os = "linux")]
            os_type: [b'l', b'i', b'n', b'u', b'x', b'0', b'0', b'0'],
            #[cfg(target_arch = "x86_64")]
            arch: [b'x', b'8', b'6', b'_', b'6', b'4', b'0', b'0'],
            #[cfg(target_arch = "aarch64")]
            arch: [b'a', b'a', b'r', b'c', b'h', b'6', b'4', b'0'],
            desc_len: 0,
        }
    }
}

impl MigrationHeader {
    /// Check parsed `MigrationHeader` is illegal or not.
    pub fn check_header(&self) -> Result<()> {
        if self.magic_num != MAGIC_NUMBER {
            return Err(anyhow!(MigrationError::HeaderItemNotFit(
                "Magic_number".to_string()
            )));
        }

        if self.compat_version > CURRENT_VERSION {
            return Err(anyhow!(MigrationError::VersionNotFit(
                self.compat_version,
                CURRENT_VERSION
            )));
        }

        #[cfg(target_arch = "x86_64")]
        let current_arch = [b'x', b'8', b'6', b'_', b'6', b'4', b'0', b'0'];
        #[cfg(target_arch = "aarch64")]
        let current_arch = [b'a', b'a', b'r', b'c', b'h', b'6', b'4', b'0'];
        if self.arch != current_arch {
            return Err(anyhow!(MigrationError::HeaderItemNotFit(
                "Arch".to_string()
            )));
        }

        if self.byte_order != EndianType::get_endian_type() {
            return Err(anyhow!(MigrationError::HeaderItemNotFit(
                "Byte order".to_string()
            )));
        }

        #[cfg(target_arch = "x86_64")]
        if self.cpu_model != cpu_model() {
            return Err(anyhow!(MigrationError::HeaderItemNotFit(
                "Cpu model".to_string()
            )));
        }

        #[cfg(target_os = "linux")]
        let current_os_type = [b'l', b'i', b'n', b'u', b'x', b'0', b'0', b'0'];
        if self.os_type != current_os_type {
            return Err(anyhow!(MigrationError::HeaderItemNotFit(
                "Os type".to_string()
            )));
        }

        let current_kvm_version = Kvm::new().unwrap().get_api_version() as u32;
        if current_kvm_version < self.hypervisor_version {
            return Err(anyhow!(MigrationError::HeaderItemNotFit(
                "Hypervisor version".to_string()
            )));
        }

        if self.desc_len > (1 << 20) {
            return Err(anyhow!(MigrationError::HeaderItemNotFit(
                "Desc length".to_string()
            )));
        }

        Ok(())
    }
}

/// Version check result enum.
#[derive(PartialEq, Eq, Debug)]
pub enum VersionCheck {
    /// Version is completely same.
    Same,
    /// Version is not same but compat.
    Compat,
    /// Version is not compatible.
    Mismatch,
}

/// Trait to acquire `DeviceState` bytes slice from `Device` and recover
/// `Device`'s state from `DeviceState` bytes slice.
///
/// # Notes
/// `DeviceState` structure is to save some device state such as register data
/// and switch flag value. `DeviceState` must implement the `ByteCode` trait.
/// So it can be transferred to bytes slice directly.
pub trait StateTransfer {
    /// Get `Device`'s state to `DeviceState` structure as bytes vector.
    fn get_state_vec(&self) -> Result<Vec<u8>>;

    /// Set a `Device`'s state from bytes slice as `DeviceState` structure.
    fn set_state(&self, _state: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Set a `Device`'s state in mutable `Device` structure from bytes slice
    /// as `DeviceState` structure.
    fn set_state_mut(&mut self, _state: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Upgrade some high-version information.
    fn upgrade_version(&mut self) {}

    /// Downcast some high-version information.
    fn downcast_version(&mut self) {}

    /// Get `DeviceState` alias used for `InstanceId`.
    fn get_device_alias(&self) -> u64;
}

/// The structure to describe `DeviceState` structure with version message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStateDesc {
    /// Device type identify.
    pub name: String,
    /// Alias for device type.
    pub alias: u64,
    /// Size of `DeviceState` structure.
    pub size: u32,
    /// Device current migration version.
    pub current_version: u32,
    /// The minimum required device migration version.
    pub compat_version: u32,
    /// Field descriptor of `DeviceState` structure.
    pub fields: Vec<FieldDesc>,
}

/// The structure to describe struct field in `DeviceState` structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDesc {
    /// Field var name.
    pub var_name: String,
    /// Field type name.
    pub type_name: String,
    /// Alias for field.
    pub alias: String,
    /// Offset for this field in bytes slice.
    pub offset: u32,
    /// Size of this field.
    pub size: u32,
}

impl DeviceStateDesc {
    /// Check the field is exist in `DeviceState` with a field alias.
    fn contains(&self, alias_name: &str) -> bool {
        for field in &self.fields {
            if alias_name == field.alias {
                return true;
            }
        }

        false
    }

    /// Get a slice index: (start, end) for given field alias.
    fn get_slice_index(&self, alias_name: &str) -> Result<(usize, usize)> {
        for field in &self.fields {
            if alias_name == field.alias {
                let start = field.offset as usize;
                let end = start + field.size as usize;
                if end > self.size as usize {
                    bail!("Data slice index out of range");
                }
                return Ok((start, end));
            }
        }

        bail!("Don't have this alias name: {}", alias_name)
    }

    /// Check padding from a device state descriptor to another version device state
    /// descriptor. The padding will be added into current_slice for `DeviceState`.
    ///
    /// # Arguments
    ///
    /// * `desc` - device state descriptor for old version `DeviceState`.
    /// * `current_slice` - current slice for `DeviceState`.
    pub fn add_padding(&self, desc: &DeviceStateDesc, current_slice: &mut Vec<u8>) -> Result<()> {
        let tmp_slice = current_slice.clone();
        current_slice.clear();
        // SAFETY: size has been checked in restore_desc_db().
        current_slice.resize(self.size as usize, 0);
        for field in self.clone().fields {
            if desc.contains(&field.alias) {
                let (new_start, new_end) = desc.get_slice_index(&field.alias)?;
                let (start, mut end) = self.get_slice_index(&field.alias)?;

                // Make snap_desc field data length fit with current field data length.
                if new_end - new_start > end - start {
                    end += (new_end - new_start) - (end - start);
                } else {
                    end -= (end - start) - (new_end - new_start);
                }

                current_slice[start..end].clone_from_slice(&tmp_slice[new_start..new_end]);
            }
        }

        Ok(())
    }

    /// Check device state version descriptor version message.
    /// If version is same, return enum `Same`.
    /// If version is not same but fit, return enum `Compat`.
    /// if version is not fit, return enum `Mismatch`.
    ///
    /// # Arguments
    ///
    /// * `desc`: device state descriptor for old version `DeviceState`.
    pub fn check_version(&self, desc: &DeviceStateDesc) -> VersionCheck {
        match self.current_version.cmp(&desc.current_version) {
            Ordering::Equal => VersionCheck::Same,
            Ordering::Greater => VersionCheck::Compat,
            Ordering::Less => VersionCheck::Mismatch,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use migration_derive::{ByteCode, Desc};
    use util::byte_code::ByteCode;

    #[test]
    fn test_normal_transfer() {
        let mut status = MigrationStatus::None;

        // None to Setup.
        assert!(status.transfer(MigrationStatus::Setup).is_ok());
        status = status.transfer(MigrationStatus::Setup).unwrap();

        // Setup to Active.
        assert!(status.transfer(MigrationStatus::Active).is_ok());
        status = status.transfer(MigrationStatus::Active).unwrap();

        // Active to Completed.
        assert!(status.transfer(MigrationStatus::Completed).is_ok());
        status = status.transfer(MigrationStatus::Completed).unwrap();

        // Completed to Active.
        assert!(status.transfer(MigrationStatus::Active).is_ok());
        status = status.transfer(MigrationStatus::Active).unwrap();

        // Any to Failed.
        assert!(status.transfer(MigrationStatus::Failed).is_ok());
        status = status.transfer(MigrationStatus::Failed).unwrap();

        // Failed to Active.
        assert!(status.transfer(MigrationStatus::Active).is_ok());
        status = status.transfer(MigrationStatus::Active).unwrap();

        // Any to Failed.
        assert!(status.transfer(MigrationStatus::Failed).is_ok());
        status = status.transfer(MigrationStatus::Failed).unwrap();

        // Failed to Setup.
        assert!(status.transfer(MigrationStatus::Setup).is_ok());
        status = status.transfer(MigrationStatus::Setup).unwrap();

        assert_eq!(status, MigrationStatus::Setup);
    }

    #[test]
    fn test_abnormal_transfer_with_error() {
        let mut status = MigrationStatus::None;

        // None to Active.
        if let Err(e) = status.transfer(MigrationStatus::Active) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::None,
                    MigrationStatus::Active
                )
            );
        } else {
            assert!(false)
        }
        status = status.transfer(MigrationStatus::Setup).unwrap();

        // Setup to Complete.
        if let Err(e) = status.transfer(MigrationStatus::Completed) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::Setup,
                    MigrationStatus::Completed
                )
            );
        } else {
            assert!(false)
        }
        status = status.transfer(MigrationStatus::Active).unwrap();

        // Active to Setup.
        if let Err(e) = status.transfer(MigrationStatus::Setup) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::Active,
                    MigrationStatus::Setup
                )
            );
        } else {
            assert!(false)
        }
        status = status.transfer(MigrationStatus::Completed).unwrap();

        // Completed to Setup.
        if let Err(e) = status.transfer(MigrationStatus::Setup) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::Completed,
                    MigrationStatus::Setup
                )
            );
        } else {
            assert!(false)
        }

        // Complete to failed.
        if let Err(e) = status.transfer(MigrationStatus::Failed) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::Completed,
                    MigrationStatus::Failed
                )
            );
        } else {
            assert!(false)
        }
    }

    #[derive(Default)]
    // A simple device version 1.
    pub struct DeviceV1 {
        state: DeviceV1State,
    }

    #[derive(Default)]
    // A simple device version 2.
    pub struct DeviceV2 {
        state: DeviceV2State,
    }

    #[derive(Default)]
    // A simple device version 3.
    pub struct DeviceV3 {
        state: DeviceV3State,
    }

    #[derive(Default)]
    // A simple device version 4.
    pub struct DeviceV4 {
        state: DeviceV4State,
    }

    #[derive(Default)]
    // A simple device version 4.
    pub struct DeviceV5 {
        state: DeviceV5State,
    }

    #[derive(Copy, Clone, Desc, ByteCode)]
    #[desc_version(current_version = "1.0.0", compat_version = "1.0.0")]
    // Statement for DeviceV1.
    pub struct DeviceV1State {
        ier: u8,
        iir: u8,
        lcr: u8,
    }

    #[derive(Copy, Clone, Desc, ByteCode)]
    #[desc_version(current_version = "2.0.0", compat_version = "1.0.0")]
    // Statement for DeviceV2.
    pub struct DeviceV2State {
        ier: u8,
        iir: u8,
        lcr: u8,
        mcr: u8,
    }

    impl StateTransfer for DeviceV1 {
        fn get_state_vec(&self) -> Result<Vec<u8>> {
            Ok(self.state.as_bytes().to_vec())
        }

        fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
            self.state = *DeviceV1State::from_bytes(state).unwrap();
            Ok(())
        }

        fn get_device_alias(&self) -> u64 {
            0
        }
    }

    impl StateTransfer for DeviceV2 {
        fn get_state_vec(&self) -> Result<Vec<u8>> {
            Ok(self.state.as_bytes().to_vec())
        }

        fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
            self.state = *DeviceV2State::from_bytes(state).unwrap();
            Ok(())
        }

        fn upgrade_version(&mut self) {
            self.state.mcr = 255_u8;
        }

        fn get_device_alias(&self) -> u64 {
            0
        }
    }

    #[derive(Copy, Clone, Desc, ByteCode)]
    #[desc_version(current_version = "3.0.0", compat_version = "2.0.0")]
    // Statement for DeviceV3
    pub struct DeviceV3State {
        ier: u64,
        iir: u64,
        lcr: u64,
        mcr: u64,
    }

    impl StateTransfer for DeviceV3 {
        fn get_state_vec(&self) -> Result<Vec<u8>> {
            Ok(self.state.as_bytes().to_vec())
        }

        fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
            self.state = *DeviceV3State::from_bytes(state).unwrap();
            Ok(())
        }

        fn get_device_alias(&self) -> u64 {
            0
        }
    }

    #[derive(Copy, Clone, Desc, ByteCode)]
    #[desc_version(current_version = "4.0.0", compat_version = "2.0.0")]
    // Statement for DeviceV4
    pub struct DeviceV4State {
        #[alias(ier)]
        rei: u64,
        #[alias(iir)]
        rii: u64,
        #[alias(lcr)]
        rcl: u64,
        #[alias(mcr)]
        rcm: u64,
    }

    impl StateTransfer for DeviceV4 {
        fn get_state_vec(&self) -> Result<Vec<u8>> {
            Ok(self.state.as_bytes().to_vec())
        }

        fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
            self.state = *DeviceV4State::from_bytes(state).unwrap();
            Ok(())
        }

        fn get_device_alias(&self) -> u64 {
            0
        }
    }

    #[derive(Copy, Clone, Desc, ByteCode)]
    #[desc_version(current_version = "5.0.0", compat_version = "2.0.0")]
    // Statement for DeviceV4
    pub struct DeviceV5State {
        #[alias(iir)]
        rii: u64,
    }

    impl StateTransfer for DeviceV5 {
        fn get_state_vec(&self) -> Result<Vec<u8>> {
            Ok(self.state.as_bytes().to_vec())
        }

        fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
            self.state = *DeviceV5State::from_bytes(state).unwrap();
            Ok(())
        }

        fn get_device_alias(&self) -> u64 {
            0
        }
    }

    #[test]
    fn test_desc_basic_padding() {
        // This test makes two version of a device. Those devices's difference is appending a new
        // field `mcr` in device state.
        // Add_padding can solve this change in descriptor of device state.
        // Test can verify this function works.

        let mut device_v1 = DeviceV1 {
            state: DeviceV1State::default(),
        };

        device_v1.state.ier = 1;
        device_v1.state.iir = 2;
        device_v1.state.lcr = 3;

        let state_1_desc = DeviceV1State::descriptor();
        let state_2_desc = DeviceV2State::descriptor();

        assert_eq!(
            state_2_desc.check_version(&state_1_desc),
            VersionCheck::Compat
        );

        let mut current_slice = device_v1.get_state_vec().unwrap();
        assert_eq!(
            state_2_desc
                .add_padding(&state_1_desc, &mut current_slice)
                .is_ok(),
            true
        );

        let mut device_v2 = DeviceV2 {
            state: DeviceV2State::default(),
        };
        device_v2.set_state_mut(&current_slice).unwrap();
        assert!(state_2_desc.current_version > state_1_desc.current_version);
        device_v2.upgrade_version();

        assert_eq!(device_v2.state.ier, device_v1.state.ier);
        assert_eq!(device_v2.state.iir, device_v1.state.iir);
        assert_eq!(device_v2.state.lcr, device_v1.state.lcr);
        assert_eq!(device_v2.state.mcr, 255_u8);
    }

    #[test]
    fn test_desc_data_type_padding() {
        // This test makes two version of a device. Those devices's difference is appending all
        // fields data value changed from u8 to u64.
        // Add_padding can solve this change in descriptor of device state.
        // Test can verify this function works.
        let mut device_v2 = DeviceV2 {
            state: DeviceV2State::default(),
        };

        device_v2.state.ier = 1;
        device_v2.state.iir = 2;
        device_v2.state.lcr = 3;
        device_v2.state.mcr = 255;

        let state_2_desc = DeviceV2State::descriptor();
        let state_3_desc = DeviceV3State::descriptor();

        assert_eq!(
            state_3_desc.check_version(&state_2_desc),
            VersionCheck::Compat
        );

        let mut current_slice = device_v2.get_state_vec().unwrap();
        assert_eq!(
            state_3_desc
                .add_padding(&state_2_desc, &mut current_slice)
                .is_ok(),
            true
        );

        let mut device_v3 = DeviceV3 {
            state: DeviceV3State::default(),
        };
        device_v3.set_state_mut(&current_slice).unwrap();
        assert!(state_3_desc.current_version > state_2_desc.current_version);

        assert_eq!(device_v3.state.ier, device_v2.state.ier as u64);
        assert_eq!(device_v3.state.iir, device_v2.state.iir as u64);
        assert_eq!(device_v3.state.lcr, device_v2.state.lcr as u64);
        assert_eq!(device_v3.state.mcr, device_v2.state.mcr as u64);
    }

    #[test]
    fn test_desc_field_name_padding() {
        // This test makes two version of a device. Those devices's difference is appending all
        // fields name changed from u8 to u64.
        // Add_padding can solve this change in descriptor of device state.
        // Test can verify this function works.
        let mut device_v3 = DeviceV3 {
            state: DeviceV3State::default(),
        };

        device_v3.state.ier = 1;
        device_v3.state.iir = 2;
        device_v3.state.lcr = 3;
        device_v3.state.mcr = 255;

        let state_3_desc = DeviceV3State::descriptor();
        let state_4_desc = DeviceV4State::descriptor();

        assert_eq!(
            state_4_desc.check_version(&state_3_desc),
            VersionCheck::Compat
        );

        let mut current_slice = device_v3.get_state_vec().unwrap();
        assert_eq!(
            state_4_desc
                .add_padding(&state_3_desc, &mut current_slice)
                .is_ok(),
            true
        );

        let mut device_v4 = DeviceV4 {
            state: DeviceV4State::default(),
        };
        device_v4.set_state_mut(&current_slice).unwrap();
        assert!(state_4_desc.current_version > state_3_desc.current_version);

        assert_eq!(device_v4.state.rei, device_v3.state.ier);
        assert_eq!(device_v4.state.rii, device_v3.state.iir);
        assert_eq!(device_v4.state.rcl, device_v3.state.lcr);
        assert_eq!(device_v4.state.rcm, device_v3.state.mcr);
    }

    #[test]
    fn test_desc_field_delete_padding() {
        // This test makes two version of a device. Those devices's difference is appending all
        // fields name changed from u8 to u64.
        // Add_padding can solve this change in descriptor of device state.
        // Test can verify this function works.
        let mut device_v4 = DeviceV4 {
            state: DeviceV4State::default(),
        };

        device_v4.state.rei = 1;
        device_v4.state.rii = 2;
        device_v4.state.rcl = 3;
        device_v4.state.rcm = 255;

        let state_4_desc = DeviceV4State::descriptor();
        let state_5_desc = DeviceV5State::descriptor();

        assert_eq!(
            state_5_desc.check_version(&state_4_desc),
            VersionCheck::Compat
        );

        let mut current_slice = device_v4.get_state_vec().unwrap();
        assert_eq!(
            state_5_desc
                .add_padding(&state_4_desc, &mut current_slice)
                .is_ok(),
            true
        );

        let mut device_v5 = DeviceV5 {
            state: DeviceV5State::default(),
        };
        device_v5.set_state_mut(&current_slice).unwrap();
        assert!(state_5_desc.current_version > state_4_desc.current_version);

        assert_eq!(device_v5.state.rii, device_v4.state.rii);
    }

    #[test]
    fn test_desc_jump_version_padding() {
        // This test makes two version of a device. Those devices jump from v2 to v5 once.
        // Add_padding can solve this change in descriptor of device state.
        // Test can verify this function works.
        let mut device_v2 = DeviceV2 {
            state: DeviceV2State::default(),
        };

        device_v2.state.ier = 1;
        device_v2.state.iir = 2;
        device_v2.state.lcr = 3;
        device_v2.state.mcr = 255;

        let state_2_desc = DeviceV2State::descriptor();
        let state_5_desc = DeviceV5State::descriptor();

        assert_eq!(
            state_5_desc.check_version(&state_2_desc),
            VersionCheck::Compat
        );

        let mut current_slice = device_v2.get_state_vec().unwrap();
        assert_eq!(
            state_5_desc
                .add_padding(&state_2_desc, &mut current_slice)
                .is_ok(),
            true
        );

        let mut device_v5 = DeviceV5 {
            state: DeviceV5State::default(),
        };
        device_v5.set_state_mut(&current_slice).unwrap();
        assert!(state_5_desc.current_version > state_2_desc.current_version);

        assert_eq!(device_v5.state.rii, device_v2.state.iir as u64);
    }

    #[test]
    fn test_check_header() {
        if !Kvm::new().is_ok() {
            return;
        }

        let header = MigrationHeader::default();
        assert_eq!(header.check_header().is_ok(), true);
    }
}
