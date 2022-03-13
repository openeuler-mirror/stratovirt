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

use kvm_ioctls::Kvm;

use util::byte_code::ByteCode;

use super::errors::{ErrorKind, Result};

/// Magic number for migration header. Those bytes represent "STRATOVIRT".
const MAGIC_NUMBER: [u8; 16] = [
    0x53, 0x54, 0x52, 0x41, 0x54, 0x4f, 0x56, 0x49, 0x52, 0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];
const CURRENT_VERSION: u32 = 1;
const COMPAT_VERSION: u32 = 1;
#[cfg(target_arch = "x86_64")]
const EAX_VENDOR_INFO: u32 = 0x0;

/// Format type for migration.
/// Different file format will have different file layout.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FileFormat {
    Device = 1,
    MemoryFull = 2,
}

/// The endianness of byte order.
#[derive(Debug, Copy, Clone, PartialEq)]
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

    // Safe because we only use cpuid for cpu info in x86_64.
    let result = unsafe { __cpuid_count(EAX_VENDOR_INFO, 0) };
    let vendor_slice = [result.ebx, result.edx, result.ecx];

    // Safe because we known those brand string length.
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
#[derive(Copy, Clone, Debug)]
pub struct MigrationHeader {
    /// Magic number for migration file/stream.
    magic_num: [u8; 16],
    /// Current version of migration.
    #[allow(dead_code)]
    current_version: u32,
    /// Compatible version of migration.
    compat_version: u32,
    /// Arch identifier.
    arch: [u8; 8],
    /// Endianness of byte order.
    byte_order: EndianType,
    /// The type of hypervisor.
    #[allow(dead_code)]
    hypervisor_type: [u8; 8],
    /// The version of hypervisor.
    hypervisor_version: u32,
    /// The type of Cpu model.
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
            current_version: CURRENT_VERSION,
            compat_version: COMPAT_VERSION,
            format: FileFormat::Device,
            byte_order: EndianType::Little,
            hypervisor_type: [b'k', b'v', b'm', b'0', b'0', b'0', b'0', b'0'],
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
            return Err(ErrorKind::HeaderItemNotFit("Magic_number".to_string()).into());
        }

        if self.compat_version > CURRENT_VERSION {
            return Err(ErrorKind::VersionNotFit(self.compat_version, CURRENT_VERSION).into());
        }

        #[cfg(target_arch = "x86_64")]
        let current_arch = [b'x', b'8', b'6', b'_', b'6', b'4', b'0', b'0'];
        #[cfg(target_arch = "aarch64")]
        let current_arch = [b'a', b'a', b'r', b'c', b'h', b'6', b'4', b'0'];
        if self.arch != current_arch {
            return Err(ErrorKind::HeaderItemNotFit("Arch".to_string()).into());
        }

        if self.byte_order != EndianType::get_endian_type() {
            return Err(ErrorKind::HeaderItemNotFit("Byte order".to_string()).into());
        }

        #[cfg(target_arch = "x86_64")]
        if self.cpu_model != cpu_model() {
            return Err(ErrorKind::HeaderItemNotFit("Cpu model".to_string()).into());
        }

        #[cfg(target_os = "linux")]
        let current_os_type = [b'l', b'i', b'n', b'u', b'x', b'0', b'0', b'0'];
        if self.os_type != current_os_type {
            return Err(ErrorKind::HeaderItemNotFit("Os type".to_string()).into());
        }

        let current_kvm_version = Kvm::new().unwrap().get_api_version() as u32;
        if current_kvm_version < self.hypervisor_version {
            return Err(ErrorKind::HeaderItemNotFit("Hypervisor version".to_string()).into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Kvm, MigrationHeader};

    #[test]
    fn test_check_header() {
        if !Kvm::new().is_ok() {
            return;
        }

        let header = MigrationHeader::default();
        assert_eq!(header.check_header().is_ok(), true);
    }
}
