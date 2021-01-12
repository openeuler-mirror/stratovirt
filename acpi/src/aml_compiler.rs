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

use util::byte_code::ByteCode;

const ACPI_NAME_SEG_MAX: u8 = 4;

/// This trait is used for converting AML Data structure to byte stream.
pub trait AmlBuilder {
    /// Transfer this struct to byte stream.
    fn aml_bytes(&self) -> Vec<u8>;
}

/// This trait is used for adding children to AML Data structure that represents
/// a scope, such as `AmlDevice`, `AmlScope`.
pub trait AmlScopeBuilder: AmlBuilder {
    /// Append a child to this AML scope structure.
    ///
    /// # Arguments
    ///
    /// * `child` - Child that will be appended to the end of this scope.
    fn append_child<T: AmlBuilder>(&mut self, child: T);
}

/// Macro that helps to define `AmlZero`, `AmlOne`, `AmlOnes`
///
/// # Arguments
///
/// * `$name` - struct name
/// * `$byte` - corresponding byte of this structure
macro_rules! zero_one_define {
    ($name: ident, $byte: expr) => {
        pub struct $name;

        impl AmlBuilder for $name {
            fn aml_bytes(&self) -> Vec<u8> {
                vec![$byte]
            }
        }
    };
}

zero_one_define!(AmlZero, 0x00);
zero_one_define!(AmlOne, 0x01);
zero_one_define!(AmlOnes, 0xFF);

/// Macro that helps to define `AmlByte`, `AmlWord`, `AmlDWord`, `AmlQWord`.
///
/// # Arguments
///
/// * `$name` - struct name
/// * `$op` - corresponding Opcode of this structure
/// * `$ty` - inner field of this struct.
macro_rules! aml_bytes_type_define {
    ($name:ident, $op:expr, $ty:tt) => {
        pub struct $name(pub $ty);

        impl AmlBuilder for $name {
            fn aml_bytes(&self) -> Vec<u8> {
                let mut bytes = Vec::new();
                bytes.push($op);
                bytes.extend(self.0.as_bytes());
                bytes
            }
        }
    };
}

aml_bytes_type_define!(AmlByte, 0x0A, u8);
aml_bytes_type_define!(AmlWord, 0x0B, u16);
aml_bytes_type_define!(AmlDWord, 0x0C, u32);
aml_bytes_type_define!(AmlQWord, 0x0E, u64);

/// Integer, max value u64::MAX.
pub struct AmlInteger(pub u64);

impl AmlBuilder for AmlInteger {
    fn aml_bytes(&self) -> Vec<u8> {
        match self.0 {
            0x00 => AmlZero.aml_bytes(),
            0x01 => AmlOne.aml_bytes(),
            0x02..=0xFF => AmlByte(self.0 as u8).aml_bytes(),
            0x100..=0xFFFF => AmlWord(self.0 as u16).aml_bytes(),
            0x10000..=0xFFFF_FFFF => AmlDWord(self.0 as u32).aml_bytes(),
            _ => AmlQWord(self.0).aml_bytes(),
        }
    }
}

/// String
pub struct AmlString(pub String);

impl AmlBuilder for AmlString {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x0D);
        bytes.extend(self.0.as_bytes().to_vec());
        bytes.push(0x0);
        bytes
    }
}

/// Parse and check a name-segment, and convert it to byte stream.
fn build_name_seg(name: &str) -> Vec<u8> {
    if name.len() > usize::from(ACPI_NAME_SEG_MAX) {
        panic!("the length of NameSeg is larger than 4.");
    }

    let mut bytes = name.as_bytes().to_vec();
    bytes.extend(vec![b'_'; ACPI_NAME_SEG_MAX as usize - name.len()]);
    bytes
}

/// Parse a name-string and convert it to byte stream
fn build_name_string(name: &str) -> Vec<u8> {
    let strs = name.split('.').collect::<Vec<&str>>();
    if strs.is_empty() || strs.len() > 255 {
        panic!("Invalid ACPI name string, length: {}", strs.len());
    }

    let mut bytes = Vec::new();

    // parse the first segment.
    let mut first_str = strs[0].to_string();
    let mut index = 0;

    for (i, ch) in first_str.chars().enumerate() {
        if ch == '\\' || ch == '^' {
            bytes.push(ch as u8);
        } else {
            index = i;
            break;
        }
    }

    let remain_first = first_str.drain(index..).collect::<String>();

    match strs.len() {
        1 => {
            if remain_first.is_empty() {
                bytes.push(0x00);
            } else {
                bytes.append(&mut build_name_seg(&remain_first));
            }
        }
        2 => {
            bytes.push(0x2E);
            bytes.append(&mut build_name_seg(&remain_first));
            bytes.append(&mut build_name_seg(&strs[1].to_string()));
        }
        _ => {
            bytes.push(0x2F);
            bytes.push(strs.len() as u8);
            bytes.append(&mut build_name_seg(&remain_first));

            strs.iter().skip(1).for_each(|s| {
                bytes.extend(build_name_seg(&s.to_string()));
            })
        }
    }

    bytes
}

/// This struct represents declaration of a named object
pub struct AmlNameDecl {
    /// Name of the object.
    name: String,
    /// The corresponding object that be named.
    obj: Vec<u8>,
}

impl AmlNameDecl {
    pub fn new<T: AmlBuilder>(name: &str, obj: T) -> AmlNameDecl {
        AmlNameDecl {
            name: name.to_string(),
            obj: obj.aml_bytes(),
        }
    }
}

impl AmlBuilder for AmlNameDecl {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x08);
        bytes.extend(build_name_string(self.name.as_ref()));
        bytes.extend(self.obj.clone());
        bytes
    }
}

/// AmlName represents a Named object that has been declared before.
#[derive(Clone)]
pub struct AmlName(pub String);

impl AmlBuilder for AmlName {
    fn aml_bytes(&self) -> Vec<u8> {
        build_name_string(self.0.as_ref())
    }
}

/// EISA ID String
pub struct AmlEisaId {
    name: String,
}

impl AmlEisaId {
    pub fn new(name: &str) -> AmlEisaId {
        if name.len() != 7 {
            panic!("Eisa: String length is not 7.");
        }
        AmlEisaId {
            name: name.to_string(),
        }
    }
}

impl AmlBuilder for AmlEisaId {
    fn aml_bytes(&self) -> Vec<u8> {
        let chars = self.name.chars().collect::<Vec<_>>();
        let dword: u32 = (chars[0] as u32 - 0x40) << 26
            | (chars[1] as u32 - 0x40) << 21
            | (chars[2] as u32 - 0x40) << 16
            | chars[3].to_digit(16).unwrap() << 12
            | chars[4].to_digit(16).unwrap() << 8
            | chars[5].to_digit(16).unwrap() << 4
            | chars[6].to_digit(16).unwrap();

        let mut bytes = dword.as_bytes().to_vec();
        bytes.reverse();
        bytes.insert(0, 0x0C);
        bytes
    }
}

/// Convert an ASCII string to a 128-bit buffer.
/// format: aabbccdd-eeff-gghh-iijj-kkllmmnnoopp
pub struct AmlToUuid {
    name: String,
}

impl AmlToUuid {
    pub fn new(str: &str) -> AmlToUuid {
        let name = str.to_string();
        if !Self::check_valid_uuid(&name) {
            panic!("Invalid UUID");
        }

        AmlToUuid { name }
    }

    /// Check if the uuid is valid.
    fn check_valid_uuid(uuid: &str) -> bool {
        if uuid.len() != 36 {
            return false;
        }

        // Char located at 8, 13, 18, 23 should be `-`
        let indexs = &[8, 13, 18, 23];
        for i in indexs {
            if uuid.chars().nth(*i).unwrap() != '-' {
                return false;
            }
        }

        for ch in uuid.chars() {
            if ch != '-' && (!ch.is_ascii_hexdigit()) {
                return false;
            }
        }

        true
    }
}

impl AmlBuilder for AmlToUuid {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // If the UUID is "aabbccdd-eeff-gghh-iijj-kkllmmnnoopp", then the encoded order is:
        // dd cc bb aa ff ee hh gg ii jj kk ll mm nn oo pp
        let index = &[6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34];

        for i in index {
            let mut chars = self.name.chars();
            bytes.push(
                (chars.nth(*i).unwrap().to_digit(16).unwrap() as u8) << 4
                    | chars.next().unwrap().to_digit(16).unwrap() as u8,
            );
        }

        bytes
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_uuid() {
        let uuid = AmlToUuid::new("33DB4D5B-1FF7-401C-9657-7441C03DD766");

        assert_eq!(
            uuid.aml_bytes(),
            &[
                0x5B, 0x4D, 0xDB, 0x33, 0xF7, 0x1F, 0x1C, 0x40, 0x96, 0x57, 0x74, 0x41, 0xC0, 0x3D,
                0xD7, 0x66
            ]
        );
    }
}
