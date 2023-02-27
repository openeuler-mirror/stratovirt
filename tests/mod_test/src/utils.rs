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

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn get_rand_str(size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

pub fn create_dir(dir_path: &str) {
    fs::create_dir(dir_path).unwrap();
}

pub fn get_tmp_dir() -> String {
    let dir_name = format!("/tmp/test-{}", get_rand_str(10));
    create_dir(&dir_name);
    dir_name
}

pub fn read_le_u16(input: &mut &[u8]) -> u16 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u16>());
    *input = rest;
    u16::from_le_bytes(int_bytes.try_into().unwrap())
}

pub fn read_le_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_le_bytes(int_bytes.try_into().unwrap())
}

pub fn read_le_u64(input: &mut &[u8]) -> u64 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u64>());
    *input = rest;
    u64::from_le_bytes(int_bytes.try_into().unwrap())
}

pub fn swap_u16(value: u16) -> u16 {
    return value << 8 | value >> 8;
}

pub fn swap_u32(value: u32) -> u32 {
    let lower_u16 = swap_u16(value as u16) as u32;
    let higher_u16 = swap_u16((value >> 16) as u16) as u32;
    lower_u16 << 16 | higher_u16
}

pub fn swap_u64(value: u64) -> u64 {
    let lower_u32 = swap_u32(value as u32) as u64;
    let higher_u32 = swap_u32((value >> 32) as u32) as u64;
    lower_u32 << 32 | higher_u32
}

pub const TEST_IMAGE_SIZE: u64 = 64 * 1024 * 1024;
/// Create image file.
pub fn create_img(size: u64, flag: u8) -> String {
    let rng_name: String = get_rand_str(8);

    assert!(cfg!(target_os = "linux"));

    let mut image_path = format!("/tmp/stratovirt-{}.img", rng_name);
    if flag == 1 {
        image_path = format!("/var/log/stratovirt-{}.img", rng_name);
    }

    let image_path_of = format!("of={}", &image_path);
    let image_size_of = format!("bs={}", size);
    let output = Command::new("dd")
        .arg("if=/dev/zero")
        .arg(&image_path_of)
        .arg(&image_size_of)
        .arg("count=1")
        .output()
        .expect("failed to create image");
    assert!(output.status.success());
    image_path
}

/// Delete image file.
pub fn cleanup_img(image_path: String) {
    let img_path = Path::new(&image_path);
    assert!(img_path.exists());

    let metadata = fs::metadata(img_path).expect("can not get file metadata");
    let file_type = metadata.file_type();
    assert!(file_type.is_file());

    fs::remove_file(img_path).expect("lack permissions to remove the file");
}
