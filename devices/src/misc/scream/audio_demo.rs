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

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    thread,
};

use core::time;
use log::error;

use super::{AudioInterface, ScreamDirection, StreamData};

pub struct AudioDemo {
    file: File,
}

impl AudioDemo {
    pub fn init(dir: ScreamDirection, playback: String, record: String) -> Self {
        let file = match dir {
            ScreamDirection::Playback => OpenOptions::new()
                .append(true)
                .open(playback)
                .unwrap_or_else(|e| {
                    error!("Failed to append open Audio Demo file: {:?}", e);
                    panic!()
                }),
            ScreamDirection::Record => File::open(record).unwrap_or_else(|e| {
                error!("Failed to append open Audio Demo file: {:?}", e);
                panic!()
            }),
        };

        Self { file }
    }
}

impl AudioInterface for AudioDemo {
    fn send(&mut self, recv_data: &StreamData) {
        // SAFETY: Audio demo device is only used for test.
        let data = unsafe {
            std::slice::from_raw_parts(
                recv_data.audio_base as *const u8,
                recv_data.audio_size as usize,
            )
        };

        self.file
            .write_all(data)
            .unwrap_or_else(|e| error!("Failed to write data to file: {:?}", e));

        self.file
            .flush()
            .unwrap_or_else(|e| error!("Failed to flush data to file: {:?}", e));
    }

    fn receive(&mut self, recv_data: &StreamData) -> i32 {
        thread::sleep(time::Duration::from_millis(20));
        // SAFETY: Audio demo device is only used for test.
        let data = unsafe {
            std::slice::from_raw_parts_mut(
                recv_data.audio_base as *mut u8,
                recv_data.audio_size as usize,
            )
        };
        let size = self.file.read(data).unwrap_or_else(|e| {
            error!("Failed to read data to file: {:?}", e);
            0
        });

        if size == data.len() {
            1
        } else {
            0
        }
    }

    fn destroy(&mut self) {}
}
