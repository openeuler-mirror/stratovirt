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

use std::sync::{Arc, Mutex, RwLock};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    thread,
};

use core::time;
use log::error;

use super::{AudioExtension, AudioInterface, AudioStatus, ScreamDirection, StreamData};
use crate::misc::ivshmem::Ivshmem;

pub const INITIAL_VOLUME_VAL: u32 = 0xaa;
const IVSHMEM_VOLUME_SYNC_VECTOR: u16 = 0;

pub struct DemoAudioVolume {
    shm_dev: Arc<Mutex<Ivshmem>>,
    vol: RwLock<u32>,
}

// SAFETY: all fields are protected by lock
unsafe impl Send for DemoAudioVolume {}
// SAFETY: all fields are protected by lock
unsafe impl Sync for DemoAudioVolume {}

impl AudioExtension for DemoAudioVolume {
    fn get_host_volume(&self) -> u32 {
        *self.vol.read().unwrap()
    }

    fn set_host_volume(&self, vol: u32) {
        *self.vol.write().unwrap() = vol;
    }
}

impl DemoAudioVolume {
    pub fn new(shm_dev: Arc<Mutex<Ivshmem>>) -> Arc<Self> {
        let vol = Arc::new(Self {
            shm_dev,
            vol: RwLock::new(0),
        });
        vol.notify(INITIAL_VOLUME_VAL);
        vol
    }

    fn notify(&self, vol: u32) {
        *self.vol.write().unwrap() = vol;
        self.shm_dev
            .lock()
            .unwrap()
            .trigger_msix(IVSHMEM_VOLUME_SYNC_VECTOR);
    }
}

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

    fn get_status(&self) -> AudioStatus {
        AudioStatus::Started
    }
}
