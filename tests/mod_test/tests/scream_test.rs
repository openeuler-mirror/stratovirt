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
    cell::RefCell,
    fs::{self, File},
    io::{Read, Write},
    mem,
    path::Path,
    rc::Rc,
    thread,
};

use core::time;

use devices::misc::scream::{ShmemHeader, ShmemStreamFmt, ShmemStreamHeader, SCREAM_MAGIC};
use mod_test::{
    libdriver::{ivshmem::TestIvshmemDev, machine::TestStdMachine},
    libtest::{test_init, TestState, MACHINE_TYPE_ARG},
    utils::get_rand_str,
};
use util::{num_ops::read_data_u32, offset_of};

const PLAY_BASE: u64 = mem::size_of::<u64>() as u64;
const PLAY_DADA_OFFSET: u64 = mem::size_of::<ShmemHeader>() as u64;

const RECORD_BASE: u64 = PLAY_BASE + mem::size_of::<ShmemStreamHeader>() as u64;
const RECORD_DATA_OFFSET: u64 = PLAY_DADA_OFFSET + (AUDIO_CHUNK_SIZE * AUDIO_CHUNK_CNT) as u64;

const IVSHMEM_DEFAULT_SIZE: u32 = 2;
const AUDIO_CHUNK_SIZE: u32 = 4;
const AUDIO_CHUNK_CNT: u32 = 7;
const AUDIO_DEFAULT_DATA: [u8; (AUDIO_CHUNK_SIZE * AUDIO_CHUNK_CNT) as usize] = [
    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
];

const POLL_DELAY_MS: u64 = 20;
const POLL_MAX_CNT: u32 = 5;

fn get_audio_file_name() -> (String, String) {
    let playback_path = format!("/tmp/audio-{}.pcm", get_rand_str(8));
    let record_path = format!("/tmp/audio-{}.pcm", get_rand_str(8));
    (playback_path, record_path)
}

fn set_up(
    size: u32,
    pci_slot: u8,
    playback_path: String,
    record_path: String,
) -> (Rc<RefCell<TestIvshmemDev>>, Rc<RefCell<TestState>>) {
    let mut extra_args: Vec<&str> = Vec::new();
    let mut args: Vec<&str> = MACHINE_TYPE_ARG.split(' ').collect();

    extra_args.append(&mut args);

    let scream_device = format!(
        "-device ivshmem-scream,memdev=scream,id=scream,interface=Demo,playback={},record={},bus=pcie.0,addr={}",
        playback_path, record_path, pci_slot,
    );
    args = scream_device.split(' ').collect();
    extra_args.append(&mut args);

    let object = format!(
        "-object memory-backend-ram,id=scream,share=on,size={}M",
        size
    );
    args = object.split(' ').collect();
    extra_args.append(&mut args);

    let test_state = Rc::new(RefCell::new(test_init(extra_args)));
    let machine = TestStdMachine::new(test_state.clone());

    let ivshmem = Rc::new(RefCell::new(TestIvshmemDev::new(machine.pci_bus)));

    (ivshmem, test_state)
}

fn stream_header_init(ivshmem: &mut TestIvshmemDev, base: u64, offset: u64) {
    // set chunk_idx
    ivshmem.writew(base + offset_of!(ShmemStreamHeader, chunk_idx) as u64, 0);
    // set max_chunks
    ivshmem.writew(
        base + offset_of!(ShmemStreamHeader, max_chunks) as u64,
        AUDIO_CHUNK_CNT as u16 - 1,
    );
    // set chunk_size
    ivshmem.writel(
        base + offset_of!(ShmemStreamHeader, chunk_size) as u64,
        AUDIO_CHUNK_SIZE,
    );
    // set offset
    ivshmem.writel(
        base + offset_of!(ShmemStreamHeader, offset) as u64,
        offset as u32,
    );

    let fmt_base = base + offset_of!(ShmemStreamHeader, fmt) as u64;
    // set fmt_generation
    ivshmem.writel(
        fmt_base + offset_of!(ShmemStreamFmt, fmt_generation) as u64,
        1,
    );
    // set rate
    ivshmem.writeb(fmt_base + offset_of!(ShmemStreamFmt, rate) as u64, 128);
    // set size
    ivshmem.writeb(fmt_base + offset_of!(ShmemStreamFmt, size) as u64, 16);
    // set channel
    ivshmem.writeb(fmt_base + offset_of!(ShmemStreamFmt, channels) as u64, 2);
    // set channel_map
    ivshmem.writel(fmt_base + offset_of!(ShmemStreamFmt, channel_map) as u64, 3);

    // Setting is_started, it must be set at the end. Otherwise, the fmt data may not be updated in
    // time.
    ivshmem.writel(base + offset_of!(ShmemStreamHeader, is_started) as u64, 1);
}

fn play_header_init(ivshmem: &mut TestIvshmemDev) {
    // set magic
    ivshmem.writeq(0, SCREAM_MAGIC);
    let base = PLAY_BASE;
    stream_header_init(ivshmem, base, PLAY_DADA_OFFSET);
}

fn play_audio_data_init(playback: String) {
    if Path::new(playback.as_str()).exists() {
        match fs::remove_file(playback.clone()) {
            Ok(_) => {}
            Err(e) => assert!(false, "{}", e),
        }
    }
    match fs::File::create(playback) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }
}

fn record_header_init(ivshmem: &mut TestIvshmemDev) {
    play_header_init(ivshmem);
    let base = RECORD_BASE;
    stream_header_init(ivshmem, base, RECORD_DATA_OFFSET);
}

fn record_audio_data_init(record: String) {
    if Path::new(record.as_str()).exists() {
        match fs::remove_file(record.clone()) {
            Ok(_) => {}
            Err(e) => assert!(false, "{}", e),
        }
    }
    let mut file = match fs::File::create(record) {
        Ok(file) => file,
        Err(e) => {
            assert!(false, "{}", e);
            return;
        }
    };
    match file.write(&AUDIO_DEFAULT_DATA) {
        Ok(_) => {}
        Err(e) => assert!(false, "{}", e),
    }
}

fn audio_data_init(playback: String, record: String) {
    play_audio_data_init(playback);
    record_audio_data_init(record);
}

fn scream_tmp_clear(playback_path: String, record_path: String) {
    if Path::new(playback_path.as_str()).exists() {
        match fs::remove_file(playback_path) {
            Ok(_) => {}
            Err(e) => assert!(false, "{}", e),
        }
    }

    if Path::new(record_path.as_str()).exists() {
        match fs::remove_file(record_path) {
            Ok(_) => {}
            Err(e) => assert!(false, "{}", e),
        }
    }
}

fn read_and_check_data(file: &mut File, src: &[u8], len: u32) {
    let mut data: [u8; AUDIO_CHUNK_SIZE as usize] = [0; AUDIO_CHUNK_SIZE as usize];
    let size = match file.read(&mut data) {
        Ok(size) => size,
        Err(e) => {
            assert!(false, "{}", e);
            0
        }
    };
    assert_eq!(size, len as usize);
    if len != 0 {
        assert_eq!(data, src);
    }
}

/// scream device playback audio.
/// TestStep:
///   1. Init scream device.
///   2. Send first audio frame.
///   3. Send four consecutive audio frames.
///   4. change audio format.
///   5. Stop VM.
///   6. Check audio frames from audio file.
/// Expect:
///   1/2/3/4/5/6: success.
#[test]
fn scream_playback_basic_test() {
    let pci_slot = 0x1;
    let (playback_path, record_path) = get_audio_file_name();
    audio_data_init(playback_path.clone(), record_path.clone());
    let (ivshmem, test_state) = set_up(
        IVSHMEM_DEFAULT_SIZE,
        pci_slot,
        playback_path.clone(),
        record_path.clone(),
    );
    ivshmem.borrow_mut().init(pci_slot);

    // Wait for 1s until the scream device is initialized and enters the polling state to
    // prevent subsequent audio frame data loss.
    thread::sleep(time::Duration::from_millis(1000));

    play_header_init(&mut ivshmem.borrow_mut());

    thread::sleep(time::Duration::from_millis(POLL_DELAY_MS));

    // write one audio chunk
    for i in 0..AUDIO_CHUNK_SIZE {
        ivshmem.borrow_mut().writeb(
            PLAY_DADA_OFFSET + (AUDIO_CHUNK_SIZE + i) as u64,
            AUDIO_DEFAULT_DATA[i as usize],
        );
    }

    // update play header chunk_idx
    ivshmem.borrow_mut().writew(
        PLAY_BASE + offset_of!(ShmemStreamHeader, chunk_idx) as u64,
        1,
    );

    thread::sleep(time::Duration::from_millis(1000));

    // When four consecutive frames of data are written, only the last two frames of data can be
    // read.
    for i in 0..AUDIO_CHUNK_SIZE {
        ivshmem
            .borrow_mut()
            .writeb(PLAY_DADA_OFFSET + i as u64, AUDIO_DEFAULT_DATA[i as usize]);
    }

    // update play header chunk_idx
    ivshmem.borrow_mut().writew(
        PLAY_BASE + offset_of!(ShmemStreamHeader, chunk_idx) as u64,
        0,
    );

    thread::sleep(time::Duration::from_millis(1000));

    // Reformat audio, change fmt_generation from 1 to 2.
    let fmt_base = PLAY_BASE + offset_of!(ShmemStreamHeader, fmt) as u64;
    ivshmem.borrow_mut().writel(
        fmt_base + offset_of!(ShmemStreamFmt, fmt_generation) as u64,
        2,
    );

    ivshmem.borrow_mut().writew(
        PLAY_BASE + offset_of!(ShmemStreamHeader, chunk_idx) as u64,
        1,
    );

    thread::sleep(time::Duration::from_millis(1000));

    // Stop the StratoVirt process before verifying data. Otherwise,
    // audio data may not be updated to the file.
    test_state.borrow_mut().stop();

    let mut file = match File::open(playback_path.clone()) {
        Ok(file) => file,
        Err(e) => {
            assert!(false, "{}", e);
            return;
        }
    };

    // Check first frame
    read_and_check_data(
        &mut file,
        &AUDIO_DEFAULT_DATA[0..AUDIO_CHUNK_SIZE as usize],
        AUDIO_CHUNK_SIZE,
    );

    // Check penultimate frame
    read_and_check_data(&mut file, &[0; AUDIO_CHUNK_SIZE as usize], AUDIO_CHUNK_SIZE);

    // Check last frame
    read_and_check_data(
        &mut file,
        &AUDIO_DEFAULT_DATA[0..AUDIO_CHUNK_SIZE as usize],
        AUDIO_CHUNK_SIZE,
    );

    // No audio frame after audio format changed.
    read_and_check_data(&mut file, &[0; AUDIO_CHUNK_SIZE as usize], 0);

    scream_tmp_clear(playback_path, record_path);
}

/// scream device record audio.
/// TestStep:
///   1. Init scream device and start recording.
///   2. Check first frame audio.
///   3. Check last frame audio.
///   4. Stop VM.
/// Expect:
///   1/2/3/4: success.
#[test]
fn scream_record_basic_test() {
    let pci_slot = 0x1;
    let (playback_path, record_path) = get_audio_file_name();
    audio_data_init(playback_path.clone(), record_path.clone());
    let (ivshmem, test_state) = set_up(
        IVSHMEM_DEFAULT_SIZE,
        pci_slot,
        playback_path.clone(),
        record_path.clone(),
    );
    ivshmem.borrow_mut().init(pci_slot);

    record_header_init(&mut ivshmem.borrow_mut());

    let mut cnt = 0;
    let mut chunk_idx = 0;
    // Waiting for first chunk data write to ivshmem, then check first chunk data.
    while cnt < POLL_MAX_CNT {
        thread::sleep(time::Duration::from_millis(POLL_DELAY_MS >> 1));

        // read chunk_idx
        let offset = RECORD_BASE + offset_of!(ShmemStreamHeader, chunk_idx) as u64;
        chunk_idx = ivshmem.borrow_mut().readw(offset);
        if chunk_idx > 0 {
            break;
        }
        cnt += 1;
    }

    assert_eq!(chunk_idx, 1);

    let audio_data = ivshmem.borrow_mut().readl(RECORD_DATA_OFFSET);
    let mut check_data = 0;
    read_data_u32(
        &AUDIO_DEFAULT_DATA[0..AUDIO_CHUNK_SIZE as usize],
        &mut check_data,
    );

    assert_eq!(audio_data, check_data);

    // Sleep 2S to wait last chunk data write to ivshmem, and check last chunk data.
    thread::sleep(time::Duration::from_millis(2000));
    // read chunk_idx
    let offset = RECORD_BASE + offset_of!(ShmemStreamHeader, chunk_idx) as u64;
    chunk_idx = ivshmem.borrow_mut().readw(offset);

    assert_eq!(chunk_idx as u32, AUDIO_CHUNK_CNT % (AUDIO_CHUNK_CNT - 1));

    let audio_data = ivshmem.borrow_mut().readl(RECORD_DATA_OFFSET);
    let mut check_data = 0;
    let start = ((AUDIO_CHUNK_CNT - 1) * AUDIO_CHUNK_SIZE) as usize;
    let end = (AUDIO_CHUNK_CNT * AUDIO_CHUNK_SIZE) as usize;
    read_data_u32(&AUDIO_DEFAULT_DATA[start..end], &mut check_data);

    assert_eq!(audio_data, check_data);

    test_state.borrow_mut().stop();
    scream_tmp_clear(playback_path, record_path);
}

/// scream device exception 001.
/// TestStep:
///   1. Init scream device.
///   2. Set buffer offset exceeded shared memory size.
///   3. Check StratoVirt process.
///   4. Stop VM.
/// Expect:
///   1/2/3/4: success.
#[test]
fn scream_exception_001() {
    let pci_slot = 0x1;
    let (playback_path, record_path) = get_audio_file_name();
    audio_data_init(playback_path.clone(), record_path.clone());
    let (ivshmem, test_state) = set_up(
        IVSHMEM_DEFAULT_SIZE,
        pci_slot,
        playback_path.clone(),
        record_path.clone(),
    );
    ivshmem.borrow_mut().init(pci_slot);

    play_header_init(&mut ivshmem.borrow_mut());
    record_header_init(&mut ivshmem.borrow_mut());

    // Setting playback and record buffer offset exceeded shared memory size.
    let playback_offset = PLAY_BASE + offset_of!(ShmemStreamHeader, offset) as u64;
    let mut buffer_offset = IVSHMEM_DEFAULT_SIZE * 1024 * 1024 + 1;
    ivshmem.borrow_mut().writel(playback_offset, buffer_offset);

    let record_offset = RECORD_BASE + offset_of!(ShmemStreamHeader, offset) as u64;
    buffer_offset = IVSHMEM_DEFAULT_SIZE * 1024 * 1024 + 2;
    ivshmem.borrow_mut().writel(record_offset, buffer_offset);

    // Wait for 1s, query StratoVirt status.
    thread::sleep(time::Duration::from_millis(1000));

    let value = test_state
        .borrow_mut()
        .qmp("{\"execute\": \"query-status\"}");
    let status = value["return"]["status"].as_str().unwrap().to_string();
    assert_eq!(status, "running".to_string());

    play_header_init(&mut ivshmem.borrow_mut());
    record_header_init(&mut ivshmem.borrow_mut());

    // Setting chunk_idx > max_chunk
    let mut chunk_offset = PLAY_BASE + offset_of!(ShmemStreamHeader, chunk_idx) as u64;
    ivshmem
        .borrow_mut()
        .writew(chunk_offset, AUDIO_CHUNK_CNT as u16);
    chunk_offset = RECORD_BASE + offset_of!(ShmemStreamHeader, chunk_idx) as u64;
    ivshmem
        .borrow_mut()
        .writew(chunk_offset, AUDIO_CHUNK_CNT as u16);

    // Wait for 1s, query StratoVirt status.
    thread::sleep(time::Duration::from_millis(1000));

    let value = test_state
        .borrow_mut()
        .qmp("{\"execute\": \"query-status\"}");
    let status = value["return"]["status"].as_str().unwrap().to_string();
    assert_eq!(status, "running".to_string());

    test_state.borrow_mut().stop();
    scream_tmp_clear(playback_path, record_path);
}

/// scream device exception 002.
/// TestStep:
///   1. Init scream device.
///   2. Set invalid channels and channel_map.
///   3. Send audio data.
///   4. Stop VM.
///   5. Check audio frames from audio file.
/// Expect:
///   1/2/3/4/5: success.
#[test]
fn scream_exception_002() {
    let pci_slot = 0x1;
    let (playback_path, record_path) = get_audio_file_name();
    audio_data_init(playback_path.clone(), record_path.clone());
    let (ivshmem, test_state) = set_up(
        IVSHMEM_DEFAULT_SIZE,
        pci_slot,
        playback_path.clone(),
        record_path.clone(),
    );
    ivshmem.borrow_mut().init(pci_slot);

    // Wait for 1s until the scream device is initialized and enters the polling state to
    // prevent subsequent audio frame data loss.
    thread::sleep(time::Duration::from_millis(1000));

    play_header_init(&mut ivshmem.borrow_mut());

    thread::sleep(time::Duration::from_millis(POLL_DELAY_MS));

    // Setting channels and channel_map to 0.
    let fmt_base = PLAY_BASE + offset_of!(ShmemStreamHeader, fmt) as u64;
    ivshmem
        .borrow_mut()
        .writeb(fmt_base + offset_of!(ShmemStreamFmt, channels) as u64, 0);
    ivshmem
        .borrow_mut()
        .writel(fmt_base + offset_of!(ShmemStreamFmt, channel_map) as u64, 0);

    // write one audio chunk
    for i in 0..AUDIO_CHUNK_SIZE {
        ivshmem.borrow_mut().writeb(
            PLAY_DADA_OFFSET + (AUDIO_CHUNK_SIZE + i) as u64,
            AUDIO_DEFAULT_DATA[i as usize],
        );
    }

    // update play header chunk_idx
    ivshmem.borrow_mut().writew(
        PLAY_BASE + offset_of!(ShmemStreamHeader, chunk_idx) as u64,
        1,
    );

    thread::sleep(time::Duration::from_millis(1000));

    // Stop the StratoVirt process before verifying data. Otherwise,
    // audio data may not be updated to the file.
    test_state.borrow_mut().stop();

    let mut file = match File::open(playback_path.clone()) {
        Ok(file) => file,
        Err(e) => {
            assert!(false, "{}", e);
            return;
        }
    };

    read_and_check_data(&mut file, &[0; AUDIO_CHUNK_SIZE as usize], 0);

    scream_tmp_clear(playback_path, record_path);
}
