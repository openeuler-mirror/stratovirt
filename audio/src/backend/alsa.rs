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

use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use alsa::{
    Direction,
    pcm::{Access, Format, Frames, PCM, State},
};
use anyhow::{Context, Result, bail};
use log::info;

use crate::{AudioInterface, AudioStreamDirection, AudioStreamIo, AudioStreamParams, PcmFmt};

/// Default buffer size in frames.
const DEFAULT_BUFFER_SIZE: i64 = 8816;
/// Default period size in frames.
const DEFAULT_PERIOD_SIZE: u64 = 2204;

pub struct Alsa {
    pcm: Arc<Mutex<PCM>>,
    direction: AudioStreamDirection,
    io_handler: Arc<dyn AudioStreamIo>,
    /// Worker thread handle.
    thread_handle: Option<JoinHandle<()>>,
    /// Flag to signal the worker thread to stop.
    running: Arc<AtomicBool>,
    /// Period size in bytes for each I/O operation.
    period_bytes: usize,
    /// Period duration in milliseconds.
    period_ms: u64,
}

// SAFETY: all fields are safe to send between threads.
unsafe impl Send for Alsa {}

impl AudioInterface for Alsa {
    fn new(
        params: AudioStreamParams,
        io_handler: Arc<dyn AudioStreamIo>,
        _token_id: Option<Arc<RwLock<u64>>>,
    ) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        let dir = match params.direction {
            AudioStreamDirection::Playback => Direction::Playback,
            AudioStreamDirection::Record => Direction::Capture,
        };

        let pcm = PCM::new("default", dir, false)?;

        // Configure hardware parameters
        {
            let hwp = alsa::pcm::HwParams::any(&pcm)?;

            // Set sample rate
            let rate = params.rate.hz();
            hwp.set_rate(rate, alsa::ValueOr::Nearest)
                .with_context(|| format!("Failed to set sample rate {}", rate))?;

            // Set sample format
            let format = match params.format {
                PcmFmt::FmtS16 => Format::S16LE,
                PcmFmt::FmtS24 => Format::S243LE,
                PcmFmt::FmtS32 => Format::S32LE,
            };
            hwp.set_format(format)
                .with_context(|| format!("Failed to set format {:?}", params.format))?;

            // Set channels
            hwp.set_channels(params.channels as u32)
                .with_context(|| format!("Failed to set channels {}", params.channels))?;

            // Set access mode
            hwp.set_access(Access::RWInterleaved)
                .context("Failed to set interleaved access")?;

            // Set buffer and period sizes
            hwp.set_buffer_size_near(DEFAULT_BUFFER_SIZE)
                .context("Failed to set buffer size")?;
            hwp.set_period_size_near(DEFAULT_PERIOD_SIZE as i64, alsa::ValueOr::Nearest)
                .context("Failed to set period size")?;

            pcm.hw_params(&hwp)
                .context("Failed to apply hardware parameters")?;
        }

        // Configure software parameters
        {
            let buffer_size = {
                let hwp = pcm.hw_params_current()?;
                hwp.get_buffer_size().context("Failed to get buffer size")?
            };

            let swp = pcm.sw_params_current().context("Failed to get sw_params")?;
            swp.set_start_threshold(buffer_size)
                .context("Failed to set start threshold")?;
            pcm.sw_params(&swp)
                .context("Failed to apply software parameters")?;

            pcm.prepare().context("Failed to prepare PCM")?;
        }

        // Calculate period_ms from period_bytes
        let period_ms =
            params.period_bytes as u64 * 1000 / (params.frame_size() * params.rate.hz()) as u64;

        Ok(Box::new(Self {
            pcm: Arc::new(Mutex::new(pcm)),
            direction: params.direction,
            io_handler,
            thread_handle: None,
            running: Arc::new(AtomicBool::new(false)),
            period_bytes: params.period_bytes as usize,
            period_ms,
        }))
    }

    fn start(&mut self) -> Result<()> {
        // Already running
        if self.thread_handle.is_some() {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);

        // For capture, start the PCM before reading
        if self.direction == AudioStreamDirection::Record {
            self.pcm
                .lock()
                .unwrap()
                .start()
                .context("Failed to start ALSA PCM for capture")?;
        }

        let running = self.running.clone();
        let io_handler = self.io_handler.clone();
        let pcm = self.pcm.clone();
        let direction = self.direction;
        let period_bytes = self.period_bytes;
        let period_ms = self.period_ms;

        let handle = thread::spawn(move || {
            let mut buffer = vec![0u8; period_bytes];

            while running.load(Ordering::SeqCst) {
                match direction {
                    AudioStreamDirection::Playback => {
                        // Read data from io_handler and write to PCM
                        match io_handler.read(&mut buffer) {
                            Ok(len) if len > 0 => {
                                if let Err(e) = write_pcm(&pcm, &buffer[..len]) {
                                    log::error!("ALSA playback write error: {:?}", e);
                                }
                            }
                            _ => {
                                // No data available, virtqueue might be empty
                            }
                        }
                    }
                    AudioStreamDirection::Record => {
                        // Read from PCM and push to io_handler
                        match read_pcm(&pcm, &mut buffer) {
                            Ok(len) if len > 0 => {
                                if let Err(e) = io_handler.write(&buffer[..len]) {
                                    log::error!("ALSA capture write to io_handler error: {:?}", e);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                thread::sleep(Duration::from_millis(period_ms));
            }
        });

        self.thread_handle = Some(handle);
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        // Signal the thread to stop
        self.running.store(false, Ordering::SeqCst);

        // Wait for the thread to finish
        if let Some(handle) = self.thread_handle.take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("Failed to join ALSA worker thread"))?;
        }

        // Stop the PCM
        let pcm = self.pcm.lock().unwrap();
        match self.direction {
            AudioStreamDirection::Playback => {
                pcm.drain().context("Failed to drain ALSA PCM")?;
            }
            AudioStreamDirection::Record => {
                info!("Stopping ALSA capture stream");
            }
        }
        pcm.prepare()
            .context("Failed to prepare ALSA PCM after stop")
    }
}

/// Write all of `data` to PCM for playback.
///
/// `snd_pcm_writei` may accept fewer frames than requested; we loop until the full buffer is
/// submitted. XRun is recovered and the current slice is retried without advancing.
fn write_pcm(pcm: &Arc<Mutex<PCM>>, data: &[u8]) -> Result<usize> {
    if data.is_empty() {
        return Ok(0);
    }

    let total_len = data.len();
    let mut offset = 0usize;

    while offset < total_len {
        let pcm_guard = pcm.lock().unwrap();

        if pcm_guard.state() != State::Running {
            pcm_guard.start().context("Failed to start PCM for write")?;
        }

        let slice = &data[offset..];
        match pcm_guard.io_bytes().writei(slice) {
            Ok(frames) => {
                let bytes = pcm_guard.frames_to_bytes(frames as Frames);
                if bytes < 0 {
                    bail!("ALSA frames_to_bytes returned negative value");
                }
                let n = bytes as usize;
                if n == 0 {
                    thread::yield_now();
                    continue;
                }
                offset = match offset.checked_add(n) {
                    Some(o) if o <= total_len => o,
                    Some(_) => bail!("ALSA wrote more bytes than supplied"),
                    None => bail!("ALSA playback offset overflow"),
                };
            }
            Err(e) => {
                if pcm_guard.state() == State::XRun {
                    pcm_guard
                        .prepare()
                        .context("Failed to prepare after XRun")?;
                    pcm_guard.start().context("Failed to start after XRun")?;
                    continue;
                } else {
                    bail!("ALSA write failed: {}", e);
                }
            }
        }
    }

    Ok(total_len)
}

/// Read until `data` is full from PCM for capture.
///
/// `snd_pcm_readi` may return fewer frames than requested (same as `writei`); we loop until the
/// buffer is full. `readi` reports **frames**; we convert to bytes via `frames_to_bytes`.
/// XRun (overrun) is recovered with `prepare`/`start` and the remainder is retried.
fn read_pcm(pcm: &Arc<Mutex<PCM>>, data: &mut [u8]) -> Result<usize> {
    if data.is_empty() {
        return Ok(0);
    }

    let total_len = data.len();
    let mut offset = 0usize;

    while offset < total_len {
        let pcm_guard = pcm.lock().unwrap();

        if pcm_guard.state() != State::Running {
            pcm_guard.start().context("Failed to start PCM for read")?;
        }

        match pcm_guard.io_bytes().readi(&mut data[offset..]) {
            Ok(frames) => {
                let bytes = pcm_guard.frames_to_bytes(frames as Frames);
                if bytes < 0 {
                    bail!("ALSA frames_to_bytes returned negative value");
                }
                let n = bytes as usize;
                if n == 0 {
                    thread::yield_now();
                    continue;
                }
                offset = match offset.checked_add(n) {
                    Some(o) if o <= total_len => o,
                    Some(_) => bail!("ALSA read more bytes than buffer capacity"),
                    None => bail!("ALSA capture offset overflow"),
                };
            }
            Err(e) => {
                if pcm_guard.state() == State::XRun {
                    pcm_guard
                        .prepare()
                        .context("Failed to prepare after XRun")?;
                    pcm_guard.start().context("Failed to start after XRun")?;
                    continue;
                } else {
                    bail!("ALSA read failed: {}", e);
                }
            }
        }
    }

    Ok(total_len)
}
