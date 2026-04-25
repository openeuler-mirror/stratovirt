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

use std::os::fd::{AsRawFd, RawFd};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};

use anyhow::{Context, Result};
use vmm_sys_util::eventfd::EventFd;

use super::{
    ctl::Ctl, pcm::Pcm, spec::*, CtrlIoHandler, EventIoHandler, IoHandler, RxIoHandler,
    SoundConfig, TxIoHandler,
};
use crate::{
    read_config_default, Element, Queue, VirtioBase, VirtioDevice, VirtioError, VirtioInterrupt,
    VirtioInterruptType, VIRTIO_F_VERSION_1, VIRTIO_TYPE_SOUND,
};
use address_space::{AddressSpace, RegionCache};
use audio::{
    auth::{register_authority_notifier, unregister_authority_notifier, AuthorityNotifier},
    set_record_authority,
    volume::{create_volume_control, VolumeControl},
};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::byte_code::ByteCode;
use util::gen_base_func;

pub struct Sound {
    base: VirtioBase,
    config: SoundConfig,
    token_id: Option<Arc<RwLock<u64>>>,
    volume_ctrl: Arc<dyn VolumeControl>,
    volume_listener_id: Option<u64>,
    event_handler: Option<Arc<EventIoHandler>>,
}

impl Sound {
    /// Create a sound device.
    ///
    /// # Arguments
    ///
    /// * `config` - sound configuration.
    /// * `token_id` - HAP's token id to create capture stream.
    pub fn new(config: SoundConfig, token_id: Option<Arc<RwLock<u64>>>) -> Sound {
        set_record_authority(config.record_auth);

        let volume_ctrl = create_volume_control(config.backendtype.clone());

        Sound {
            base: VirtioBase::new(VIRTIO_TYPE_SOUND, VIRTIO_QUEUE_MAX, VIRTIO_SND_QUEUE_SIZE),
            config,
            token_id,
            volume_ctrl,
            volume_listener_id: None,
            event_handler: None,
        }
    }

    fn register_notifier<T: IoHandler>(
        &mut self,
        handler: Arc<T>,
        iothread: Option<String>,
        fd: RawFd,
    ) -> Result<()> {
        let notifiers = T::register_notifier(handler, fd);
        register_event_helper(notifiers, iothread.as_ref(), &mut self.base.deactivate_evts)
    }
}

impl VirtioDevice for Sound {
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

    fn realize(&mut self) -> Result<()> {
        self.init_config_features()
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_SND_F_CTLS);
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let config = VirtioSndConfig {
            jacks: VIRTIO_SND_JACK_DEFAULT,
            streams: VIRTIO_SND_STREAM_DEFAULT,
            chmaps: VIRTIO_SND_CHMAP_DEFAULT,
            controls: VIRTIO_SND_CTL_DEFAULT,
        };
        read_config_default(config.as_bytes(), offset, data)
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = self.base.queues.clone();

        let ctl = Arc::new(Mutex::new(Ctl::new(self.volume_ctrl.clone())));

        let pcm = Arc::new(Mutex::new(Pcm::new(
            VIRTIO_SND_STREAM_DEFAULT,
            self.token_id.clone(),
            self.config.backendtype.clone(),
        )));
        let tx_virtq = VirtQ::new(
            self.base.driver_features,
            mem_space.clone(),
            queues[VIRTIO_QUEUE_TX_IDX].clone(),
            self.base.broken.clone(),
            interrupt_cb.clone(),
        );
        let rx_virtq = VirtQ::new(
            self.base.driver_features,
            mem_space.clone(),
            queues[VIRTIO_QUEUE_RX_IDX].clone(),
            self.base.broken.clone(),
            interrupt_cb.clone(),
        );
        pcm.lock()
            .unwrap()
            .init_stream(VIRTIO_SND_STREAM_DEFAULT, tx_virtq, rx_virtq);

        // queues[0] is for control.
        self.register_notifier(
            CtrlIoHandler::new(
                VirtQ::new(
                    self.base.driver_features,
                    mem_space.clone(),
                    queues[VIRTIO_QUEUE_CTRL_IDX].clone(),
                    self.base.broken.clone(),
                    interrupt_cb.clone(),
                ),
                pcm.clone(),
                ctl.clone(),
            ),
            self.config.iothread.clone(),
            queue_evts[VIRTIO_QUEUE_CTRL_IDX].as_raw_fd(),
        )
        .with_context(|| "Failed to register sound ctrl notifier to MainLoop")?;

        // queues[1] is for event.
        let event_handler = EventIoHandler::new(
            VirtQ::new(
                self.base.driver_features,
                mem_space.clone(),
                queues[VIRTIO_QUEUE_EVENT_IDX].clone(),
                self.base.broken.clone(),
                interrupt_cb.clone(),
            ),
            ctl,
        );
        register_authority_notifier(event_handler.clone());
        self.volume_listener_id = Some(self.volume_ctrl.register_listener(event_handler.clone()));
        self.event_handler = Some(event_handler);

        // queues[2] is for tx.
        self.register_notifier(
            TxIoHandler::new(
                VirtQ::new(
                    self.base.driver_features,
                    mem_space.clone(),
                    queues[VIRTIO_QUEUE_TX_IDX].clone(),
                    self.base.broken.clone(),
                    interrupt_cb.clone(),
                ),
                pcm.clone(),
            ),
            self.config.iothread.clone(),
            queue_evts[VIRTIO_QUEUE_TX_IDX].as_raw_fd(),
        )
        .with_context(|| "Failed to register sound tx notifier to MainLoop")?;

        // queues[3] is for rx.
        self.register_notifier(
            RxIoHandler::new(
                VirtQ::new(
                    self.base.driver_features,
                    mem_space.clone(),
                    queues[VIRTIO_QUEUE_RX_IDX].clone(),
                    self.base.broken.clone(),
                    interrupt_cb.clone(),
                ),
                pcm.clone(),
            ),
            self.config.iothread.clone(),
            queue_evts[VIRTIO_QUEUE_RX_IDX].as_raw_fd(),
        )
        .with_context(|| "Failed to register sound rx notifier to MainLoop")?;

        self.base.broken.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        if let Some(id) = self.volume_listener_id.take() {
            self.volume_ctrl.unregister_listener(id);
        }

        if let Some(handler) = self.event_handler.take() {
            unregister_authority_notifier(&(handler as Arc<dyn AuthorityNotifier>));
        }

        unregister_event_helper(
            self.config.iothread.as_ref(),
            &mut self.base.deactivate_evts,
        )
    }
}

#[derive(Clone)]
pub struct VirtQ {
    /// The features of driver.
    driver_features: u64,
    /// Address space.
    mem_space: Arc<AddressSpace>,
    /// Queue.
    queue: Arc<Mutex<Queue>>,
    /// Device is broken or not.
    device_broken: Arc<AtomicBool>,
    /// The interrupt call back function.
    interrupt_cb: Arc<VirtioInterrupt>,
}

impl VirtQ {
    pub fn new(
        driver_features: u64,
        mem_space: Arc<AddressSpace>,
        queue: Arc<Mutex<Queue>>,
        device_broken: Arc<AtomicBool>,
        interrupt_cb: Arc<VirtioInterrupt>,
    ) -> Self {
        Self {
            driver_features,
            mem_space,
            queue,
            device_broken,
            interrupt_cb,
        }
    }

    pub fn pop_elem(&self) -> Result<Element> {
        self.queue
            .lock()
            .unwrap()
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
    }

    pub fn add_used(&self, index: u16, len: u32) -> Result<()> {
        let mut locked_queue = self.queue.lock().unwrap();
        locked_queue.vring.add_used(index, len)?;
        if locked_queue.vring.should_notify(self.driver_features) {
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&locked_queue), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger("sound", VirtioInterruptType::Vring)
                })?;
        }
        Ok(())
    }

    #[inline]
    pub fn sys_mem(&self) -> Arc<AddressSpace> {
        self.mem_space.clone()
    }

    #[inline]
    pub fn get_cache(&self) -> Option<RegionCache> {
        *self.queue.lock().unwrap().vring.get_cache()
    }

    #[inline]
    pub fn device_broken(&self) -> bool {
        self.device_broken.load(Ordering::SeqCst)
    }
}
