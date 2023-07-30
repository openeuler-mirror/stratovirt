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

// The num of high priority queue
const VIRIOT_FS_HIGH_PRIO_QUEUE_NUM: usize = 1;
// The num of request queue
const VIRTIO_FS_REQ_QUEUES_NUM: usize = 1;
// The size of queue for virtio fs
const VIRTIO_FS_QUEUE_SIZE: u16 = 128;

use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use log::error;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use address_space::AddressSpace;
use machine_manager::config::{FsConfig, MAX_TAG_LENGTH};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};

use super::super::super::{VirtioDevice, VIRTIO_TYPE_FS};
use super::super::{VhostNotify, VhostOps};
use super::{VhostBackendType, VhostUserClient};
use crate::{read_config_default, VirtioBase, VirtioInterrupt, VirtioInterruptType};

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; MAX_TAG_LENGTH],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; MAX_TAG_LENGTH],
            num_request_queues: 0,
        }
    }
}

impl ByteCode for VirtioFsConfig {}

struct VhostUserFsHandler {
    interrupt_cb: Arc<VirtioInterrupt>,
    host_notifies: Vec<VhostNotify>,
}

impl EventNotifierHelper for VhostUserFsHandler {
    fn internal_notifiers(vhost_user_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        let vhost_user = vhost_user_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let locked_vhost_user = vhost_user.lock().unwrap();
            for host_notify in locked_vhost_user.host_notifies.iter() {
                if let Err(e) = (locked_vhost_user.interrupt_cb)(
                    &VirtioInterruptType::Vring,
                    Some(&host_notify.queue.lock().unwrap()),
                    false,
                ) {
                    error!(
                        "Failed to trigger interrupt for vhost user device, error is {:?}",
                        e
                    );
                }
            }
            None as Option<Vec<EventNotifier>>
        });
        for host_notify in vhost_user_handler.lock().unwrap().host_notifies.iter() {
            notifiers.push(EventNotifier::new(
                NotifierOperation::AddShared,
                host_notify.notify_evt.as_raw_fd(),
                None,
                EventSet::IN,
                vec![handler.clone()],
            ));
        }

        notifiers
    }
}

pub struct Fs {
    base: VirtioBase,
    fs_cfg: FsConfig,
    config_space: VirtioFsConfig,
    client: Option<Arc<Mutex<VhostUserClient>>>,
    mem_space: Arc<AddressSpace>,
    /// The notifier events from host.
    call_events: Vec<Arc<EventFd>>,
    enable_irqfd: bool,
}

impl Fs {
    /// The construct function of the Fs device.
    ///
    /// # Arguments
    ///
    /// `fs_cfg` - The config of this Fs device.
    /// `mem_space` - The address space of this Fs device.
    /// `enable_irqfd` - Whether irqfd is enabled on this Fs device.
    pub fn new(fs_cfg: FsConfig, mem_space: Arc<AddressSpace>, enable_irqfd: bool) -> Self {
        let queue_num = VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM;
        let queue_size = VIRTIO_FS_QUEUE_SIZE;

        Fs {
            base: VirtioBase::new(VIRTIO_TYPE_FS, queue_num, queue_size),
            fs_cfg,
            config_space: VirtioFsConfig::default(),
            client: None,
            mem_space,
            call_events: Vec::<Arc<EventFd>>::new(),
            enable_irqfd,
        }
    }
}

impl VirtioDevice for Fs {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        let queues_num = VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM;
        let client = VhostUserClient::new(
            &self.mem_space,
            &self.fs_cfg.sock,
            queues_num as u64,
            VhostBackendType::TypeFs,
        )
        .with_context(|| {
            "Failed to create the client which communicates with the server for virtio fs"
        })?;
        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;
        self.client = Some(client);

        self.init_config_features()?;

        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let tag_bytes_vec = self.fs_cfg.tag.clone().into_bytes();
        self.config_space.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
        self.config_space.num_request_queues = VIRTIO_FS_REQ_QUEUES_NUM as u32;

        let client = self.client.as_ref().unwrap();
        self.base.device_features = client
            .lock()
            .unwrap()
            .get_features()
            .with_context(|| "Failed to get features for virtio fs")?;

        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        read_config_default(self.config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = &self.base.queues;
        let mut host_notifies = Vec::new();
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for virtio fs")),
        };
        client.features = self.base.driver_features;
        client.set_queues(queues);
        client.set_queue_evts(&queue_evts);
        client.activate_vhost_user()?;

        if !self.enable_irqfd {
            for (queue_index, queue_mutex) in queues.iter().enumerate() {
                let host_notify = VhostNotify {
                    notify_evt: self.call_events[queue_index].clone(),
                    queue: queue_mutex.clone(),
                };
                host_notifies.push(host_notify);
            }

            let handler = VhostUserFsHandler {
                interrupt_cb,
                host_notifies,
            };

            let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
            register_event_helper(notifiers, None, &mut self.base.deactivate_evts)?;
        }

        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        for fd in queue_evts.iter() {
            let cloned_evt_fd = fd.clone();
            self.call_events.push(cloned_evt_fd);
        }
        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for virtio fs")),
        }
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(None, &mut self.base.deactivate_evts)?;
        self.call_events.clear();
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.base.device_features = 0_u64;
        self.base.driver_features = 0_u64;
        self.config_space = VirtioFsConfig::default();

        let client = match &self.client {
            None => return Err(anyhow!("Failed to get client when resetting virtio fs")),
            Some(client_) => client_,
        };
        client
            .lock()
            .unwrap()
            .delete_event()
            .with_context(|| "Failed to delete virtio fs event")?;
        self.client = None;

        self.realize()
    }
}
