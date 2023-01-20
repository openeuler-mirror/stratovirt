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

use crate::VirtioError;
use std::cmp;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use log::error;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use address_space::AddressSpace;
use machine_manager::config::{FsConfig, MAX_TAG_LENGTH};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::byte_code::ByteCode;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::num_ops::read_u32;

use super::super::super::{Queue, VirtioDevice, VIRTIO_TYPE_FS};
use super::super::{VhostNotify, VhostOps};
use super::VhostUserClient;
use crate::{VirtioInterrupt, VirtioInterruptType};
use anyhow::{anyhow, Context, Result};

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
    interrup_cb: Arc<VirtioInterrupt>,
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
                if let Err(e) = (locked_vhost_user.interrup_cb)(
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
    fs_cfg: FsConfig,
    config: VirtioFsConfig,
    client: Option<Arc<Mutex<VhostUserClient>>>,
    avail_features: u64,
    acked_features: u64,
    mem_space: Arc<AddressSpace>,
    /// The notifier events from host.
    call_events: Vec<Arc<EventFd>>,
    deactivate_evts: Vec<RawFd>,
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
        Fs {
            fs_cfg,
            config: VirtioFsConfig::default(),
            client: None,
            avail_features: 0_u64,
            acked_features: 0_u64,
            mem_space,
            call_events: Vec::<Arc<EventFd>>::new(),
            deactivate_evts: Vec::new(),
            enable_irqfd,
        }
    }
}

impl VirtioDevice for Fs {
    fn realize(&mut self) -> Result<()> {
        let tag_bytes_vec = self.fs_cfg.tag.clone().into_bytes();
        self.config.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
        self.config.num_request_queues = VIRTIO_FS_REQ_QUEUES_NUM as u32;

        let queues_num = VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM;
        let client = VhostUserClient::new(&self.mem_space, &self.fs_cfg.sock, queues_num as u64)
            .with_context(|| {
                "Failed to create the client which communicates with the server for virtio fs"
            })?;
        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;
        self.avail_features = client
            .lock()
            .unwrap()
            .get_features()
            .with_context(|| "Failed to get features for virtio fs")?;
        self.client = Some(client);

        Ok(())
    }

    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_FS
    }

    fn queue_num(&self) -> usize {
        VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM
    }

    fn queue_size(&self) -> u16 {
        VIRTIO_FS_QUEUE_SIZE
    }

    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.avail_features, features_select)
    }

    fn set_driver_features(&mut self, page: u32, value: u32) {
        self.acked_features = self.checked_driver_features(page, value);
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.acked_features, features_select)
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.config.as_bytes();
        let config_size = config_slice.len() as u64;
        if offset >= config_size {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_size)));
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_size) as usize])?;
        }

        Ok(())
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        interrup_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let mut host_notifies = Vec::new();
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for virtio fs")),
        };
        client.features = self.acked_features;
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
                interrup_cb,
                host_notifies,
            };

            let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
            register_event_helper(notifiers, None, &mut self.deactivate_evts)?;
        }

        Ok(())
    }

    /// Set guest notifiers for notifying the guest.
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
        unregister_event_helper(None, &mut self.deactivate_evts)?;
        self.call_events.clear();
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.avail_features = 0_u64;
        self.acked_features = 0_u64;
        self.config = VirtioFsConfig::default();

        let client = match &self.client {
            None => return Err(anyhow!("Failed to get client when reseting virtio fs")),
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
