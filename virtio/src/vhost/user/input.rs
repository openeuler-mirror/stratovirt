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

//! vhost-user-input device frontend.
//!
//! This frontend is a thin passthrough to a userspace vhost-user backend
//! (e.g. rust-vmm `vhost-device-input`). Unlike the kernel virtio-input
//! implementation (`virtio::device::input`), which opens a host evdev node
//! and serves the config space from a cached `EvdevConfig`, this frontend
//! never touches an evdev device. Instead the config space is served over the
//! vhost-user protocol:
//!
//! * Guest writes `select`/`subsel` to the config space -> forwarded to the
//!   backend with [`VHOST_USER_SET_CONFIG`][crate::VhostUser::message::VhostUserMsgReq::SetConfig],
//!   preserving the exact write offset and length (the Linux virtio-input
//!   driver writes the two fields separately).
//! * Guest reads the config space -> the full 136-byte `virtio_input_config`
//!   is fetched from the backend with
//!   [`VHOST_USER_GET_CONFIG`][crate::VhostUser::message::VhostUserMsgReq::GetConfig]
//!   and the requested slice is returned. Reads are never cached because the
//!   payload depends on the backend's evdev state and the just-written
//!   `select`/`subsel`.
//!
//! The two virtqueues (event + status) are handed to the backend; the
//! frontend does not process them.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use vmm_sys_util::eventfd::EventFd;

use super::super::VhostOps;
use super::client::VhostUserClient;
use crate::VhostUser::client::{
    VhostBackendType, VHOST_USER_PROTOCOL_F_CONFIG, VHOST_USER_PROTOCOL_F_MQ,
};
use crate::VhostUser::listen_guest_notifier;
use crate::VhostUser::message::VHOST_USER_F_PROTOCOL_FEATURES;
use crate::{
    read_config_default, virtio_has_feature, VirtioBase, VirtioDevice, VirtioInterrupt,
    VIRTIO_F_VERSION_1, VIRTIO_TYPE_INPUT,
};
use address_space::AddressSpace;
use machine_manager::config::{
    get_chardev_socket_path, get_pci_df, parse_bool, valid_id, ChardevConfig,
    DEFAULT_VIRTQUEUE_SIZE,
};
use machine_manager::event_loop::unregister_event_helper;
use util::byte_code::ByteCode;
use util::gen_base_func;

/// Size in bytes of the virtio-input `payload` union (`string`/`bitmap`/
/// `abs`/`ids`), matching the virtio-input spec and `uapi/linux/virtio_input.h`.
const VIRTIO_INPUT_CFG_PAYLOAD_SIZE: usize = 128;

/// Total size of the virtio-input config space:
/// `select(1) + subsel(1) + size(1) + reserved[5] + payload[128]` = 136 bytes.
const VIRTIO_INPUT_CONFIG_SPACE_SIZE: usize = 1 + 1 + 1 + 5 + VIRTIO_INPUT_CFG_PAYLOAD_SIZE;

/// Number of virtqueues for virtio-input: the event queue (device -> guest)
/// and the status queue (guest -> device).
const QUEUE_NUM_INPUT: usize = 2;

/// The virtio-input configuration space layout.
///
/// This mirrors `struct virtio_input_config` from `uapi/linux/virtio_input.h`:
/// a `select`/`subsel` selector pair, a `size` field reporting how many
/// payload bytes are valid, 5 reserved bytes, and a 128-byte payload union.
/// It is a fixed 136-byte structure, exchanged verbatim with the backend over
/// `GET_CONFIG`/`SET_CONFIG`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VhostUserInputConfig {
    /// Which configuration item the driver is requesting.
    pub select: u8,
    /// Sub-selector (e.g. event type for `EV_BITS`, axis for `ABS_INFO`).
    pub subsel: u8,
    /// Number of valid bytes in `payload` for the current `select`/`subsel`.
    pub size: u8,
    /// Reserved, must be zero.
    pub reserved: [u8; 5],
    /// Configuration payload (name/serial/bitmap/absinfo/devids).
    pub payload: [u8; VIRTIO_INPUT_CFG_PAYLOAD_SIZE],
}

// `#[derive(Default)]` on a struct containing a 128-element array relies on
// the const-generic array `Default` impl; implement it manually for clarity
// and to stay aligned with the rust-vmm backend's `VuInputConfig`.
impl Default for VhostUserInputConfig {
    fn default() -> Self {
        VhostUserInputConfig {
            select: 0,
            subsel: 0,
            size: 0,
            reserved: [0; 5],
            payload: [0; VIRTIO_INPUT_CFG_PAYLOAD_SIZE],
        }
    }
}

// SAFETY: the layout is fixed (`#[repr(C)]`, no padding) and the struct only
// contains plain bytes, so it is safe to reinterpret as a byte slice.
impl ByteCode for VhostUserInputConfig {}

impl VhostUserInputConfig {
    /// Construct an all-zero config space.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Config structure for the vhost-user-input device, parsed from the
/// `-device` command line.
#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct VhostUserInputDevConfig {
    #[arg(long, value_parser = ["vhost-user-input-pci", "vhost-user-input-device"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser = parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    /// Chardev id of the unix-socket connected to the vhost-device-input
    /// backend. The backend's `--socket-path` creates `path0`, `path1`, ...
    /// sockets, one per evdev; each frontend instance consumes one of them.
    #[arg(long)]
    pub chardev: String,
}

/// vhost-user-input device frontend.
///
/// Pure passthrough: it negotiates the vhost-user protocol, forwards config
/// space reads/writes to the backend via `GET_CONFIG`/`SET_CONFIG`, and hands
/// both virtqueues to the backend. It never reads an evdev device nor caches
/// the volatile payload.
pub struct VhostUserInput {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the vhost-user-input's socket chardev.
    chardev_cfg: ChardevConfig,
    /// Virtio-input config space. Only `select`/`subsel` are authoritative on
    /// the frontend side (to forward guest writes); `size`/`payload` are
    /// fetched fresh from the backend on every read.
    config_space: VhostUserInputConfig,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Vhost user client.
    client: Option<Arc<Mutex<VhostUserClient>>>,
    /// Whether irqfd can be used.
    pub enable_irqfd: bool,
    /// Vhost user protocol features negotiated with the backend.
    protocol_features: u64,
}

impl VhostUserInput {
    pub fn new(
        cfg: &VhostUserInputDevConfig,
        chardev_cfg: ChardevConfig,
        mem_space: &Arc<AddressSpace>,
    ) -> Self {
        // The CLI device config is consumed only to construct the device; the
        // authoritative config space lives in the backend and is fetched on
        // demand, so no copy is retained.
        let _ = cfg;
        VhostUserInput {
            base: VirtioBase::new(VIRTIO_TYPE_INPUT, QUEUE_NUM_INPUT, DEFAULT_VIRTQUEUE_SIZE),
            chardev_cfg,
            config_space: VhostUserInputConfig::new(),
            mem_space: mem_space.clone(),
            client: None,
            enable_irqfd: false,
            protocol_features: 0_u64,
        }
    }

    /// Connect with the backend and register the reconnection event.
    fn init_client(&mut self) -> Result<()> {
        let socket_path = get_chardev_socket_path(self.chardev_cfg.clone())?;
        let client = VhostUserClient::new(
            &self.mem_space,
            &socket_path,
            self.queue_num() as u64,
            VhostBackendType::TypeInput,
        )
        .with_context(|| {
            "Failed to create the client which communicates with the server for vhost-user input"
        })?;
        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;
        self.client = Some(client);
        Ok(())
    }
}

impl VirtioDevice for VhostUserInput {
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

    fn realize(&mut self) -> Result<()> {
        self.init_client()?;
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let locked_client = self.client.as_ref().unwrap().lock().unwrap();
        let features = locked_client
            .get_features()
            .with_context(|| "Failed to get features for vhost-user input")?;

        // VHOST_USER_F_PROTOCOL_FEATURES (bit 30) must be supported: it is the
        // prerequisite for protocol-features negotiation and for SET_VRING_ENABLE
        // to take effect.
        if !virtio_has_feature(features, VHOST_USER_F_PROTOCOL_FEATURES) {
            bail!("Bad vhost-user-input feature: {:#b}", features);
        }

        let protocol_features = locked_client
            .get_protocol_features()
            .with_context(|| "Failed to get protocol features for vhost-user input")?;
        // The rust-vmm vhost-device-input backend advertises MQ | CONFIG.
        // CONFIG is mandatory: without it the frontend cannot serve the config
        // space at all. REPLY_ACK is not negotiated (the backend doesn't offer
        // it), so SET_CONFIG and SET_VRING_ENABLE are fire-and-forget.
        let supported_protocol_features =
            (1 << VHOST_USER_PROTOCOL_F_MQ) | (1 << VHOST_USER_PROTOCOL_F_CONFIG);
        self.protocol_features = supported_protocol_features & protocol_features;
        locked_client
            .set_protocol_features(self.protocol_features)
            .with_context(|| "Failed to set protocol features for vhost-user input")?;

        // CONFIG must have been negotiated, otherwise the frontend has no way
        // to obtain the config space and the device is unusable.
        if !virtio_has_feature(
            self.protocol_features,
            u32::from(VHOST_USER_PROTOCOL_F_CONFIG),
        ) {
            bail!(
                "vhost-user-input backend doesn't support CONFIG, protocol features: {:#b}",
                protocol_features
            );
        }

        if virtio_has_feature(protocol_features, u32::from(VHOST_USER_PROTOCOL_F_MQ)) {
            let max_queue_num = locked_client
                .get_max_queue_num()
                .with_context(|| "Failed to get queue num for vhost-user input")?;
            if self.queue_num() > max_queue_num as usize {
                bail!(
                    "Exceed the max queue num that vhost-user-input supported ({} queues)",
                    max_queue_num
                );
            }
        } else {
            bail!(
                "vhost-user-input backend doesn't support MQ, protocol features: {:#b}",
                protocol_features
            );
        }
        drop(locked_client);

        // virtio-input backend features = VERSION_1 | RING_F_INDIRECT_DESC |
        // RING_F_EVENT_IDX | PROTOCOL_FEATURES. The transport-level ring
        // features (INDIRECT_DESC / EVENT_IDX) are handled by the backend; the
        // frontend only needs to expose VERSION_1 (plus whatever the backend
        // offers).
        self.base.device_features = 1_u64 << VIRTIO_F_VERSION_1;
        self.base.device_features &= features;

        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        // The config payload depends on the backend's evdev state and the
        // `select`/`subsel` the driver just wrote, so fetch a fresh copy from
        // the backend on every read instead of serving a stale local cache.
        let config = self
            .client
            .as_ref()
            .with_context(|| "Failed to get client when reading config")?
            .lock()
            .unwrap()
            .get_virtio_config::<VhostUserInputConfig>()
            .with_context(|| "Failed to get config for vhost-user input")?;
        read_config_default(config.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        // Forward the guest write verbatim to the backend, preserving the exact
        // offset and length. The Linux virtio-input driver writes `select`
        // (offset 0) and `subsel` (offset 1) in separate one-byte writes, so a
        // whole-struct write at offset 0 would carry a stale `subsel` and
        // confuse the backend.
        let offset_usize = offset as usize;
        if offset_usize + data.len() > VIRTIO_INPUT_CONFIG_SPACE_SIZE {
            bail!(
                "Write config out of range, offset: {}, len: {}",
                offset,
                data.len()
            );
        }

        // Mirror the written bytes into the local cache so the frontend keeps a
        // coherent view of `select`/`subsel`. The payload portion is best
        // effort here; `read_config` always refetches it from the backend.
        let config_slice = self.config_space.as_mut_bytes();
        config_slice[offset_usize..offset_usize + data.len()].copy_from_slice(data);

        self.client
            .as_ref()
            .with_context(|| "Failed to get client when writing config")?
            .lock()
            .unwrap()
            .set_virtio_config_range(offset as u32, data)
            .with_context(|| "Failed to set config for vhost-user input")?;

        Ok(())
    }

    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for vhost-user input")),
        };
        // Add VHOST_USER_F_PROTOCOL_FEATURES bit so that the backend enters
        // protocol-features mode and honours SET_VRING_ENABLE.
        client.features = self.base.driver_features | (1 << VHOST_USER_F_PROTOCOL_FEATURES);
        client.protocol_features = self.protocol_features;
        // Both queues (event + status) are handed to the backend.
        client.set_queues(&self.base.queues);
        client.set_queue_evts(&queue_evts);

        if !self.enable_irqfd {
            let queue_num = self.base.queues.len();
            listen_guest_notifier(&mut self.base, &mut client, None, queue_num, interrupt_cb)?;
        }

        client.activate_vhost_user()?;
        self.base.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        if let Some(client) = &self.client {
            client.lock().unwrap().reset_vhost_user(false);
        }
        unregister_event_helper(None, &mut self.base.deactivate_evts)?;
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        self.client
            .as_ref()
            .with_context(|| "Failed to get client when stopping event")?
            .lock()
            .unwrap()
            .delete_event()
            .with_context(|| "Failed to delete vhost-user input event")?;
        self.client = None;
        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        self.enable_irqfd = true;
        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for vhost-user input")),
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::address_space_init;
    use machine_manager::config::str_slip_to_clap;

    /// Build a `VhostUserInput` instance without connecting to a backend.
    /// `realize` is deliberately not called, so the client is never created.
    fn create_test_input() -> VhostUserInput {
        let cfg = VhostUserInputDevConfig {
            classtype: "vhost-user-input-pci".to_string(),
            id: "test_input".to_string(),
            chardev: "test_chardev".to_string(),
            ..Default::default()
        };
        let chardev_cfg = ChardevConfig::try_parse_from(str_slip_to_clap(
            "socket,id=test_chardev,path=/tmp/input-test.sock",
            true,
            true,
        ))
        .unwrap();
        let mem_space = address_space_init();
        VhostUserInput::new(&cfg, chardev_cfg, &mem_space)
    }

    #[test]
    fn test_vhost_user_input_cmdline_parser() {
        let cmd = "vhost-user-input-pci,id=input0,chardev=chardev0,bus=pcie.0,addr=0x1";
        let cfg = VhostUserInputDevConfig::try_parse_from(str_slip_to_clap(cmd, true, false))
            .expect("Failed to parse valid vhost-user-input cmdline");
        assert_eq!(cfg.classtype, "vhost-user-input-pci");
        assert_eq!(cfg.id, "input0");
        assert_eq!(cfg.chardev, "chardev0");
        assert_eq!(cfg.bus.unwrap(), "pcie.0");
        assert_eq!(cfg.addr.unwrap(), (1, 0));

        // The mmio variant is also accepted.
        let mmio_cmd = "vhost-user-input-device,id=input1,chardev=chardev1";
        let cfg = VhostUserInputDevConfig::try_parse_from(str_slip_to_clap(mmio_cmd, true, false))
            .unwrap();
        assert_eq!(cfg.classtype, "vhost-user-input-device");
        assert_eq!(cfg.chardev, "chardev1");

        // Missing chardev is rejected.
        let bad_cmd = "vhost-user-input-pci,id=input0";
        assert!(
            VhostUserInputDevConfig::try_parse_from(str_slip_to_clap(bad_cmd, true, false))
                .is_err()
        );
    }

    #[test]
    fn test_vhost_user_input_config_space_layout() {
        use std::mem::size_of;
        // select + subsel + size + reserved[5] + payload[128] = 136 bytes.
        assert_eq!(
            size_of::<VhostUserInputConfig>(),
            VIRTIO_INPUT_CONFIG_SPACE_SIZE
        );
        assert_eq!(VIRTIO_INPUT_CONFIG_SPACE_SIZE, 136);
    }

    #[test]
    fn test_vhost_user_input_device_meta() {
        let input = create_test_input();
        assert_eq!(input.device_type(), VIRTIO_TYPE_INPUT);
        assert_eq!(input.queue_num(), QUEUE_NUM_INPUT);
        assert_eq!(input.queue_size_max(), DEFAULT_VIRTQUEUE_SIZE);
        assert!(input.client.is_none());
        assert!(!input.enable_irqfd);
    }

    #[test]
    fn test_vhost_user_input_config_space_default() {
        let cfg = VhostUserInputConfig::new();
        assert_eq!(cfg.select, 0);
        assert_eq!(cfg.subsel, 0);
        assert_eq!(cfg.size, 0);
        assert_eq!(cfg.reserved, [0_u8; 5]);
        assert_eq!(cfg.payload, [0_u8; VIRTIO_INPUT_CFG_PAYLOAD_SIZE]);
    }

    #[test]
    fn test_vhost_user_input_write_config_mirrors_local() {
        let mut input = create_test_input();

        // `write_config` updates the local cache first, then forwards to the
        // backend. With no client connected (realize not called) the forward
        // fails, but the local mirror of `select`/`subsel` must still be updated
        // so the frontend keeps a coherent view of the guest's selection.

        // Guest writes `select` at offset 0 (one byte), like the Linux driver.
        assert!(input.write_config(0, &[0x01]).is_err());
        assert_eq!(input.config_space.select, 0x01);

        // Guest writes `subsel` at offset 1 (one byte), separately.
        assert!(input.write_config(1, &[0x11]).is_err());
        assert_eq!(input.config_space.subsel, 0x11);

        // A two-byte write at offset 0 updates both fields.
        assert!(input.write_config(0, &[0x02, 0x12]).is_err());
        assert_eq!(input.config_space.select, 0x02);
        assert_eq!(input.config_space.subsel, 0x12);
    }

    #[test]
    fn test_vhost_user_input_write_config_out_of_range_rejected() {
        let mut input = create_test_input();
        // Writing past the end of the 136-byte config space must fail.
        let buf = [0_u8; 4];
        assert!(input.write_config(133, &buf).is_err());
        assert!(input
            .write_config(VIRTIO_INPUT_CONFIG_SPACE_SIZE as u64, &[0])
            .is_err());
    }
}
