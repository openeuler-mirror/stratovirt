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

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use clap::{ArgAction, Parser};
use log::warn;
use vmm_sys_util::eventfd::EventFd;

use super::super::VhostOps;
use super::client::VhostUserClient;
use crate::VhostUser::client::{
    VhostBackendType, VHOST_USER_PROTOCOL_F_CONFIG, VHOST_USER_PROTOCOL_F_MQ,
    VHOST_USER_PROTOCOL_F_REPLY_ACK,
};
use crate::VhostUser::listen_guest_notifier;
use crate::VhostUser::message::VHOST_USER_F_PROTOCOL_FEATURES;
use crate::{
    read_config_default, virtio_has_feature, VirtioBase, VirtioDevice, VirtioInterrupt,
    VIRTIO_F_VERSION_1, VIRTIO_TYPE_VSOCK,
};
use address_space::AddressSpace;
use machine_manager::config::{
    get_chardev_socket_path, get_pci_df, parse_bool, valid_id, ChardevConfig,
    DEFAULT_VIRTQUEUE_SIZE,
};
use machine_manager::event_loop::unregister_event_helper;
use util::gen_base_func;

/// Number of virtqueues for virtio-vsock: rx, tx and event queue.
const QUEUE_NUM_VSOCK: usize = 3;
/// The config space is a single little-endian u64 guest CID.
const VSOCK_CONFIG_SPACE_SIZE: usize = 8;
/// Minimum guest CID. CIDs 0/1/2 are reserved (invalid, loopback, host).
const MIN_GUEST_CID: u64 = 3;
/// Maximum guest CID (u32 range as of virtio-vsock 1.0).
const MAX_GUEST_CID: u64 = 4_294_967_295;

/// Config structure for vhost-user-vsock device.
#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct VhostUserVsockDevConfig {
    #[arg(long, value_parser = ["vhost-user-vsock-pci", "vhost-user-vsock-device"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser = parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    #[arg(long, alias = "guest-cid", value_parser = clap::value_parser!(u64).range(MIN_GUEST_CID..=MAX_GUEST_CID))]
    pub guest_cid: u64,
    #[arg(long)]
    pub chardev: String,
}

/// Vhost-user-vsock device structure.
///
/// This frontend is a pure passthrough: it only negotiates the vhost-user
/// protocol, hands all three queues (rx/tx/event) to the backend and exposes
/// the guest CID through the virtio config space. It never touches vsock
/// packets.
pub struct VhostUserVsock {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the vhost-user-vsock device.
    vsock_cfg: VhostUserVsockDevConfig,
    /// Configuration of the vhost-user-vsock's socket chardev.
    chardev_cfg: ChardevConfig,
    /// Virtio-vsock config space: a single little-endian u64 guest CID.
    config_space: [u8; VSOCK_CONFIG_SPACE_SIZE],
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Vhost user client.
    client: Option<Arc<Mutex<VhostUserClient>>>,
    /// Whether irqfd can be used.
    pub enable_irqfd: bool,
    /// Vhost user protocol features negotiated with the backend.
    protocol_features: u64,
    /// Whether this instance currently holds the guest CID in the process-wide
    /// registry. Tracks the claim so that `deactivate`/`Drop` only releases
    /// once and never clobbers another device's claim.
    cid_claimed: bool,
}

impl VhostUserVsock {
    pub fn new(
        cfg: &VhostUserVsockDevConfig,
        chardev_cfg: ChardevConfig,
        mem_space: &Arc<AddressSpace>,
    ) -> Self {
        // Seed the config space from the CLI provided guest CID. The backend
        // authoritative CID (fetched later via GET_CONFIG) may override this.
        let mut config_space = [0_u8; VSOCK_CONFIG_SPACE_SIZE];
        LittleEndian::write_u64(&mut config_space, cfg.guest_cid);

        VhostUserVsock {
            base: VirtioBase::new(VIRTIO_TYPE_VSOCK, QUEUE_NUM_VSOCK, DEFAULT_VIRTQUEUE_SIZE),
            vsock_cfg: cfg.clone(),
            chardev_cfg,
            config_space,
            mem_space: mem_space.clone(),
            client: None,
            enable_irqfd: false,
            protocol_features: 0_u64,
            cid_claimed: false,
        }
    }

    /// Get the guest CID currently exposed in the config space.
    pub fn guest_cid(&self) -> u64 {
        LittleEndian::read_u64(&self.config_space)
    }

    /// Connect with the backend and register the reconnection event.
    fn init_client(&mut self) -> Result<()> {
        let socket_path = get_chardev_socket_path(self.chardev_cfg.clone())?;
        let client = VhostUserClient::new(
            &self.mem_space,
            &socket_path,
            self.queue_num() as u64,
            VhostBackendType::TypeVsock,
        )
        .with_context(|| {
            "Failed to create the client which communicates with the server for vhost-user vsock"
        })?;
        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;
        self.client = Some(client);
        Ok(())
    }
}

/// Process-wide registry of claimed guest CIDs.
///
/// vhost-user-vsock uses connection-oriented CIDs that must be unique per host
/// process: two active vsock devices sharing a CID would ambiguously route
/// packets. The registry is a simple set guarded by a mutex, lazily initialised
/// through an `OnceLock`.
static CLAIMED_CIDS: OnceLock<Mutex<BTreeMap<u64, ()>>> = OnceLock::new();

fn cid_registry() -> &'static Mutex<BTreeMap<u64, ()>> {
    CLAIMED_CIDS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Try to claim `cid` for the calling device. Returns `false` if the CID is
/// already held by another active device.
fn claim_cid(cid: u64) -> bool {
    let mut registry = cid_registry().lock().unwrap();
    if registry.contains_key(&cid) {
        return false;
    }
    registry.insert(cid, ());
    true
}

/// Release a previously claimed `cid`. Safe to call even if the CID was not
/// claimed (the owner is tracked per-device via `cid_claimed`).
fn release_cid(cid: u64) {
    if let Some(registry) = CLAIMED_CIDS.get() {
        registry.lock().unwrap().remove(&cid);
    }
}

impl VirtioDevice for VhostUserVsock {
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

    fn realize(&mut self) -> Result<()> {
        self.init_client()?;
        self.init_config_features()?;
        // Claim the guest CID at the very end of realize, once the authoritative
        // CID (from GET_CONFIG or the CLI fallback) is settled in the config
        // space. This guarantees process-wide CID uniqueness across all active
        // vhost-user-vsock devices.
        let cid = self.guest_cid();
        if !claim_cid(cid) {
            bail!(
                "Guest CID {} is already in use by another vhost-user-vsock device",
                cid
            );
        }
        self.cid_claimed = true;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let locked_client = self.client.as_ref().unwrap().lock().unwrap();
        let features = locked_client
            .get_features()
            .with_context(|| "Failed to get features for vhost-user vsock")?;

        // VHOST_USER_F_PROTOCOL_FEATURES (bit 30) must be supported: it is the
        // prerequisite for the protocol-features negotiation and for
        // SET_VRING_ENABLE to take effect.
        if !virtio_has_feature(features, VHOST_USER_F_PROTOCOL_FEATURES) {
            bail!("Bad vhost-user-vsock feature: {:#b}", features);
        }

        let protocol_features = locked_client
            .get_protocol_features()
            .with_context(|| "Failed to get protocol features for vhost-user vsock")?;
        // Negotiate MQ | CONFIG | REPLY_ACK as required by the vhost-user-vsock
        // contract. REPLY_ACK lets the frontend detect backend errors on
        // SET_VRING_ENABLE and other commands that would otherwise be fire-and-forget.
        let supported_protocol_features = (1 << VHOST_USER_PROTOCOL_F_MQ)
            | (1 << VHOST_USER_PROTOCOL_F_CONFIG)
            | (1 << VHOST_USER_PROTOCOL_F_REPLY_ACK);
        self.protocol_features = supported_protocol_features & protocol_features;
        locked_client
            .set_protocol_features(self.protocol_features)
            .with_context(|| "Failed to set protocol features for vhost-user vsock")?;

        // Once CONFIG has been negotiated the backend CID is authoritative:
        // fetch it through GET_CONFIG and adopt it into the config space.
        // vhost-user-vsock has no SET_GUEST_CID message, so the CID only ever
        // travels through the config space. A mismatch with the CLI-provided
        // CID is just warned about, not fatal.
        if virtio_has_feature(
            self.protocol_features,
            u32::from(VHOST_USER_PROTOCOL_F_CONFIG),
        ) {
            let backend_cid = locked_client
                .get_virtio_config::<u64>()
                .with_context(|| "Failed to get config for vhost-user vsock")?;
            if backend_cid != self.vsock_cfg.guest_cid {
                warn!(
                    "Backend guest CID {} differs from CLI guest CID {}, adopting backend CID",
                    backend_cid, self.vsock_cfg.guest_cid
                );
            }
            LittleEndian::write_u64(&mut self.config_space, backend_cid);
        }

        if virtio_has_feature(protocol_features, u32::from(VHOST_USER_PROTOCOL_F_MQ)) {
            let max_queue_num = locked_client
                .get_max_queue_num()
                .with_context(|| "Failed to get queue num for vhost-user vsock")?;
            if self.queue_num() > max_queue_num as usize {
                bail!(
                    "Exceed the max queue num that vhost-user-vsock supported ({} queues)",
                    max_queue_num
                );
            }
        } else {
            bail!(
                "vhost-user-vsock backend doesn't support MQ, protocol features: {:#b}",
                protocol_features
            );
        }
        drop(locked_client);

        self.base.device_features = 1_u64 << VIRTIO_F_VERSION_1;
        self.base.device_features &= features;

        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        read_config_default(&self.config_space[..], offset, data)
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        // The virtio-vsock config space (guest CID) is read-only for the driver.
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
            None => return Err(anyhow!("Failed to get client for vhost-user vsock")),
        };
        // Add VHOST_USER_F_PROTOCOL_FEATURES bit so that the backend enters
        // protocol-features mode and honours SET_VRING_ENABLE.
        client.features = self.base.driver_features | (1 << VHOST_USER_F_PROTOCOL_FEATURES);
        client.protocol_features = self.protocol_features;
        // Pure passthrough: all three queues (rx/tx/event) are handed to the
        // backend. The event queue is NOT handled by the frontend.
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
        if self.cid_claimed {
            release_cid(self.guest_cid());
            self.cid_claimed = false;
        }
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        self.client
            .as_ref()
            .with_context(|| "Failed to get client when stopping event")?
            .lock()
            .unwrap()
            .delete_event()
            .with_context(|| "Failed to delete vhost-user vsock event")?;
        self.client = None;
        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        self.enable_irqfd = true;
        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for vhost-user vsock")),
        };

        Ok(())
    }
}

impl Drop for VhostUserVsock {
    fn drop(&mut self) {
        // Release the CID if this instance still holds the claim (e.g. when the
        // device is destroyed without an explicit deactivate).
        if self.cid_claimed {
            release_cid(self.guest_cid());
            self.cid_claimed = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::address_space_init;
    use machine_manager::config::str_slip_to_clap;

    /// Build a `VhostUserVsock` instance without connecting to a backend.
    /// `realize` is deliberately not called, so no CID is claimed and the
    /// global registry is untouched.
    fn create_test_vsock(guest_cid: u64) -> VhostUserVsock {
        let cfg = VhostUserVsockDevConfig {
            classtype: "vhost-user-vsock-pci".to_string(),
            id: "test_vsock".to_string(),
            guest_cid,
            chardev: "test_chardev".to_string(),
            ..Default::default()
        };
        let chardev_cfg = ChardevConfig::try_parse_from(str_slip_to_clap(
            "socket,id=test_chardev,path=/tmp/vsock-test.sock",
            true,
            true,
        ))
        .unwrap();
        let mem_space = address_space_init();
        VhostUserVsock::new(&cfg, chardev_cfg, &mem_space)
    }

    #[test]
    fn test_vhost_user_vsock_cmdline_parser() {
        let cmd = "vhost-user-vsock-pci,id=test_vsock,guest-cid=3,chardev=chardev0";
        let cfg = VhostUserVsockDevConfig::try_parse_from(str_slip_to_clap(cmd, true, false))
            .expect("Failed to parse valid vhost-user-vsock cmdline");
        assert_eq!(cfg.classtype, "vhost-user-vsock-pci");
        assert_eq!(cfg.id, "test_vsock");
        assert_eq!(cfg.guest_cid, 3);
        assert_eq!(cfg.chardev, "chardev0");

        // CIDs below the minimum (3) are rejected.
        let bad_cmd = "vhost-user-vsock-pci,id=test_vsock,guest-cid=2,chardev=chardev0";
        assert!(
            VhostUserVsockDevConfig::try_parse_from(str_slip_to_clap(bad_cmd, true, false))
                .is_err()
        );

        // The mmio variant is also accepted.
        let mmio_cmd = "vhost-user-vsock-device,id=test_vsock2,guest-cid=10,chardev=chardev1";
        let cfg = VhostUserVsockDevConfig::try_parse_from(str_slip_to_clap(mmio_cmd, true, false))
            .unwrap();
        assert_eq!(cfg.classtype, "vhost-user-vsock-device");
        assert_eq!(cfg.guest_cid, 10);
    }

    #[test]
    fn test_vhost_user_vsock_new_seeds_config_space() {
        let vsock = create_test_vsock(42);
        // The CLI CID must seed the config space as a little-endian u64.
        assert_eq!(vsock.guest_cid(), 42);
        assert_eq!(LittleEndian::read_u64(&vsock.config_space), 42);

        // A freshly created device has not claimed anything yet.
        assert!(!vsock.cid_claimed);
        assert!(vsock.client.is_none());
    }

    #[test]
    fn test_vhost_user_vsock_read_config_le() {
        let vsock = create_test_vsock(0x0102_0304_0506_0708);

        // Full 8-byte read returns the CID in little-endian.
        let mut buf8 = [0_u8; 8];
        vsock.read_config(0, &mut buf8).unwrap();
        assert_eq!(LittleEndian::read_u64(&buf8), 0x0102_0304_0506_0708);

        // Low 4-byte read.
        let mut buf4 = [0_u8; 4];
        vsock.read_config(0, &mut buf4).unwrap();
        assert_eq!(LittleEndian::read_u32(&buf4), 0x0506_0708);

        // High 4-byte read.
        let mut buf4 = [0_u8; 4];
        vsock.read_config(4, &mut buf4).unwrap();
        assert_eq!(LittleEndian::read_u32(&buf4), 0x0102_0304);

        // Out-of-bounds reads must fail.
        let mut buf4 = [0_u8; 4];
        assert!(vsock.read_config(5, &mut buf4).is_err());
        assert!(vsock.read_config(8, &mut buf4).is_err());
    }

    #[test]
    fn test_vhost_user_vsock_device_meta() {
        let vsock = create_test_vsock(3);
        assert_eq!(vsock.device_type(), VIRTIO_TYPE_VSOCK);
        assert_eq!(vsock.queue_num(), QUEUE_NUM_VSOCK);
        assert_eq!(vsock.queue_size_max(), DEFAULT_VIRTQUEUE_SIZE);
    }

    #[test]
    fn test_cid_claim_release_uniqueness() {
        // Use a dedicated CID unlikely to collide with other parallel tests.
        let cid = 7001;
        release_cid(cid);

        // First claim succeeds, second (duplicate) fails.
        assert!(claim_cid(cid));
        assert!(!claim_cid(cid));

        // After release the CID can be claimed again.
        release_cid(cid);
        assert!(claim_cid(cid));

        // Cleanup for test isolation.
        release_cid(cid);
    }

    #[test]
    fn test_cid_claim_multiple_distinct() {
        let cids = [7002_u64, 7003, 7004];
        for cid in &cids {
            release_cid(*cid);
        }

        // Each distinct CID can be claimed independently.
        for cid in &cids {
            assert!(claim_cid(*cid), "failed to claim distinct CID {}", cid);
        }

        // None of them can be re-claimed while held.
        for cid in &cids {
            assert!(!claim_cid(*cid), "CID {} should not be re-claimable", cid);
        }

        // Releasing one does not affect the others.
        release_cid(cids[0]);
        assert!(claim_cid(cids[0]));
        assert!(!claim_cid(cids[1]));

        // Cleanup.
        for cid in &cids {
            release_cid(*cid);
        }
    }
}
