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
        // Negotiate MQ | CONFIG as required by the vhost-user-vsock contract.
        // The rust-vmm vhost-device-vsock backend advertises exactly MQ | CONFIG
        // (it does not offer REPLY_ACK), so those are the only bits that survive
        // the intersection below. REPLY_ACK is intentionally not requested: this
        // frontend never sets VHOST_USER_NEED_REPLY on its requests
        // (SET_VRING_ENABLE, GET_CONFIG, ...), so the feature would be negotiated
        // but unused. Fire-and-forget semantics are acceptable here because a
        // failed SET_VRING_ENABLE already surfaces as a broken device at runtime.
        let supported_protocol_features =
            (1 << VHOST_USER_PROTOCOL_F_MQ) | (1 << VHOST_USER_PROTOCOL_F_CONFIG);
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

    /// Base CID used for registry tests. Kept in a clearly test-only range so it
    /// can never collide with a real guest CID produced by `create_test_vsock`
    /// (which never claims anything) or with another parallel test case.
    const TEST_CID_BASE: u64 = 90_000;

    /// Build a `VhostUserVsock` instance without connecting to a backend.
    ///
    /// `realize` is deliberately not called, so no CID is claimed and the
    /// process-wide registry is left untouched — this keeps construction tests
    /// isolated from the CID-registry tests below.
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
        .expect("test chardev config must parse");
        let mem_space = address_space_init();
        VhostUserVsock::new(&cfg, chardev_cfg, &mem_space)
    }

    /// Parse a vhost-user-vsock command line into its config struct.
    fn parse_vsock_config(
        cmd: &str,
    ) -> std::result::Result<VhostUserVsockDevConfig, clap::Error> {
        VhostUserVsockDevConfig::try_parse_from(str_slip_to_clap(cmd, true, false))
    }

    /// RAII guard that automatically releases a claimed CID on drop, so a
    /// failing or panicking test cannot leak entries into the process-wide
    /// registry and corrupt the isolation of later tests.
    struct ClaimedCid(u64);

    impl ClaimedCid {
        /// Claim `cid`, panicking if it is already held by another test.
        fn new(cid: u64) -> Self {
            assert!(claim_cid(cid), "precondition: CID {} must be free", cid);
            ClaimedCid(cid)
        }

        /// Try to claim `cid`; returns `None` (without asserting) if already held.
        fn try_new(cid: u64) -> Option<Self> {
            if claim_cid(cid) {
                Some(ClaimedCid(cid))
            } else {
                None
            }
        }
    }

    impl Drop for ClaimedCid {
        fn drop(&mut self) {
            release_cid(self.0);
        }
    }

    // ---------------------------------------------------------------------
    // Command-line parsing
    // ---------------------------------------------------------------------

    #[test]
    fn test_config_parse_valid_variants() {
        // PCI variant with every field populated.
        let cfg = parse_vsock_config("vhost-user-vsock-pci,id=vsock0,guest-cid=3,chardev=ch0")
            .expect("valid PCI config should parse");
        assert_eq!(cfg.classtype, "vhost-user-vsock-pci");
        assert_eq!(cfg.id, "vsock0");
        assert_eq!(cfg.guest_cid, 3);
        assert_eq!(cfg.chardev, "ch0");

        // MMIO (`-device`) variant is equally accepted.
        let cfg = parse_vsock_config("vhost-user-vsock-device,id=vsock1,guest-cid=10,chardev=ch1")
            .expect("valid MMIO config should parse");
        assert_eq!(cfg.classtype, "vhost-user-vsock-device");
        assert_eq!(cfg.guest_cid, 10);
    }

    #[test]
    fn test_config_parse_guest_cid_boundaries() {
        // The parser accepts the inclusive range [MIN_GUEST_CID=3,
        // MAX_GUEST_CID=4294967295]; CIDs 0/1/2 are reserved and must be
        // rejected, as is anything above the maximum.
        let valid = [
            ("min", MIN_GUEST_CID),
            ("max", MAX_GUEST_CID),
            ("typical", 42_u64),
        ];
        for (label, cid) in valid {
            let cmd = format!("vhost-user-vsock-pci,id=v,guest-cid={},chardev=c", cid);
            assert!(
                parse_vsock_config(&cmd).is_ok(),
                "guest-cid={} ({}) should be accepted",
                cid, label
            );
        }

        let invalid = [
            ("reserved-2", 2_u64),
            ("reserved-1", 1_u64),
            ("reserved-0", 0_u64),
            ("above-max", MAX_GUEST_CID + 1),
        ];
        for (label, cid) in invalid {
            let cmd = format!("vhost-user-vsock-pci,id=v,guest-cid={},chardev=c", cid);
            assert!(
                parse_vsock_config(&cmd).is_err(),
                "guest-cid={} ({}) should be rejected",
                cid, label
            );
        }
    }

    #[test]
    fn test_config_parse_missing_required_fields() {
        // `id`, `guest-cid` and `chardev` are all mandatory.
        assert!(parse_vsock_config("vhost-user-vsock-pci,guest-cid=3,chardev=ch0").is_err());
        assert!(parse_vsock_config("vhost-user-vsock-pci,id=v,chardev=ch0").is_err());
        assert!(parse_vsock_config("vhost-user-vsock-pci,id=v,guest-cid=3").is_err());
    }

    #[test]
    fn test_config_parse_invalid_classtype() {
        // Only the `pci` and `device` classtypes are accepted.
        assert!(
            parse_vsock_config("vhost-user-vsock-foobar,id=v,guest-cid=3,chardev=c").is_err()
        );
    }

    // ---------------------------------------------------------------------
    // Device construction
    // ---------------------------------------------------------------------

    #[test]
    fn test_construction_seeds_config_space() {
        let vsock = create_test_vsock(42);
        // The CLI CID must seed the config space as a little-endian u64 and be
        // readable through the public accessor.
        assert_eq!(vsock.guest_cid(), 42);
        assert_eq!(LittleEndian::read_u64(&vsock.config_space), 42);

        // A freshly created device has not yet connected or claimed a CID.
        assert!(!vsock.cid_claimed);
        assert!(vsock.client.is_none());
    }

    #[test]
    fn test_construction_splits_high_cid() {
        // A CID above 2^32 must be split correctly into the low/high 32-bit
        // halves of the 64-bit config space (little-endian).
        let cid: u64 = 0x0000_0001_0000_0005;
        let vsock = create_test_vsock(cid);

        let mut low = [0_u8; 4];
        vsock.read_config(0, &mut low).unwrap();
        assert_eq!(LittleEndian::read_u32(&low), 0x0000_0005);

        let mut high = [0_u8; 4];
        vsock.read_config(4, &mut high).unwrap();
        assert_eq!(LittleEndian::read_u32(&high), 0x0000_0001);
    }

    #[test]
    fn test_construction_device_meta() {
        let vsock = create_test_vsock(3);
        assert_eq!(vsock.device_type(), VIRTIO_TYPE_VSOCK);
        assert_eq!(vsock.queue_num(), QUEUE_NUM_VSOCK);
        assert_eq!(vsock.queue_size_max(), DEFAULT_VIRTQUEUE_SIZE);
    }

    // ---------------------------------------------------------------------
    // Config-space read (`read_config`)
    // ---------------------------------------------------------------------

    #[test]
    fn test_read_config_within_bounds() {
        // Seed a recognizable little-endian pattern across all 8 bytes.
        let pattern: u64 = 0x0102_0304_0506_0708;
        let vsock = create_test_vsock(pattern);

        // (offset, len, expected value read back from those bytes, LE-decoded)
        let cases: &[(u64, usize, u64)] = &[
            (0, 8, 0x0102_0304_0506_0708), // full config space
            (0, 4, 0x0506_0708),           // low 32 bits
            (4, 4, 0x0102_0304),           // high 32 bits
            (0, 2, 0x0708),                // low 16 bits
            (6, 2, 0x0102),                // high 16 bits
            (0, 1, 0x08),                  // lowest byte
            (7, 1, 0x01),                  // highest byte
        ];
        for (offset, len, expected) in cases {
            let mut buf = vec![0_u8; *len];
            vsock.read_config(*offset, &mut buf).unwrap_or_else(|_| {
                panic!("read at offset={} len={} should succeed", offset, len)
            });
            let value = match *len {
                1 => u64::from(buf[0]),
                2 => u64::from(LittleEndian::read_u16(&buf)),
                4 => u64::from(LittleEndian::read_u32(&buf)),
                8 => LittleEndian::read_u64(&buf),
                _ => unreachable!("test case uses only len 1/2/4/8"),
            };
            assert_eq!(value, *expected, "offset={} len={}", offset, len);
        }
    }

    #[test]
    fn test_read_config_out_of_bounds() {
        let vsock = create_test_vsock(42);
        // Any read whose [offset, offset+len) window exceeds the 8-byte config
        // space (or whose arithmetic overflows) must be rejected.
        let oob: &[(u64, usize)] = &[
            (5, 4),        // 5 + 4 = 9 > 8
            (8, 4),        // 8 + 4 = 12 > 8
            (1, 8),        // 1 + 8 = 9 > 8
            (7, 2),        // 7 + 2 = 9 > 8
            (u64::MAX, 1), // offset arithmetic overflows
        ];
        for (offset, len) in oob {
            let mut buf = vec![0_u8; *len];
            assert!(
                vsock.read_config(*offset, &mut buf).is_err(),
                "read at offset={} len={} must be rejected",
                offset, len
            );
        }
    }

    #[test]
    fn test_read_config_empty_is_allowed() {
        let vsock = create_test_vsock(42);
        // A zero-length read never touches the buffer and is always within
        // bounds, even at the very end of the config space.
        for offset in [0_u64, 8] {
            let mut buf: [u8; 0] = [];
            assert!(
                vsock.read_config(offset, &mut buf).is_ok(),
                "empty read at offset={} must succeed",
                offset
            );
        }
    }

    // ---------------------------------------------------------------------
    // CID registry (claim / release / uniqueness)
    // ---------------------------------------------------------------------

    #[test]
    fn test_cid_claim_uniqueness() {
        let cid = TEST_CID_BASE + 1;
        release_cid(cid); // clean slate

        let _guard = ClaimedCid::new(cid);
        // While held, a duplicate claim must be rejected.
        assert!(
            ClaimedCid::try_new(cid).is_none(),
            "duplicate claim of CID {} must be rejected",
            cid
        );
    }

    #[test]
    fn test_cid_release_then_reclaim() {
        let cid = TEST_CID_BASE + 2;
        release_cid(cid);

        let guard = ClaimedCid::new(cid);
        drop(guard); // explicitly release

        // The CID is free again and can be re-claimed.
        let _guard = ClaimedCid::new(cid);
    }

    #[test]
    fn test_cid_claim_multiple_distinct() {
        let cids = [TEST_CID_BASE + 3, TEST_CID_BASE + 4, TEST_CID_BASE + 5];
        for &c in &cids {
            release_cid(c);
        }

        // Each distinct CID is held by its own owned guard so that `drop` can
        // release them independently (a `Vec` index only yields a `&ClaimedCid`,
        // whose `drop` would be a no-op).
        let g0 = ClaimedCid::new(cids[0]);
        let g1 = ClaimedCid::new(cids[1]);
        let g2 = ClaimedCid::new(cids[2]);

        // None of the held CIDs can be re-claimed.
        for &c in &cids {
            assert!(
                ClaimedCid::try_new(c).is_none(),
                "CID {} must still be held",
                c
            );
        }

        // Releasing one CID frees only that CID, leaving the others intact.
        drop(g0);
        assert!(
            ClaimedCid::try_new(cids[0]).is_some(),
            "CID {} should be free after release",
            cids[0]
        );
        assert!(
            ClaimedCid::try_new(cids[1]).is_none(),
            "CID {} must remain held",
            cids[1]
        );
        // g1 and g2 drop at end of scope, releasing cids[1] and cids[2].
    }

    #[test]
    fn test_cid_release_is_idempotent() {
        // `release_cid` is documented safe to call even when the CID was never
        // claimed, and must not break a subsequent claim.
        let cid = TEST_CID_BASE + 99;
        release_cid(cid);
        release_cid(cid);
        let _guard = ClaimedCid::new(cid);
    }

    #[test]
    fn test_cid_claim_boundary_values() {
        // The registry keys on raw u64 CIDs; the valid range is enforced
        // upstream by the config parser, not here. Verify the extreme *valid*
        // guest CIDs (min and max) can still be claimed and released.
        for &cid in &[MIN_GUEST_CID, MAX_GUEST_CID] {
            release_cid(cid);
            let _guard = ClaimedCid::new(cid);
        }
    }
}
