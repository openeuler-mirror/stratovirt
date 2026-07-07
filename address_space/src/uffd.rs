// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
//
// UFFD (userfaultfd) memory backend for StratoVirt snapshot restore.
//
// Protocol:
//   1. Create a userfaultfd fd via SYS_userfaultfd.
//   2. Enable it with UFFDIO_API.
//   3. For every guest RAM region, call UFFDIO_REGISTER (MISSING mode).
//   4. Connect to the external uffd daemon Unix socket at `socket_path`.
//   5. Send one message via sendmsg:
//      - iov[0]: JSON-encoded Vec<RegionMapping>  (region addresses + sizes)
//      - cmsg:   SCM_RIGHTS carrying the uffd fd
//   6. Block-read one ACK byte from the socket.  The daemon sends this byte
//      once its Serve() goroutine is running and ready to handle page faults.
//      This ensures vCPUs do not start executing before the daemon is ready.
//   7. The external uffd daemon takes ownership of the uffd and serves page faults
//      from the snapshot block device.

use std::io::Read;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use machine_manager::qmp::qmp_schema::MemDirtyBitmap;
use util::bitmap::set_dense_bitmap_bit;
use util::unix::{host_page_size, PagemapBatchReader};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

// ────────────────────────────────────────────────────────────────────────────
// Linux userfaultfd constants (not yet exposed by libc 0.2 / nix 0.26)
// ────────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
const SYS_USERFAULTFD_NR: libc::c_long = 282;
#[cfg(target_arch = "x86_64")]
const SYS_USERFAULTFD_NR: libc::c_long = 323;

const UFFD_API: u64 = 0xAA;
const UFFDIO_API: u64 = 0xc018aa3f;
const UFFDIO_REGISTER: u64 = 0xc020aa00;
const UFFDIO_WRITEPROTECT: u64 = 0xc018aa06;

const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
const UFFDIO_REGISTER_MODE_WP: u64 = 1 << 1;
const UFFDIO_WRITEPROTECT_MODE_WP: u64 = 1 << 0;

// UFFD_FEATURE_EVENT_REMOVE: generate REMOVE events on madvise(MADV_DONTNEED)
// so the external uffd daemon can track dirty pages during snapshot creation.
const UFFD_FEATURE_EVENT_REMOVE: u64 = 1 << 6;
// UFFD_FEATURE_WP_ASYNC: write-protect faults are cleared by the kernel
// automatically (no UFFD event), which is required for UFFDIO_COPY_MODE_WP.
const UFFD_FEATURE_WP_ASYNC: u64 = 1 << 15;

#[repr(C)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioRegister {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioWriteProtect {
    range: UffdioRange,
    mode: u64,
}

static UFFD_BACKEND: OnceLock<Mutex<Option<UffdMemoryBackend>>> = OnceLock::new();

fn backend_state() -> &'static Mutex<Option<UffdMemoryBackend>> {
    UFFD_BACKEND.get_or_init(|| Mutex::new(None))
}

// ────────────────────────────────────────────────────────────────────────────
// Wire format sent to the external uffd daemon
// ────────────────────────────────────────────────────────────────────────────

/// One guest RAM region as serialised and sent to the external uffd daemon's UFFD handler.
#[derive(Debug, PartialEq, serde::Serialize)]
struct RegionMapping {
    base_hva: u64,
    size: u64,
    /// Byte offset of this region's data within the flat snapshot file.
    offset: u64,
    /// Kept as `page_size_kib` for wire-compatibility with Firecracker.
    /// The value is in *bytes*, matching the deprecated Firecracker field.
    page_size_kib: u64,
}

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/// UFFD memory backend: registers guest RAM with a userfaultfd and hands the
/// fd to the external uffd daemon so it can serve page faults from a snapshot source.
pub struct UffdMemoryBackend {
    socket_path: PathBuf,
    /// Collected RAM regions (host addr, size, cumulative offset).
    regions: Vec<(u64, u64, u64)>,
    uffd_fd: RawFd,
}

impl UffdMemoryBackend {
    /// Create a new backend that will connect to `socket_path` when
    /// [`Self::send_to_external_uffd_daemon`] is called.
    pub fn new(socket_path: &str) -> Result<Self> {
        let uffd_fd = create_uffd().context("failed to create userfaultfd")?;
        Ok(UffdMemoryBackend {
            socket_path: PathBuf::from(socket_path),
            regions: Vec::new(),
            uffd_fd,
        })
    }

    /// Register a guest RAM region with the userfaultfd (MISSING fault mode).
    ///
    /// * `host_addr` – host virtual address of the region start.
    /// * `size`      – size in bytes.
    /// * `offset`    – byte offset of this region in the flat snapshot file.
    ///
    /// Before registering, the region is cleared with MADV_DONTNEED.
    /// UFFDIO_REGISTER does not evict pages that are already present: any
    /// page populated before registration (mem-prealloc touching every page,
    /// guest RAM accesses during the device-state restore that runs earlier,
    /// or even a stray read mapping the kernel zero page) would never raise
    /// a MISSING fault, and the restored VM would silently see zero/stale
    /// content instead of snapshot content.  The clear step restores the
    /// invariant that every access faults as MISSING and is served by the
    /// UFFD handler.  On an untouched anonymous mapping the madvise is
    /// essentially free, so it is kept unconditionally as a safety net.
    pub fn register_region(&mut self, host_addr: u64, size: u64, offset: u64) -> Result<()> {
        // SAFETY: host_addr points to a valid anonymous mapping of exactly `size` bytes
        // belonging to this guest RAM region; the region remains alive for the duration
        // of this call.
        let ret = unsafe {
            libc::madvise(
                host_addr as *mut libc::c_void,
                size as libc::size_t,
                libc::MADV_DONTNEED,
            )
        };
        if ret != 0 {
            bail!(
                "madvise(MADV_DONTNEED) failed for [{:#x}, +{:#x}): {}",
                host_addr,
                size,
                std::io::Error::last_os_error()
            );
        }

        let mut reg = UffdioRegister {
            range: UffdioRange {
                start: host_addr,
                len: size,
            },
            mode: UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP,
            ioctls: 0,
        };
        // SAFETY: uffd_fd is a valid userfaultfd opened by create_uffd(); `reg` is a
        // fully-initialised UffdioRegister on the stack and its pointer is valid for
        // the duration of the ioctl.
        let ret = unsafe { libc::ioctl(self.uffd_fd, UFFDIO_REGISTER as _, &mut reg as *mut _) };
        if ret != 0 {
            bail!(
                "UFFDIO_REGISTER failed for [{:#x}, +{:#x}): {}",
                host_addr,
                size,
                std::io::Error::last_os_error()
            );
        }
        self.regions.push((host_addr, size, offset));
        Ok(())
    }

    /// Connect to the external uffd daemon socket, hand over the uffd fd together
    /// with the region mapping JSON, then block until the daemon sends a one-byte
    /// ready ACK.
    ///
    /// The ACK ensures the daemon's Serve() loop is running before this function
    /// returns.  Callers must not resume vCPUs until this returns successfully,
    /// otherwise a page fault could arrive before the daemon is ready to handle it.
    pub fn send_to_external_uffd_daemon(&self) -> Result<()> {
        // SAFETY: sysconf(_SC_PAGESIZE) is always valid on Linux and never fails;
        // no pointers or memory invariants are involved.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;

        let json = serde_json::to_vec(&self.region_mappings(page_size))
            .context("failed to serialise region mappings")?;

        let mut stream = send_fd_with_json(&self.socket_path, self.uffd_fd, &json)
            .context("failed to send uffd fd to external uffd daemon")?;

        // Block until the daemon signals it is ready to serve page faults.
        let mut ack = [0u8; 1];
        stream
            .read_exact(&mut ack)
            .context("waiting for uffd daemon ready ACK")?;

        Ok(())
    }

    fn region_mappings(&self, page_size: u64) -> Vec<RegionMapping> {
        self.regions
            .iter()
            .map(|&(host_addr, size, offset)| RegionMapping {
                base_hva: host_addr,
                size,
                offset,
                page_size_kib: page_size,
            })
            .collect()
    }
}

/// Keep the UFFD fd alive in StratoVirt and make dirty bitmap queries available.
pub fn store_uffd_backend(backend: UffdMemoryBackend) {
    *backend_state().lock().unwrap() = Some(backend);
}

fn build_dirty_bitmap(backend: &UffdMemoryBackend) -> Result<MemDirtyBitmap> {
    // Dirty bitmap bits and pagemap entries both use the host base page size.
    let page_size = host_page_size();
    let mut pagemap = PagemapBatchReader::new()?;
    let mut bitmap = Vec::new();

    for &(base_hva, size, offset) in &backend.regions {
        if offset % page_size != 0 {
            bail!(
                "UFFD mapping offset {} is not aligned to page size {}",
                offset,
                page_size
            );
        }
        let page_base = offset / page_size;
        pagemap.scan_range(base_hva, size, page_size, |bitmap_page_index, entry| {
            if entry.is_uffd_dirty() {
                set_dense_bitmap_bit(&mut bitmap, page_base + bitmap_page_index)?;
            }
            Ok(())
        })?;
    }

    Ok(MemDirtyBitmap { bitmap, page_size })
}

fn write_protect_mappings(backend: &UffdMemoryBackend, enabled: bool) -> Result<()> {
    let mode = if enabled {
        UFFDIO_WRITEPROTECT_MODE_WP
    } else {
        0
    };

    for &(base_hva, size, _) in &backend.regions {
        if size == 0 {
            continue;
        }

        let mut wp = UffdioWriteProtect {
            range: UffdioRange {
                start: base_hva,
                len: size,
            },
            mode,
        };
        // SAFETY: backend.uffd_fd is an open userfaultfd and `wp` points to a
        // valid UFFDIO_WRITEPROTECT payload for the duration of the ioctl.
        let ret = unsafe {
            libc::ioctl(
                backend.uffd_fd,
                UFFDIO_WRITEPROTECT as _,
                &mut wp as *mut UffdioWriteProtect,
            )
        };
        if ret < 0 {
            bail!(
                "Failed to {} UFFD-WP range at {:#x}: {}",
                if enabled { "enable" } else { "disable" },
                base_hva,
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

/// Return dirty pages since the previous query, then reset UFFD-WP tracking.
pub fn query_and_reset_dirty_bitmap() -> Result<MemDirtyBitmap> {
    let guard = backend_state().lock().unwrap();
    let backend = guard
        .as_ref()
        .with_context(|| "UFFD dirty tracking is not enabled")?;

    let bitmap = build_dirty_bitmap(backend)?;
    write_protect_mappings(backend, true)
        .with_context(|| "Failed to reset UFFD-WP dirty tracking")?;
    Ok(bitmap)
}

impl Drop for UffdMemoryBackend {
    fn drop(&mut self) {
        if self.uffd_fd >= 0 {
            // SAFETY: uffd_fd >= 0 guarantees the fd is valid; Drop runs exactly once,
            // so this is the sole close for this fd.
            unsafe { libc::close(self.uffd_fd) };
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helper: create userfaultfd
// ────────────────────────────────────────────────────────────────────────────

fn create_uffd() -> Result<RawFd> {
    // O_CLOEXEC = 0x80000 on both x86_64 and aarch64
    // SAFETY: SYS_USERFAULTFD_NR is the correct syscall number for this architecture;
    // O_CLOEXEC | O_NONBLOCK are valid flags accepted by userfaultfd(2).
    let fd = unsafe { libc::syscall(SYS_USERFAULTFD_NR, libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if fd < 0 {
        bail!(
            "SYS_userfaultfd failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let fd = fd as RawFd;

    // Enable the API, requesting WP_ASYNC (required for UFFDIO_COPY_MODE_WP)
    // and EVENT_REMOVE (required for dirty-page tracking during snapshots).
    let mut api = UffdioApi {
        api: UFFD_API,
        features: UFFD_FEATURE_EVENT_REMOVE | UFFD_FEATURE_WP_ASYNC,
        ioctls: 0,
    };
    // SAFETY: fd is a valid userfaultfd just opened above; `api` is a valid UffdioApi
    // struct on the stack and its pointer is live for the duration of the ioctl.
    let ret = unsafe { libc::ioctl(fd, UFFDIO_API as _, &mut api as *mut _) };
    if ret != 0 {
        // SAFETY: fd was successfully opened by the syscall above; closing it on the
        // error path prevents a file-descriptor leak.
        unsafe { libc::close(fd) };
        bail!("UFFDIO_API failed: {}", std::io::Error::last_os_error());
    }

    Ok(fd)
}

// ────────────────────────────────────────────────────────────────────────────
// Helper: send fd + JSON over a Unix socket (SCM_RIGHTS)
// ────────────────────────────────────────────────────────────────────────────

/// Connect to `socket_path`, send `fd` as SCM_RIGHTS ancillary data together
/// with `json` as the message payload, and return the open `UnixStream` so the
/// caller can read a ready-ACK byte from the daemon.
fn send_fd_with_json(socket_path: &PathBuf, fd: RawFd, json: &[u8]) -> Result<UnixStream> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("connect to UFFD socket {:?}", socket_path))?;
    stream
        .send_with_fd(json, fd)
        .with_context(|| "sendmsg to UFFD socket failed")?;
    Ok(stream)
}

// ────────────────────────────────────────────────────────────────────────────
// Unit tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Create a `UffdMemoryBackend` pointing at `socket_path`.
    /// Returns `None` when `userfaultfd` is not available in this environment
    /// (e.g. a restricted container), so callers can skip the test gracefully.
    fn try_new_uffd(socket_path: &str) -> Option<UffdMemoryBackend> {
        UffdMemoryBackend::new(socket_path).ok()
    }

    /// Spawn a mock daemon thread that:
    /// 1. Accepts one connection on `listener`.
    /// 2. Drains the incoming sendmsg payload (SCM_RIGHTS fd auto-closed).
    /// 3. Sends one ACK byte.
    fn spawn_mock_daemon_with_ack(listener: UnixListener) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock daemon: accept");
            let mut buf = [0u8; 65536];
            // Drain the sendmsg payload; ancillary SCM_RIGHTS fd is silently discarded.
            // SAFETY: buf is a valid mutable slice on the stack; stream.as_raw_fd()
            // returns a valid connected socket fd for the duration of this call.
            unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            stream.write_all(&[1u8]).expect("mock daemon: send ACK");
        })
    }

    /// Spawn a mock daemon thread that accepts a connection but closes it
    /// without sending any ACK (simulates a daemon that crashes before ready).
    fn spawn_mock_daemon_no_ack(listener: UnixListener) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("mock daemon: accept");
            // _stream drops here → EOF on the other side, no ACK sent.
        })
    }

    #[test]
    fn test_send_to_external_uffd_daemon_receives_ack() {
        let socket_path = "/tmp/sv_test_uffd_ack_ok.sock";
        let Some(uffd) = try_new_uffd(socket_path) else {
            eprintln!("skip: userfaultfd not available");
            return;
        };

        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).expect("bind");

        let handle = spawn_mock_daemon_with_ack(listener);

        // regions is empty → sends `[]` as JSON; tests the ACK round-trip.
        assert!(
            uffd.send_to_external_uffd_daemon().is_ok(),
            "should succeed after daemon sends ACK"
        );

        handle.join().expect("daemon thread");
        let _ = std::fs::remove_file(socket_path);
    }

    #[test]
    fn test_region_mappings_use_registered_offsets() {
        let backend = UffdMemoryBackend {
            socket_path: PathBuf::from("/tmp/unused.sock"),
            regions: vec![(0x1000, 0x2000, 0), (0x8000, 0x1000, 0x2000)],
            uffd_fd: -1,
        };

        let mappings = backend.region_mappings(4096);

        assert_eq!(
            mappings,
            vec![
                RegionMapping {
                    base_hva: 0x1000,
                    size: 0x2000,
                    offset: 0,
                    page_size_kib: 4096,
                },
                RegionMapping {
                    base_hva: 0x8000,
                    size: 0x1000,
                    offset: 0x2000,
                    page_size_kib: 4096,
                },
            ]
        );
    }

    #[test]
    fn test_send_to_external_uffd_daemon_no_ack_returns_error() {
        let socket_path = "/tmp/sv_test_uffd_ack_err.sock";
        let Some(uffd) = try_new_uffd(socket_path) else {
            eprintln!("skip: userfaultfd not available");
            return;
        };

        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).expect("bind");

        let handle = spawn_mock_daemon_no_ack(listener);

        // Daemon closes connection without ACK → read_exact gets EOF.
        assert!(
            uffd.send_to_external_uffd_daemon().is_err(),
            "should fail when no ACK is received"
        );

        handle.join().expect("daemon thread");
        let _ = std::fs::remove_file(socket_path);
    }

    #[test]
    fn test_send_to_external_uffd_daemon_socket_missing() {
        // Socket path does not exist → connect fails immediately.
        match try_new_uffd("/tmp/sv_test_uffd_nonexistent.sock") {
            Some(uffd) => {
                assert!(
                    uffd.send_to_external_uffd_daemon().is_err(),
                    "should fail when socket path does not exist"
                );
            }
            None => eprintln!("skip: userfaultfd not available"),
        }
    }
}
