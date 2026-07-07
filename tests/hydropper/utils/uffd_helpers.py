# Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
#
# StratoVirt is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#         http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
"""Shared helpers for UFFD (userfaultfd) pytest tests.

Provides:
  - uffd_supported     pytest.mark.skipif decorator
  - MockUffdDaemon     Python mock of the external uffd daemon
  - _send_fd_with_json / _recv_fd_and_json  (protocol helpers)
"""

import array
import ctypes
import ctypes.util
import errno as errno_mod
import json
import mmap
import os
import platform
import select
import socket
import struct
import threading

import pytest

from utils.config import CONFIG

# ────────────────────────────────────────────────────────────────────────────
# UFFD constants
# ────────────────────────────────────────────────────────────────────────────

_SYS_USERFAULTFD = 282 if 'aarch' in platform.machine() else 323

# _IOWR(0xAA, 0x03, struct uffdio_copy) — same on x86_64 and aarch64
UFFDIO_COPY = 0xC028AA03

UFFD_EVENT_PAGEFAULT = 0x12

# ────────────────────────────────────────────────────────────────────────────
# libc helpers
# ────────────────────────────────────────────────────────────────────────────

_libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
_libc.ioctl.restype = ctypes.c_int
_libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
_libc.syscall.restype = ctypes.c_long
_libc.close.restype = ctypes.c_int


class _UffdioCopy(ctypes.Structure):
    """struct uffdio_copy — argument to the UFFDIO_COPY ioctl."""
    _fields_ = [
        ('dst', ctypes.c_uint64),
        ('src', ctypes.c_uint64),
        ('len', ctypes.c_uint64),
        ('mode', ctypes.c_uint64),
        ('copy', ctypes.c_int64),
    ]


# ────────────────────────────────────────────────────────────────────────────
# Kernel support check
# ────────────────────────────────────────────────────────────────────────────

def check_uffd_support():
    """Return True when SYS_userfaultfd succeeds (kernel ≥ 4.11 required)."""
    fd = _libc.syscall(_SYS_USERFAULTFD, 0)
    if fd < 0:
        return False
    _libc.close(fd)
    return True


uffd_supported = pytest.mark.skipif(
    not check_uffd_support(),
    reason="userfaultfd not available in this kernel/container environment",
)


def _microvm_images_present():
    """Return True when microvm kernel + rootfs images exist on disk."""
    for path in (CONFIG.stratovirt_rootfs, CONFIG.stratovirt_vmlinux):
        if not path or not os.path.isfile(path):
            return False
    return True


def _standvm_images_present():
    """Return True when standvm kernel + rootfs images exist on disk."""
    for path in (CONFIG.stratovirt_stand_rootfs, CONFIG.stratovirt_stand_vmlinux):
        if not path or not os.path.isfile(path):
            return False
    return True


vm_images_available = pytest.mark.skipif(
    not _microvm_images_present(),
    reason="microvm image files not found (set STRATOVIRT_ROOTFS / STRATOVIRT_VMLINUX in config)",
)

standvm_images_available = pytest.mark.skipif(
    not _standvm_images_present(),
    reason="standvm image files not found (set STRATOVIRT_STAND_ROOTFS / STRATOVIRT_STAND_VMLINUX in config)",
)

# ────────────────────────────────────────────────────────────────────────────
# Protocol helpers
# ────────────────────────────────────────────────────────────────────────────


def recv_fd_and_json(conn):
    """Receive JSON payload and one fd via SCM_RIGHTS from *conn*.

    Returns ``(json_bytes, fd)``; *fd* is -1 if no ancillary fd was present.
    """
    json_bytes, ancdata, _flags, _addr = conn.recvmsg(65536, socket.CMSG_SPACE(4))
    fd = -1
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            fds = array.array('i')
            nbytes = len(cmsg_data) - (len(cmsg_data) % fds.itemsize)
            fds.frombytes(cmsg_data[:nbytes])
            if fds:
                fd = fds[0]
    return json_bytes, fd


def send_fd_with_json(sock_path, fd, json_bytes):
    """Connect to *sock_path* and send *fd* + *json_bytes* via SCM_RIGHTS.

    Returns the open UnixStream so the caller can read the ACK byte.
    Mirrors StratoVirt's ``send_fd_with_json`` Rust function.
    """
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.connect(sock_path)
        cmsg_data = array.array('i', [fd])
        conn.sendmsg(
            [json_bytes],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, cmsg_data)],
        )
    except Exception:
        conn.close()
        raise
    return conn


# ────────────────────────────────────────────────────────────────────────────
# Mock UFFD daemon
# ────────────────────────────────────────────────────────────────────────────

class MockUffdDaemon:
    """Python mock of the external uffd daemon expected by StratoVirt.

    Protocol:
        1. Listen on ``socket_path``.
        2. Accept one connection.
        3. Receive JSON region list + uffd fd via SCM_RIGHTS.
        4. Send 1-byte ACK (unless ``send_ack=False``).
        5. (Optional) Serve MISSING page faults from ``memory_file``.

    After ``stop()``, inspect ``errors`` and ``page_faults_served``.
    """

    def __init__(self, socket_path, memory_file=None, send_ack=True):
        self.socket_path = socket_path
        self.memory_file = memory_file
        self.send_ack = send_ack

        self._stop = threading.Event()
        self._server = None
        self._thread = None

        # Populated by _handle_connection
        self._uffd_fd = -1
        self.regions = []
        self.errors = []
        self.page_faults_served = 0

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self):
        """Bind Unix socket and start the background handler thread."""
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(1)
        self._thread = threading.Thread(
            target=self._run, daemon=True, name='mock-uffd-daemon'
        )
        self._thread.start()

    def start_with_server(self, server_socket):
        """Start the background handler thread using a pre-bound server socket."""
        self._server = server_socket
        self._thread = threading.Thread(
            target=self._run, daemon=True, name='mock-uffd-daemon'
        )
        self._thread.start()

    def join(self, timeout=None):
        """Wait for the background handler thread to finish."""
        if self._thread:
            self._thread.join(timeout=timeout)

    def take_uffd_fd(self):
        """Return the received uffd fd and transfer ownership to the caller.

        Returns -1 if no fd was received. The caller is responsible for closing it.
        """
        fd = self._uffd_fd
        self._uffd_fd = -1
        return fd

    def stop(self):
        """Signal the daemon thread to exit and release resources."""
        self._stop.set()
        try:
            self._server.close()
        except Exception as exc:
            self.errors.append(f"server close failed: {exc}")
        uffd = self._uffd_fd
        self._uffd_fd = -1
        if uffd >= 0:
            try:
                os.close(uffd)
            except OSError as exc:
                self.errors.append(f"uffd close failed: {exc}")
        if self._thread:
            self._thread.join(timeout=5)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _run(self):
        try:
            self._server.settimeout(10.0)
            conn, _ = self._server.accept()
        except Exception as exc:
            if not self._stop.is_set():
                self.errors.append(exc)
            return
        try:
            with conn:
                self._handle_connection(conn)
        except Exception as exc:
            if not self._stop.is_set():
                self.errors.append(exc)

    def _handle_connection(self, conn):
        json_bytes, fd = recv_fd_and_json(conn)
        self.regions = json.loads(json_bytes)
        if fd >= 0:
            self._uffd_fd = fd

        if not self.send_ack:
            return

        conn.sendall(b'\x01')

        if self.memory_file and self._uffd_fd >= 0:
            self._serve_faults()

    def _serve_faults(self):
        """Serve UFFD MISSING faults by reading pages from the memory snapshot."""
        page_size = 4096
        with open(self.memory_file, 'rb') as mf:
            mem = mmap.mmap(mf.fileno(), 0, access=mmap.ACCESS_READ)
        buf = ctypes.create_string_buffer(page_size)
        try:
            while not self._stop.is_set():
                rlist, _, _ = select.select([self._uffd_fd], [], [], 1.0)
                if not rlist:
                    continue
                try:
                    raw = os.read(self._uffd_fd, 32)
                except BlockingIOError:
                    continue
                except OSError:
                    break

                if len(raw) < 32:
                    break

                if raw[0] != UFFD_EVENT_PAGEFAULT:
                    continue

                # uffd_msg layout: event(1)+rsv1(1)+rsv2(2)+rsv3(4)+flags(8)+address(8)
                fault_addr = struct.unpack_from('<Q', raw, 16)[0]
                page_addr = fault_addr & ~(page_size - 1)

                region = self._find_region(page_addr)
                if region is None:
                    self.errors.append('page fault %#x outside all regions' % page_addr)
                    continue

                file_off = region['offset'] + (page_addr - region['base_host_virt_addr'])
                page_data = mem[file_off: file_off + page_size]
                ctypes.memmove(buf, page_data, min(len(page_data), page_size))

                copy = _UffdioCopy()
                copy.dst = page_addr
                copy.src = ctypes.addressof(buf)
                copy.len = page_size
                copy.mode = 0
                copy.copy = 0

                ret = _libc.ioctl(self._uffd_fd, UFFDIO_COPY, ctypes.byref(copy))
                if ret != 0:
                    ev = ctypes.get_errno()
                    if ev != errno_mod.EEXIST:  # EEXIST: page already mapped, harmless
                        self.errors.append('UFFDIO_COPY failed: errno %d' % ev)
                else:
                    self.page_faults_served += 1
        finally:
            mem.close()

    def _find_region(self, page_addr):
        for r in self.regions:
            base = r['base_host_virt_addr']
            if base <= page_addr < base + r['size']:
                return r
        return None
