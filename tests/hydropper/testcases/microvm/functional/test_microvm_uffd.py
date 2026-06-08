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
"""Tests for the userfaultfd (UFFD) lazy-load memory backend — microvm variant.

Two test layers:
  L1 – TestUffdProtocol: pure Python socket/SCM_RIGHTS protocol tests (no VM).
  L2 – test_microvm_snapshot_uffd_*: full integration with a running microvm.
"""

import json
import os
import time

import pytest

from conftest import init_microvm
from utils.uffd_helpers import (
    MockUffdDaemon,
    recv_fd_and_json,
    send_fd_with_json,
    uffd_supported,
    vm_images_available,
)

# ────────────────────────────────────────────────────────────────────────────
# L1: Protocol-level tests (no VM required)
# ────────────────────────────────────────────────────────────────────────────


class TestUffdProtocol:
    """Verify the Unix-socket / SCM_RIGHTS protocol without a running StratoVirt."""

    @staticmethod
    def _server_socket(tmp_path, name='proto.sock'):
        import socket as _socket
        path = os.path.join(str(tmp_path), name)
        srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        try:
            srv.bind(path)
            srv.listen(1)
        except:
            srv.close()
            raise
        return srv, path

    @staticmethod
    def _start_daemon(daemon, srv):
        daemon.start_with_server(srv)

    def test_ack_returned_to_sender(self, tmp_path):
        """Client receives the ACK byte when the daemon is ready."""
        srv, path = self._server_socket(tmp_path)
        daemon = MockUffdDaemon(path, send_ack=True)
        self._start_daemon(daemon, srv)

        null_fd = os.open('/dev/null', os.O_RDONLY)
        try:
            client = send_fd_with_json(path, null_fd, b'[]')
            try:
                ack = client.recv(1)
            finally:
                client.close()
        finally:
            os.close(null_fd)

        daemon.join(timeout=3)
        assert ack == b'\x01'
        assert not daemon.errors

    def test_no_ack_causes_empty_recv(self, tmp_path):
        """When the daemon closes without sending ACK the client gets EOF."""
        srv, path = self._server_socket(tmp_path)
        daemon = MockUffdDaemon(path, send_ack=False)
        self._start_daemon(daemon, srv)

        null_fd = os.open('/dev/null', os.O_RDONLY)
        try:
            client = send_fd_with_json(path, null_fd, b'[]')
            os.close(null_fd)
            null_fd = -1
            try:
                ack = client.recv(1)
            finally:
                client.close()
        finally:
            if null_fd >= 0:
                os.close(null_fd)

        daemon.join(timeout=3)
        assert ack == b''  # EOF — no ACK was sent

    def test_region_json_is_parsed_correctly(self, tmp_path):
        """Region JSON sent by the client is decoded correctly by the daemon."""
        srv, path = self._server_socket(tmp_path)
        daemon = MockUffdDaemon(path, send_ack=True)
        self._start_daemon(daemon, srv)

        regions = [
            {
                'base_hva': 0x7F0000000000,
                'size': 0x100000,
                'offset': 8192,
                'page_size_kib': 4096,
            },
            {
                'base_hva': 0x7F0000200000,
                'size': 0x200000,
                'offset': 8192 + 0x100000,
                'page_size_kib': 4096,
            },
        ]
        payload = json.dumps(regions).encode()
        null_fd = os.open('/dev/null', os.O_RDONLY)
        try:
            client = send_fd_with_json(path, null_fd, payload)
            try:
                client.recv(1)
            finally:
                client.close()
        finally:
            os.close(null_fd)

        daemon.join(timeout=3)
        assert not daemon.errors
        assert len(daemon.regions) == 2
        assert daemon.regions[0]['base_hva'] == 0x7F0000000000
        assert daemon.regions[1]['size'] == 0x200000

    def test_fd_received_via_scm_rights_is_valid(self, tmp_path):
        """The fd passed via SCM_RIGHTS arrives intact and is usable."""
        srv, path = self._server_socket(tmp_path)
        daemon = MockUffdDaemon(path, send_ack=True)
        self._start_daemon(daemon, srv)

        null_fd = os.open('/dev/null', os.O_RDONLY)
        try:
            client = send_fd_with_json(path, null_fd, b'[]')
            try:
                client.recv(1)
            finally:
                client.close()
        finally:
            os.close(null_fd)

        daemon.join(timeout=3)
        assert not daemon.errors
        uffd_fd = daemon.take_uffd_fd()
        assert uffd_fd >= 0

        try:
            os.fstat(uffd_fd)
            valid = True
        except OSError:
            valid = False
        finally:
            try:
                os.close(uffd_fd)
            except OSError:
                pass

        assert valid, "received fd is not a valid open file descriptor"

    @staticmethod
    def test_connect_to_missing_socket_raises(tmp_path):
        """Attempting to connect to a non-existent socket path raises OSError."""
        absent = os.path.join(str(tmp_path), 'no_such_socket.sock')
        null_fd = os.open('/dev/null', os.O_RDONLY)
        try:
            with pytest.raises(OSError):
                send_fd_with_json(absent, null_fd, b'[]')
        finally:
            os.close(null_fd)

# ────────────────────────────────────────────────────────────────────────────
# L2: Integration tests (require running microvm + uffd kernel support)
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.acceptance
@uffd_supported
@vm_images_available
def test_microvm_snapshot_uffd_restore(microvm, test_session_tmp_path):
    """Save a snapshot, then restore it via UFFD lazy-load memory backend.

    The mock daemon serves MISSING page faults from the memory snapshot file.
    The restored VM must come up and shut down cleanly.
    """
    snap_dir = os.path.join(test_session_tmp_path, 'snap_uffd')
    os.makedirs(snap_dir)
    mem_file = os.path.join(snap_dir, 'memory')
    socket_path = os.path.join(test_session_tmp_path, 'uffd.sock')

    src_vm = microvm
    src_vm.basic_config(mem_size=256)
    src_vm.launch()
    src_vm.stop()
    src_vm.migrate(uri='file:%s' % snap_dir)
    src_vm.shutdown()

    assert os.path.isfile(mem_file), "memory snapshot file was not created"

    daemon = MockUffdDaemon(socket_path, memory_file=mem_file)
    daemon.start()

    restore_vm = init_microvm(test_session_tmp_path)
    restore_vm.incoming = True  # skip serial-login wait in _post_launch
    incoming = 'file:%s,mapped=false,uffd_sock=%s' % (snap_dir, socket_path)
    restore_vm.basic_config(quickstart_incoming=incoming, mem_size=256)
    try:
        restore_vm.launch()
        restore_vm.wait_console_create()
        restore_vm.post_launch_qmp()
        time.sleep(0.5)
        restore_vm.shutdown()
    finally:
        daemon.stop()
        restore_vm.kill()

    assert not daemon.errors, 'UFFD daemon errors: %s' % daemon.errors


@pytest.mark.acceptance
@uffd_supported
@vm_images_available
def test_microvm_snapshot_uffd_freeze_cpu(microvm, test_session_tmp_path):
    """UFFD restore with -S (freeze_cpu): VM starts paused, resumes via QMP cont."""
    snap_dir = os.path.join(test_session_tmp_path, 'snap_freeze')
    os.makedirs(snap_dir)
    mem_file = os.path.join(snap_dir, 'memory')
    socket_path = os.path.join(test_session_tmp_path, 'uffd_freeze.sock')

    src_vm = microvm
    src_vm.basic_config(mem_size=256)
    src_vm.launch()
    src_vm.stop()
    src_vm.migrate(uri='file:%s' % snap_dir)
    src_vm.shutdown()

    daemon = MockUffdDaemon(socket_path, memory_file=mem_file)
    daemon.start()

    restore_vm = init_microvm(test_session_tmp_path)
    restore_vm.incoming = True  # skip serial-login wait in _post_launch
    incoming = 'file:%s,mapped=false,uffd_sock=%s' % (snap_dir, socket_path)
    restore_vm.basic_config(quickstart_incoming=incoming, mem_size=256)
    restore_vm.freeze = True  # adds -S to the command line
    try:
        restore_vm.launch()
        restore_vm.wait_console_create()
        restore_vm.post_launch_qmp()
        restore_vm.cont()
        time.sleep(0.3)
        restore_vm.shutdown()
    finally:
        daemon.stop()
        restore_vm.kill()

    assert not daemon.errors, 'UFFD daemon errors: %s' % daemon.errors


@pytest.mark.acceptance
@uffd_supported
@vm_images_available
def test_microvm_snapshot_uffd_invalid_socket(microvm, test_session_tmp_path):
    """UFFD restore with a missing socket: StratoVirt must exit with an error."""
    snap_dir = os.path.join(test_session_tmp_path, 'snap_bad_sock')
    os.makedirs(snap_dir)
    mem_file = os.path.join(snap_dir, 'memory')

    src_vm = microvm
    src_vm.basic_config(mem_size=256)
    src_vm.launch()
    src_vm.stop()
    src_vm.migrate(uri='file:%s' % snap_dir)
    src_vm.shutdown()

    absent_sock = os.path.join(test_session_tmp_path, 'no_daemon.sock')

    restore_vm = init_microvm(test_session_tmp_path)
    incoming = 'file:%s,mapped=false,uffd_sock=%s' % (snap_dir, absent_sock)
    restore_vm.basic_config(quickstart_incoming=incoming, mem_size=256)
    restore_vm.error_test = True
    try:
        restore_vm.launch()

        pid = restore_vm.pid
        still_alive = False
        if pid:
            # Poll until StratoVirt exits (socket-connect fails after it
            # finishes daemonize + memory allocation), timeout 15 s.
            deadline = time.time() + 15
            while time.time() < deadline:
                try:
                    os.kill(int(pid), 0)
                    time.sleep(0.5)
                except (ProcessLookupError, ValueError):
                    break
            try:
                os.kill(int(pid), 0)
                still_alive = True
            except (ProcessLookupError, ValueError):
                pass
    finally:
        restore_vm.kill()

    assert not still_alive, (
        'StratoVirt should have exited when the uffd socket is absent, '
        'but pid %s is still running' % pid
    )
