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
"""Tests for the userfaultfd (UFFD) lazy-load memory backend — standvm variant.

Integration tests that save a standard-VM snapshot and restore it via the
UFFD lazy-load path, exercising the same code path as the microvm tests but
with the q35/virt machine type that carries additional emulated devices (PCIe,
ACPI, OVMF/SeaBIOS firmware).

All tests are marked ``acceptance`` and are skipped when the kernel does not
support userfaultfd (e.g. in restricted container environments).
"""

import os
import time

import pytest

from conftest import init_standvm
from utils.uffd_helpers import (
    MockUffdDaemon,
    standvm_images_available,
    uffd_supported,
)


# ────────────────────────────────────────────────────────────────────────────
# L2: Integration tests
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.acceptance
@uffd_supported
@standvm_images_available
def test_standvm_snapshot_uffd_restore(standvm, test_session_tmp_path):
    """Save a standard-VM snapshot, then restore it via UFFD lazy-load.

    The mock daemon serves MISSING page faults from the memory snapshot file.
    The restored VM must come up and shut down cleanly.
    """
    snap_dir = os.path.join(test_session_tmp_path, 'snap_uffd')
    os.makedirs(snap_dir)
    mem_file = os.path.join(snap_dir, 'memory')
    socket_path = os.path.join(test_session_tmp_path, 'uffd.sock')

    src_vm = standvm
    src_vm.launch()
    src_vm.stop()
    src_vm.migrate(uri='file:%s' % snap_dir)
    src_vm.shutdown()

    assert os.path.isfile(mem_file), "memory snapshot file was not created"

    daemon = MockUffdDaemon(socket_path, memory_file=mem_file)
    daemon.start()

    restore_vm = init_standvm(test_session_tmp_path)
    restore_vm.incoming = True  # skip serial-login wait in _post_launch
    incoming = 'file:%s,mapped=false,uffd_sock=%s' % (snap_dir, socket_path)
    restore_vm.basic_config(quickstart_incoming=incoming)
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
@standvm_images_available
def test_standvm_snapshot_uffd_freeze_cpu(standvm, test_session_tmp_path):
    """UFFD restore with -S (freeze_cpu): VM starts paused, resumes via QMP cont."""
    snap_dir = os.path.join(test_session_tmp_path, 'snap_freeze')
    os.makedirs(snap_dir)
    mem_file = os.path.join(snap_dir, 'memory')
    socket_path = os.path.join(test_session_tmp_path, 'uffd_freeze.sock')

    src_vm = standvm
    src_vm.launch()
    src_vm.stop()
    src_vm.migrate(uri='file:%s' % snap_dir)
    src_vm.shutdown()

    daemon = MockUffdDaemon(socket_path, memory_file=mem_file)
    daemon.start()

    restore_vm = init_standvm(test_session_tmp_path)
    restore_vm.incoming = True  # skip serial-login wait in _post_launch
    incoming = 'file:%s,mapped=false,uffd_sock=%s' % (snap_dir, socket_path)
    restore_vm.basic_config(quickstart_incoming=incoming)
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
@standvm_images_available
def test_standvm_snapshot_uffd_invalid_socket(standvm, test_session_tmp_path):
    """UFFD restore with a missing socket: StratoVirt must exit with an error."""
    snap_dir = os.path.join(test_session_tmp_path, 'snap_bad_sock')
    os.makedirs(snap_dir)
    mem_file = os.path.join(snap_dir, 'memory')

    src_vm = standvm
    src_vm.launch()
    src_vm.stop()
    src_vm.migrate(uri='file:%s' % snap_dir)
    src_vm.shutdown()

    absent_sock = os.path.join(test_session_tmp_path, 'no_daemon.sock')

    restore_vm = init_standvm(test_session_tmp_path)
    incoming = 'file:%s,mapped=false,uffd_sock=%s' % (snap_dir, absent_sock)
    restore_vm.basic_config(quickstart_incoming=incoming)
    restore_vm.error_test = True
    try:
        restore_vm.launch()
        time.sleep(2.0)

        pid = restore_vm.pid
        still_alive = False
        if pid:
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
