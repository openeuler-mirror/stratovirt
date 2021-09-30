# Copyright (c) 2021 Huawei Technologies Co.,Ltd. All rights reserved.
#
# StratoVirt is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#         http:#license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

"""Test microvm rng"""

import logging
import pytest
from subprocess import run
from utils.config import CONFIG

def _check_virtio_rng_device(test_vm):
    """Check virtio rng device in Guest"""
    _cmd = "ls /dev/hwrng"
    status,_ = test_vm.serial_cmd(_cmd)
    assert status == 0

    rng_files = (
        "/sys/devices/virtual/misc/hw_random/rng_available",
        "/sys/devices/virtual/misc/hw_random/rng_current")
    _, rng_avail = test_vm.serial_cmd("cat %s" % rng_files[0])
    _, rng_curr = test_vm.serial_cmd("cat %s" % rng_files[1])
    rng_avail = rng_avail.strip()
    rng_curr = rng_curr.strip()
    logging.debug("rng avail: %s, rng current: %s", rng_avail, rng_curr)
    if not rng_curr.count("virtio") or rng_curr not in rng_avail:
        pytest.xfail(reason="Failed to check rng file on guest")

    _cmd = ("dd if=/dev/hwrng of=rng.test count=100 && rm -f rng.test")
    try:
        ret,_ = test_vm.serial_cmd(_cmd)
        assert ret == 0
    finally:
        test_vm.serial_cmd("rm -f rng.test")

@pytest.mark.acceptance
def test_microvm_virtio_rng(microvm):
    test_vm = microvm
    test_vm.basic_config(rng=True)
    test_vm.launch()

    # check virtio rng device
    _check_virtio_rng_device(test_vm)

    test_vm.stop()
    test_vm.event_wait(name='STOP')
    test_vm.cont()
    test_vm.event_wait(name='RESUME')

    # check virtio rng device
    _check_virtio_rng_device(test_vm)

@pytest.mark.acceptance
@pytest.mark.parametrize("max_bytes", [1000000000, 200000000])
def test_microvm_virtio_rng_bytes_limit(microvm, max_bytes):
    test_vm = microvm
    test_vm.basic_config(rng=True, max_bytes=max_bytes)
    test_vm.launch()

    # check virtio rng device
    _check_virtio_rng_device(test_vm)

    test_vm.stop()
    test_vm.event_wait(name='STOP')
    test_vm.cont()
    test_vm.event_wait(name='RESUME')

    # check virtio rng device
    _check_virtio_rng_device(test_vm)

