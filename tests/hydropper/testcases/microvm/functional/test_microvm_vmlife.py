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
"""Test microvm vmlife"""

import logging
import pytest
from utils import utils_qmp
from utils.config import CONFIG
from utils.exception import QMPTimeoutError

def _get_guest_hwinfo(test_vm):
    """
    Get guest hwinfo via ssh_session

    Returns:
        {"cpu": {"vcpu_count": xx, "maxvcpu": xx},
        "mem": {"memsize": xx, "maxmem": xx},
        "virtio": {"virtio_blk": [{"name": "virtio0"}],
                "virtio_console": [{"name": "virtio1"}],
                "virtio_net": [{"name": "virtio2"}],
                "virtio_rng": [{"name": "virtio3"}],
                }
        }
    """
    retdict = {"cpu": {}, "mem": {}, "virtio": {}}
    if test_vm.ssh_session is not None:
        vcpu_count = int(test_vm.ssh_session.cmd_output("grep -c processor /proc/cpuinfo"))
        memsize = int(test_vm.ssh_session.cmd_output("grep MemTotal /proc/meminfo | awk '{print $2}'"))
        retdict["cpu"] = {"vcpu_count": vcpu_count, "maxvcpu": vcpu_count}
        retdict["mem"] = {"memsize": memsize, "maxmem": memsize}
        # ignore virtio_rng device now
        for dev in ["virtio_blk", "virtio_net", "virtio_console"]:
            devdir = "/sys/bus/virtio/drivers/%s" % dev
            _cmd = "test -d %s && ls %s | grep virtio" % (devdir, devdir)
            virtiodevs = test_vm.ssh_session.cmd_output(_cmd).strip().split()
            for virtiodev in virtiodevs:
                _tempdev = {"name": virtiodev}
                if dev not in retdict["virtio"]:
                    retdict["virtio"][dev] = list()
                retdict["virtio"][dev].append(_tempdev)

    return retdict

@pytest.mark.acceptance
@pytest.mark.parametrize("vcpu_count, memsize, vnetnums",
                         [(1, 256, 1),
                          (2, 1024, 2)])
def test_microvm_start(microvm, vcpu_count, memsize, vnetnums):
    """Test a normal microvm start"""
    test_vm = microvm
    test_vm.basic_config(vcpu_count=vcpu_count, mem_size=memsize, vnetnums=vnetnums)
    test_vm.launch()
    vmhwinfo = _get_guest_hwinfo(test_vm)
    logging.debug("current vmhwinfo is %s", vmhwinfo)
    assert vmhwinfo["cpu"]["vcpu_count"] == vcpu_count
    assert vmhwinfo["mem"]["memsize"] > (memsize * 1024 * 90 / 100)
    assert len(vmhwinfo["virtio"]["virtio_blk"]) == 4
    assert len(vmhwinfo["virtio"]["virtio_net"]) == 2
    assert len(vmhwinfo["virtio"]["virtio_console"]) == 1
    test_vm.shutdown()


@pytest.mark.system
@pytest.mark.parametrize("destroy_value", [9, 15])
def test_microvm_destroy(microvm, destroy_value):
    """Test a normal microvm destroy(kill -9)"""
    test_vm = microvm
    test_vm.launch()
    test_vm.destroy(signal=destroy_value)


@pytest.mark.acceptance
def test_microvm_pause_resume(microvm):
    """Test a normal microvm pause"""
    test_vm = microvm
    test_vm.launch()
    resp = test_vm.query_status()
    utils_qmp.assert_qmp(resp, "return/status", "running")
    test_vm.stop()
    test_vm.event_wait(name='STOP')
    resp = test_vm.query_status()
    utils_qmp.assert_qmp(resp, "return/status", "paused")
    test_vm.cont()
    test_vm.event_wait(name='RESUME')
    resp = test_vm.query_status()
    utils_qmp.assert_qmp(resp, "return/status", "running")
    ret, _ = test_vm.serial_cmd("ls")
    assert ret == 0


@pytest.mark.system
def test_microvm_pause_resume_abnormal(microvm):
    """Abnormal test for microvm pause/resume"""
    test_vm = microvm
    test_vm.launch()
    resp = test_vm.cont()
    utils_qmp.assert_qmp(resp, "error/class", "GenericError")
    with pytest.raises(QMPTimeoutError):
        test_vm.event_wait(name='RESUME', timeout=3.0)
    test_vm.qmp_reconnect()
    ret, _ = test_vm.serial_cmd("ls")
    assert ret == 0
    resp = test_vm.stop()
    utils_qmp.assert_qmp(resp, "return", {})
    test_vm.event_wait(name='STOP')
    resp = test_vm.stop()
    utils_qmp.assert_qmp(resp, "error/class", "GenericError")
    with pytest.raises(QMPTimeoutError):
        test_vm.event_wait(name='STOP', timeout=3.0)
    test_vm.qmp_reconnect()
    resp = test_vm.cont()
    utils_qmp.assert_qmp(resp, "return", {})
    test_vm.event_wait(name='RESUME')
    ret, _ = test_vm.serial_cmd("ls")
    assert ret == 0
    resp = test_vm.cont()
    utils_qmp.assert_qmp(resp, "error/class", "GenericError")
    ret, _ = test_vm.serial_cmd("ls")
    assert ret == 0
    with pytest.raises(QMPTimeoutError):
        test_vm.event_wait(name='RESUME', timeout=3.0)
    test_vm.qmp_reconnect()
