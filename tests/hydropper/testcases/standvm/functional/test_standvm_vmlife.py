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
"""Test standvm vmlife"""

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
        retdict["cpu"] = {"vcpu_count": vcpu_count}
        retdict["mem"] = {"memsize": memsize}
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

@pytest.mark.standvm_accept
@pytest.mark.parametrize("vcpu_count, memsize, vnetnums",
                         [(1, 1024, 1),
                          (2, 2048, 2)])
def test_standvm_start(standvm, vcpu_count, memsize, vnetnums):
    """Test a normal microvm start"""
    test_vm = standvm
    test_vm.basic_config(vcpu_count=vcpu_count, mem_size=memsize, vnetnums=vnetnums)
    test_vm.launch()
    vmhwinfo = _get_guest_hwinfo(test_vm)
    logging.debug("current vmhwinfo is %s", vmhwinfo)
    assert vmhwinfo["cpu"]["vcpu_count"] == vcpu_count
    assert vmhwinfo["mem"]["memsize"] > (memsize * 1024 * 90 / 100)
    assert len(vmhwinfo["virtio"]["virtio_blk"]) == 1
    assert len(vmhwinfo["virtio"]["virtio_net"]) == vnetnums
    assert len(vmhwinfo["virtio"]["virtio_console"]) == 1
    test_vm.shutdown()
