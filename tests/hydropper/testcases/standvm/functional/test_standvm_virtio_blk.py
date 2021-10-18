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
"""Test standvm virtio block"""

import os
from subprocess import run
import pytest

def _get_lsblk_info(test_vm):
    """
    Get lsblk info

    Returns:
        {
            "vdx": {"size": xx, "readonly": xx},
        }
    """
    retdict = {}
    if test_vm.ssh_session is not None:
        _output = test_vm.ssh_session.cmd_output("lsblk")
        for line in _output.split("\n"):
            temp = line.split()
            if len(temp) == 6:
                name = temp[0]
                size = temp[3]
                readonly = temp[4]
                if name not in retdict:
                    retdict[name] = {"size": size, "readonly": readonly}

    return retdict

@pytest.mark.standvm_accept
@pytest.mark.parametrize("readonly", [True, False])
def test_standvm_virtio_blk_configuration(test_session_root_path, standvm, readonly):
    """
    Test virtio-blk configuration:

    1) Generate a temp disk
    2) Configure temp disk read_only and Add it to test_vm
    3) Launch to test_vm and get block information
    4) Assert temp disk readonly as expect
    """
    test_vm = standvm
    temp_disk = os.path.join(test_session_root_path, "test_image")
    run("rm -rf %s; dd if=/dev/zero of=%s bs=1M count=16" %
        (temp_disk, temp_disk), shell=True, check=True)
    test_vm.add_drive(path_on_host=temp_disk, read_only=readonly)
    test_vm.launch()
    _cmd = "ls /sys/bus/virtio/drivers/virtio_blk/ | grep -c virtio[0-9]*"
    _, output = test_vm.serial_cmd(_cmd)

    # check readonly
    _cmd = "lsblk | grep vdb | awk '{print $5}'"
    _, output = test_vm.serial_cmd(_cmd)
    expect_ro = 1 if readonly else 0
    assert int(output.split('\n')[0].strip()) == expect_ro
