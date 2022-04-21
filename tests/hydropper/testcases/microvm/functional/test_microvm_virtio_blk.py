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
"""Test microvm virtio block"""

import json
import os
import logging
from subprocess import run
from subprocess import PIPE
import pytest
from utils.config import CONFIG

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
        _output = json.loads(test_vm.ssh_session.cmd_output("lsblk -J"))
        blockdevices = _output.get("blockdevices", [])
        for dic in blockdevices:
            mountpoints = dic.get("mountpoints", [])
            if len(mountpoints) != 0 and None in mountpoints:
                name = dic.get("name", "")
                size = dic.get("size", "")
                readonly = dic.get("ro", None)
                if size != "0B" and name not in retdict:
                    retdict[name] = {"size": size, "readonly": readonly}

    return retdict

@pytest.mark.acceptance
@pytest.mark.parametrize("readonly", [True, False])
def test_microvm_virtio_blk_configuration(test_session_root_path, microvm, readonly):
    """
    Test virtio-blk configuration:

    1) Generate a temp disk
    2) Configure temp disk read_only and Add it to test_vm
    3) Launch to test_vm and get block information
    4) Assert temp disk readonly as expect
    """
    test_vm = microvm
    temp_disk = os.path.join(test_session_root_path, "test_image")
    run("rm -rf %s; dd if=/dev/zero of=%s bs=1M count=16" %
        (temp_disk, temp_disk), shell=True, check=True)
    test_vm.add_drive(path_on_host=temp_disk, read_only=readonly)
    test_vm.launch()
    _cmd = "ls /sys/bus/virtio/drivers/virtio_blk/ | grep -c virtio[0-9]*"
    _, output = test_vm.serial_cmd(_cmd)
    virtio_blk_number_in_guest = int(output.split('\n')[-2].strip())

    # check readonly
    _cmd = "lsblk | grep vdb | awk '{print $5}'"
    _, output = test_vm.serial_cmd(_cmd)
    expect_ro = 1 if readonly else 0
    assert int(output.split('\n')[0].strip()) == expect_ro


@pytest.mark.system
@pytest.mark.parametrize("testtimes", [1, 10])
def test_microvm_virtio_blk_at_dt(test_session_root_path, microvm, testtimes):
    """
    Test virtio-blk hotplug and unplug:

    1) Generate 3 temp disks and add them to test_vm.
    2) Assert disks' name and size as expect.
    3) Delete temp disks from test_vm.
    4) Assert temp disks are deleted.
    """
    test_vm = microvm
    test_vm.launch()
    disknum = 3
    disklist = []
    for index in range(disknum):
        temp_disk = os.path.join(test_session_root_path, "test_image%d" % (index + 1))
        run("rm -rf %s; dd if=/dev/zero of=%s bs=1M count=16" %
            (temp_disk, temp_disk), shell=True, check=True)
        disklist.append(temp_disk)

    for _ in range(testtimes):
        index = 1
        for disk in disklist:
            test_vm.add_disk(disk, index=index)
            index += 1

        blkinfo = _get_lsblk_info(test_vm)
        logging.debug("blkinfo is %s", blkinfo)

        for devid in ["vdb", "vdc", "vdd"]:
            assert devid in blkinfo
            assert blkinfo[devid]["size"] == "16M"

        index = 1
        for disk in disklist:
            test_vm.del_disk(index=index)
            index += 1

        blkinfo = _get_lsblk_info(test_vm)
        for devid in ["vdb", "vdc", "vdd"]:
            assert devid not in blkinfo

@pytest.mark.acceptance
def test_microvm_virtio_blk_md5(test_session_root_path, microvm):
    """
    Test data consistency by md5sum:

    1) Generate a temp disk for test_vm and  launch.
    2) Mount the temp disk
    3) Touch a file and compute it md5sum.
    4) Umount the temp disk
    5) Exit the vm, mount the temp disk to hostos and compute the file md5sum again.
    6) Assert the same values twice
    """
    test_vm = microvm
    temp_disk = os.path.join(test_session_root_path, "test_image")
    run("rm -rf %s; dd if=/dev/zero of=%s bs=1M count=16" %
        (temp_disk, temp_disk), shell=True, check=True)
    test_vm.launch()
    test_vm.add_disk(temp_disk)

    blkinfo = _get_lsblk_info(test_vm)
    logging.debug("blkinfo is %s", blkinfo)

    format_cmd = "mkfs.ext4 /dev/vdb"
    test_vm.serial_cmd(format_cmd)

    mount_cmd = "mount /dev/vdb /mnt"
    test_vm.serial_cmd(mount_cmd)

    wirte_cmd = "touch /mnt/test_virtioblk.c"
    test_vm.serial_cmd(wirte_cmd)

    _cmd = "md5sum /mnt/test_virtioblk.c"
    _, md5 = test_vm.serial_cmd(_cmd)
    test_vm.serial_cmd("umount /mnt")

    test_vm.shutdown()
    try:
        run("mount %s /mnt" % temp_disk, shell=True, check=True)
        output = run("md5sum /mnt/test_virtioblk.c", shell=True, check=True,
                     stdout=PIPE).stdout.decode('utf-8')
        assert output == md5
    finally:
        run("umount /mnt", shell=True, check=False)
