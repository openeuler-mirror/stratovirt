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
"""Test standvm vfio"""

import logging
import pytest
import platform
from subprocess import run
import utils.utils_common as utils
from utils.utils_logging import TestLog

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="/var/log/pytest.log", level=logging.DEBUG, format=LOG_FORMAT)
LOG = TestLog.get_global_log()

@pytest.mark.standvm_accept
@pytest.mark.parametrize("host_ip, net_type, bdf, pf_name",
                         [('9.13.7.139', '1822', '0000:03:00.0', 'enp3s0')])
@pytest.mark.skipif(
    platform.machine() == "x86_64",
    reason="this testcase need specified device"
)
def test_standvm_vfio_net(standvm, host_ip, net_type, bdf, pf_name):
    """
    Test standvm vfio with net.
    """
    vf_bdf = bdf.split('.')[0] + '.1'
    flag = False

    testvm = standvm
    utils.config_host_vfio(net_type=net_type, number='2', bdf=bdf)
    try:
        utils.check_vf(pf_name=pf_name)
        run("modprobe vfio-pci", shell=True, check=True)
        utils.rebind_vfio_pci(bdf=vf_bdf)
        testvm.basic_config(vfio=True, bdf=vf_bdf)
        testvm.launch()
        _cmd = "ip a | awk '{ print $2 }' | cut -d ':' -f 1"
        ret, output = testvm.serial_cmd(_cmd)
        output = output.split()
        for pf in output:
            ret, _ = testvm.serial_cmd("ethtool -i %s | grep hinic" % pf)
            if ret == 0:
                flag = True
                ret, _ = testvm.serial_cmd("dhclient %s" % pf)
                assert ret == 0
                ret, _ = testvm.serial_cmd("ping -c 2 %s" % host_ip)
                assert ret == 0
                break
        # if flag is False, means set vfio failed!
        assert flag == True
    finally:
        testvm.shutdown()
        utils.clean_vf(bdf=bdf)

@pytest.mark.standvm_accept
@pytest.mark.parametrize("bdf",[('0000:08:00.0')])
@pytest.mark.skipif(
    platform.machine() == "x86_64",
    reason="this testcase need specified device"
)
def test_standvm_vfio_ssd(standvm, bdf):
    """
    Test standvm vfio with ssd
    """
    testvm = standvm
    run("lspci | grep 'Non-Volatile memory'", shell=True, check=True)
    run("modprobe vfio-pci", shell=True, check=True)
    utils.rebind_vfio_pci(bdf=bdf)
    testvm.basic_config(vfio=True, bdf=bdf)
    testvm.launch()
    session = testvm.create_ssh_session()
    ret, _ = testvm.serial_cmd("lsblk | grep nvme")
    assert ret == 0
    ret, _ = session.cmd_status_output(cmd="mkfs.ext4 -F /dev/nvme0n1", timeout=180)
    assert ret == 0
    ret, _ = testvm.serial_cmd("mount /dev/nvme0n1 /mnt")
    assert ret == 0
    ret, _ = testvm.serial_cmd("cd /mnt && dd if=/dev/zero of=test bs=1M count=1000")
    assert ret == 0
    ret, _ = testvm.serial_cmd("rm test")
    assert ret == 0

    session.close()
    testvm.shutdown()
