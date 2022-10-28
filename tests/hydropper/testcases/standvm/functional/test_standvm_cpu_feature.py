# Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

"""Test standvm PMU"""
import time
import logging
import pytest

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='/var/log/pytest.log', level=logging.DEBUG, format=LOG_FORMAT)

@pytest.mark.skipif("platform.machine().startswith('x86_64')")
@pytest.mark.acceptance
def test_standvm_pmu(standvm):
    """
    Test PMU feature for standvm.

    steps:
    1) launch standvm with argument: "-cpu pmu=on".
    2) Check PMU presence.
    """
    test_vm = standvm
    test_vm.basic_config(cpu_features="pmu=on")
    test_vm.launch()
    #PMU events available?
    guest_cmd = "perf list | grep cache-misses"
    status, output = test_vm.serial_cmd(guest_cmd)
    assert status == 0

    #PMU interrupt available?
    guest_cmd = "cat /proc/interrupts | grep -i 'pmu' | head -1"
    status, output = test_vm.serial_cmd(guest_cmd)
    assert status == 0
