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
"""Test microvm timer"""

from subprocess import run
from subprocess import PIPE
import pytest

@pytest.mark.acceptance
def test_microvm_time(microvm):
    """
    Test microvm time:

    1) Launch to test_vm
    2) Get guest date and host date
    3) Compare them
    """
    test_vm = microvm
    test_vm.launch()
    _, guest_date = test_vm.serial_cmd("date +%s")
    host_date = run("date +%s", shell=True, check=True,
                    stdout=PIPE).stdout.decode('utf-8')
    #The difference depends on machine performance
    assert abs(int(guest_date) - int(host_date)) < 3
