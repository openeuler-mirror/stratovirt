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
"""Test microvm api"""

import logging
import pytest

@pytest.mark.acceptance
def test_api_lifecycle(microvm):
    """
    Test a normal microvm start:

    1) Set vcpu_count to 4.
    2) Launch to test_vm.
    3) Assert vcpu_count is 4.
    """
    test_vm = microvm
    test_vm.basic_config(vcpu_count=4)
    test_vm.launch()
    rsp = test_vm.query_cpus()
    assert len(rsp.get("return", [])) == 4
    test_vm.shutdown()
