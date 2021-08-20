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
"""Test microvm concurrency"""

import logging
import threading
import pytest

@pytest.mark.system
def test_microvm_concurrency(microvms):
    """
    Test multi microvms start:

    1) Set each VM vcpu_count = 4, then launch it and confirm vcpu count is 4.
    And increase _succ_sum.
    2) Execute step 1 concurrency by threads.
    3) Confirm each VM is execute successffully by _succ_sum

    Note: You can modify CONCURRENT_QUANTITY tag in config/config.ini to set vm quantity.
    """

    def _check_vm_life(testvm):
        test_vm = testvm
        test_vm.basic_config(vcpu_count=4, vnetnums=0)
        test_vm.launch()
        rsp = test_vm.query_cpus()
        assert len(rsp.get("return", [])) == 4
        rsp = test_vm.query_hotpluggable_cpus()
        logging.debug("vm %s return: %s", test_vm.name, rsp)
        test_vm.shutdown()

    test_ths = []
    for testvm in microvms:
        vm_test_th = threading.Thread(target=_check_vm_life, args=(testvm,))
        test_ths.append(vm_test_th)

    for testthr in test_ths:
        testthr.start()

    for testthr in test_ths:
        testthr.join()
