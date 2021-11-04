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
"""Test standvm iothread"""

import pytest

@pytest.mark.standvm_accept
def test_standvm_iothread_iops(test_standvm_with_iothread):
    """
    Test standvm with net iothread, block iothread and iops
    configure: standvm_iothread.json
    """
    testvm = test_standvm_with_iothread
    testvm.basic_config(net_iothread='iothread1')
    testvm.launch()