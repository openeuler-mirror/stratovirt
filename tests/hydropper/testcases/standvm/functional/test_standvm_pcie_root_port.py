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
"""Test standvm pcie root port"""

import pytest

@pytest.mark.standvm_accept
def test_standvm_pcie_root_port(standvm):
    """
    Test standvm pcie root port
    """
    testvm = standvm
    testvm.basic_config(pcie_root_port_num=4)
    testvm.config_pcie_root_port("net", True)
    testvm.config_pcie_root_port("block", True)
    testvm.config_pcie_root_port("vsock", True)
    testvm.config_pcie_root_port("balloon", True)
    testvm.launch()