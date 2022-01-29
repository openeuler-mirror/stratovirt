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
"""Test standvm api"""

import logging
from typing import Pattern
import pytest
import re
from subprocess import run
from utils.utils_common import get_timestamp
from utils.utils_logging import TestLog

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="/var/log/pytest.log", level=logging.DEBUG, format=LOG_FORMAT)
LOG = TestLog.get_global_log()

@pytest.mark.acceptance
def test_standvm_snapshot(standvm):
    """
    Test standvm snapshot
    """
    test_vm = standvm
    test_vm.launch()
    test_vm.stop()
    test_vm.migrate(uri='file:/var/tmp/snapshot_template')
    test_vm.shutdown()

@pytest.mark.acceptance
def test_standvm_quickstart(standvm):
    """
    Test a standvm quickstart from snapshot_template and
    this testcases must execute after test_standvm_snapshot.
    """
    test_vm = standvm
    temp_log_path = "/var/tmp/test_standvm_quickstart.log"
    run("rm -r %s; touch %s" % (temp_log_path, temp_log_path), shell=True, check=False)
    test_vm.basic_config(quickstart_incoming='file:/var/tmp/snapshot_template', logpath=temp_log_path)
    test_vm.launch()

    start_time = 0
    startover_time = 0
    with open(temp_log_path, 'r') as logfile:
        start_vcpu = 0
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{9})'
        for line in logfile.readlines():
            if ":INFO: Vcpu" in line:
                start_vcpu += 1
            if ":INFO: VmConfig" in line:
                start_match = re.match(pattern, line)
                assert start_match is not None
                LOG.debug("start time is %s", start_match.group(0))
                start_time = get_timestamp(start_match.group(0))
            # waiting for the last vcpu started.
            if start_vcpu == test_vm.vcpus:
                end_match = re.match(pattern, line)
                assert end_match is not None
                LOG.debug("startover time is %s", end_match.group(0))
                startover_time = get_timestamp(end_match.group(0))

    assert startover_time != start_time != 0
    quickstart_time = startover_time - start_time
    LOG.debug("quickstart_time is %s", quickstart_time)
    assert quickstart_time < 0.05

    test_vm.shutdown()
