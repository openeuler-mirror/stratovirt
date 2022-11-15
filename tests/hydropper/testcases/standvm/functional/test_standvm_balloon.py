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

"""Test standvm balloon"""
import time
import logging
import pytest

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='/var/log/pytest.log', level=logging.DEBUG, format=LOG_FORMAT)

@pytest.mark.acceptance
def test_standvm_balloon_fpr(standvm):
    """
    Test free page reporting of querying balloon

    steps:
    1) launch standvm with argument: "-balloon free-page-reporting=true".
    2) execute command "stress --vm 2 --vm-bytes 1G --vm-keep --timeout 20".
    3) compare rss between booted and fpr done.
    """
    test_vm = standvm
    test_vm.basic_config(mem_size=3072, balloon=True, free_page_reporting=True)
    test_vm.launch()

    rss_booted = test_vm.get_rss_with_status_check()
    test_vm.memory_stress()
    rss_fpr_done = test_vm.get_rss_with_status_check()
    assert rss_fpr_done - rss_booted < 20480
    test_vm.shutdown()

@pytest.mark.acceptance
def test_standvm_balloon_query(standvm):
    """
    Test qmp command of querying balloon

    steps:
    1) launch standvm with argument: "-balloon deflate-on-oom=true".
    2) query the memory size, and check if it is 2524971008 which is the default memory size.
    """
    test_vm = standvm
    test_vm.basic_config(balloon=True, deflate_on_oom=True)
    test_vm.launch()
    resp = test_vm.query_balloon()
    assert int(resp["return"]["actual"]) == int(standvm.memsize) * 1024 * 1024

@pytest.mark.acceptance
def test_standvm_balloon(standvm):
    """
    Test qmp command of setting balloon

    steps:
    1) launch standvm with argument: "-balloon deflate-on-oom=true".
    2) query memory size, and save.
    3) set memory size through balloon device to 814743552.
    4) wait 5 seconds for ballooning.
    5) check if the memory size is less than 2524971008.
    6) set memory size through balloon device to 2524971008, and wait.
    7) check if the memory size is 2524971008.
    Note that balloon device may not inflate as many as the given argument, but it can deflate until
    no page left in balloon device. Therefore, memory in step 5 is less than 2524971008,
    while that in step 7 equals 2524971008.
    """
    test_vm = standvm
    test_vm.basic_config(balloon=True, deflate_on_oom=True)
    test_vm.launch()
    resp = test_vm.query_balloon()
    ori = int(resp["return"]["actual"])

    resp = test_vm.balloon_set(value=814743552)
    time.sleep(5)
    test_vm.event_wait(name='BALLOON_CHANGED', timeout=2.0)
    resp = test_vm.query_balloon()
    set1 = int(resp["return"]["actual"])
    assert set1 < 2524971008

    resp = test_vm.balloon_set(value=2524971008)
    time.sleep(5)
    resp = test_vm.query_balloon()
    logging.debug(resp)
    set2 = int(resp["return"]["actual"])
    assert ori == set2

@pytest.mark.acceptance
def test_standvm_balloon_active(standvm):
    """
    Test qmp command of setting balloon

    steps:
    1) launch standvm without active balloon device.
    2) check if balloon device is activated.
    """
    test_vm = standvm
    test_vm.basic_config()
    test_vm.launch()
    resp = test_vm.query_balloon()
    assert resp["error"]["desc"] == "No balloon device has been activated"
    resp = test_vm.balloon_set(value=2524971008)
    assert resp["error"]["desc"] == "No balloon device has been activated"
