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
"""Tests for the CPU topology emulation feature."""

import platform
import logging
import re
import json
from enum import Enum
from enum import auto
import pytest
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='/var/log/pytest.log',
                    level=logging.DEBUG, format=LOG_FORMAT)

def _parse_output(output):

    cpu_info = {}
    for item in output:
        cpu_info.update({item['field']: item['data']})
        cpu_info.update(_parse_output(item.get('children', [])))
    return cpu_info

def _get_cpu_info(test_microvm):

    output = json.loads(test_microvm.ssh_session.cmd_output("lscpu -J"))
    return _parse_output(output.get("lscpu", []))

def _check_cpu_topology(test_microvm, expected_cpu_count,
                        expected_threads_per_core,
                        expected_cores_per_socket,
                        expected_cpus_list):

    expected_cpu_topology = {
        "CPU(s):": str(expected_cpu_count),
        "On-line CPU(s) list:": expected_cpus_list,
        "Thread(s) per core:": str(expected_threads_per_core),
        "Core(s) per socket:": str(expected_cores_per_socket),
        "Socket(s):": str(int(expected_cpu_count / expected_cores_per_socket / expected_threads_per_core)),
    }

    cpu_info = _get_cpu_info(test_microvm)
    if "Core(s) per cluster:" in cpu_info.keys():
        expected_cpu_topology["Core(s) per cluster:"] = expected_cpu_topology["Core(s) per socket:"]
        del expected_cpu_topology["Core(s) per socket:"]
    if "Cluster(s):" in cpu_info.keys():
        expected_cpu_topology["Cluster(s):"] = expected_cpu_topology["Socket(s):"]
        del expected_cpu_topology["Socket(s):"]

    for key, expect_value in expected_cpu_topology.items():
        assert cpu_info[key] == expect_value


@pytest.mark.acceptance
def test_1vcpu_topo(microvm):
    """
    Check the cpu topo for a microvm with the specified config:

    1) Set vcpu_count=1, then launch.
    2) Check cpu topology with `lscpu` command.
    """
    test_vm = microvm
    test_vm.basic_config(vcpu_count=1)
    test_vm.launch()

    _check_cpu_topology(test_vm, 1, 1, 1, "0")


@pytest.mark.acceptance
def test_128vcpu_topo(microvm):
    """
    Check the CPUID for a microvm with the specified config:

    1) Set vcpu_count=128 then launch.
    2) Check cpu topology with `lscpu` command.
    """
    test_vm = microvm
    test_vm.basic_config(vcpu_count=128)
    test_vm.launch()

    _check_cpu_topology(test_vm, 128, 1, 128, "0-127")


@pytest.mark.skipif("platform.machine().startswith('aarch64')")
@pytest.mark.acceptance
def test_brand_string(microvm):
    """Ensure the guest band string is correct.
    """
    branch_string_format = "^model name\\s+:\\s+(.+)$"
    host_brand_string = None
    for line in open('/proc/cpuinfo', 'r'):
        matchoutput = re.search(branch_string_format, line)
        if matchoutput:
            host_brand_string = matchoutput.group(1)
    assert host_brand_string is not None

    test_vm = microvm

    test_vm.basic_config(vcpu_count=1)
    test_vm.launch()

    guest_cmd = "cat /proc/cpuinfo | grep 'model name' | head -1"
    status, output = test_vm.serial_cmd(guest_cmd)
    assert status == 0

    line = output.splitlines()[0].rstrip()
    matchoutput = re.search(branch_string_format, line)
    assert matchoutput
    guest_brand_string = matchoutput.group(1)
    assert guest_brand_string
    assert guest_brand_string == host_brand_string


@pytest.mark.skipif("platform.machine().startswith('x86_64')")
@pytest.mark.acceptance
def test_pmu(microvm):
    '''Test for PMU events and interrupt.
    '''
    test_vm = microvm 
    test_vm.basic_config(vcpu_count=1,cpu_features="pmu=on")
    test_vm.launch()

    #PMU events available?
    guest_cmd = "perf list | grep cache-misses"
    status, output = test_vm.serial_cmd(guest_cmd)
    assert status == 0

    #PMU interrupt available?
    guest_cmd = "cat /proc/interrupts | grep -i 'pmu' | head -1"
    status, output = test_vm.serial_cmd(guest_cmd)
    assert status == 0



