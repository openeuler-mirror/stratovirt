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
from enum import Enum
from enum import auto
import pytest
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='/var/log/pytest.log',
                    level=logging.DEBUG, format=LOG_FORMAT)

class CpuVendor(Enum):
    """CPU vendors enum."""

    AMD = auto()
    INTEL = auto()


def _get_cpu_vendor():
    cif = open('/proc/cpuinfo', 'r')
    host_vendor_id = None
    while True:
        line = cif.readline()
        if line == '':
            break
        matchoutput = re.search("^vendor_id\\s+:\\s+(.+)$", line)
        if matchoutput:
            host_vendor_id = matchoutput.group(1)
    cif.close()
    assert host_vendor_id is not None

    if host_vendor_id == "AuthenticAMD":
        return CpuVendor.AMD
    return CpuVendor.INTEL


def _check_guest_cmd_output(microvm, guest_cmd, expected_header,
                            expected_separator,
                            expected_key_value_store):
    status, output = microvm.serial_cmd(guest_cmd)

    assert status == 0
    for line in output.splitlines():
        line = line.strip()
        if line != '':
            # all the keys have been matched. Stop.
            if not expected_key_value_store:
                break

            # try to match the header if needed.
            if expected_header not in (None, ''):
                if line.strip() == expected_header:
                    expected_header = None
                continue

            # see if any key matches.
            # we use a try-catch block here since line.split() may fail.
            try:
                [key, value] = list(
                    map(lambda x: x.strip(), line.split(expected_separator)))
            except ValueError:
                continue

            if key in expected_key_value_store.keys():
                assert value == expected_key_value_store[key], \
                    "%s does not have the expected value" % key
                del expected_key_value_store[key]

        else:
            break

    assert not expected_key_value_store, \
        "some keys in dictionary have not been found in the output: %s" \
        % expected_key_value_store


def _check_cpu_topology(test_microvm, expected_cpu_count,
                        expected_threads_per_core,
                        expected_cores_per_socket,
                        expected_cpus_list):
    expected_cpu_topology = {
        "CPU(s)": str(expected_cpu_count),
        "On-line CPU(s) list": expected_cpus_list,
        "Thread(s) per core": str(expected_threads_per_core),
        "Core(s) per socket": str(expected_cores_per_socket),
        "Socket(s)": str(int(expected_cpu_count / expected_cores_per_socket / expected_threads_per_core)),
    }

    _check_guest_cmd_output(test_microvm, "lscpu", None, ':',
                            expected_cpu_topology)


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

    if 'x86_64' in platform.machine():
        _check_cpu_topology(test_vm, 128, 1, 128, "0-127")
    else:
        _check_cpu_topology(test_vm, 128, 2, 2, "0-127")


@pytest.mark.skipif("platform.machine().startswith('aarch64')")
@pytest.mark.acceptance
def test_brand_string(microvm):
    """Ensure good formatting for the guest band string.

    * For Intel CPUs, the guest brand string should be:
        Intel(R) Xeon(R) Processor @ {host frequency}
    where {host frequency} is the frequency reported by the host CPUID
    (e.g. 4.01GHz)
    * For AMD CPUs, the guest brand string should be:
        AMD EPYC
    * For other CPUs, the guest brand string should be:
        ""
    """
    cif = open('/proc/cpuinfo', 'r')
    host_brand_string = None
    while True:
        line = cif.readline()
        if line == '':
            break
        matchoutput = re.search("^model name\\s+:\\s+(.+)$", line)
        if matchoutput:
            host_brand_string = matchoutput.group(1)
    cif.close()
    assert host_brand_string is not None

    test_vm = microvm

    test_vm.basic_config(vcpu_count=1)
    test_vm.launch()

    guest_cmd = "cat /proc/cpuinfo | grep 'model name' | head -1"
    status, output = test_vm.serial_cmd(guest_cmd)
    assert status == 0

    line = output.splitlines()[0].rstrip()
    matchoutput = re.search("^model name\\s+:\\s+(.+)$", line)
    assert matchoutput
    guest_brand_string = matchoutput.group(1)
    assert guest_brand_string

    cpu_vendor = _get_cpu_vendor()
    expected_guest_brand_string = ""
    if cpu_vendor == CpuVendor.AMD:
        expected_guest_brand_string += "AMD EPYC"
    elif cpu_vendor == CpuVendor.INTEL:
        expected_guest_brand_string = host_brand_string

    assert guest_brand_string == expected_guest_brand_string

