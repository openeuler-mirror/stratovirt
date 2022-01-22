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
"""Test standvm net"""

import logging
from subprocess import run
from subprocess import PIPE
import pytest
from utils.resources import NETWORKS

def _start_iperf_on_guest(standvm):
    """Start iperf in server mode on guest through serial session"""
    _cmd = "which iperf3"
    status, _ = standvm.serial_cmd(_cmd)
    if status != 0:
        logging.warning("iperf3 is not running, ignore to test")
        return False

    iperf_cmd = "iperf3 -sD -f KBytes\n"
    status, _ = standvm.serial_cmd(iperf_cmd)
    return not bool(status)


def _run_iperf_on_local(iperf_cmd):
    process = run(iperf_cmd, shell=True, stdout=PIPE, check=True)
    return process.stdout.decode("utf-8")


def _check_virtio_net_vectors(standvm, mqueue=1):
    _cmd = "lspci |grep -w Virtio"
    _, output = standvm.serial_cmd(_cmd)
    index = 0
    for line in output.splitlines():
        if "network" in line.strip():
            _check_vec_cmd = "grep -w virtio%d /proc/interrupts | wc -l" % index
            _status, _output = standvm.serial_cmd(_check_vec_cmd)
            vecs = int(_output.splitlines()[-2].strip())
            expect_vecs = 2 * mqueue + 1
            assert vecs == expect_vecs
        index += 1


@pytest.mark.standvm_accept
@pytest.mark.parametrize("vhost_type", [None])
def test_standvm_vnet_send_recv(standvm, vhost_type):
    """
    Test virtio-net send and recv:

    1) Set vhost_type and launch to test_vm
    2) Check nic numbers
    3) Test the vnet by ping
    4) Test TCP/UDP by iperf3
    """
    test_vm = standvm
    test_vm.basic_config(vhost_type=vhost_type)
    test_vm.launch()
    # check nic numbers
    _cmd = "ls /sys/bus/virtio/drivers/virtio_net/ | grep -c virtio[0-9]*"
    _, output = test_vm.serial_cmd(_cmd)
    logging.debug("virtio net output is %s", output)
    virtio_net_number_in_guest = int(output.split('\n')[-2].strip())
    assert virtio_net_number_in_guest == len(test_vm.get_interfaces_inner())

    # test ICMP (ping to vm)
    run("ping -c 2 %s" % test_vm.guest_ip, shell=True, check=True)
    status, output = test_vm.serial_cmd("ping -c 2 %s" % NETWORKS.ipaddr)
    assert status == 0
    # test TCP/UDP by iperf3
    if not _start_iperf_on_guest(test_vm):
        return

    iperf_cmd = "/usr/bin/iperf3 -c %s -t 5" % test_vm.guest_ip
    output = _run_iperf_on_local(iperf_cmd)
    logging.debug(output)

    iperf_cmd = "iperf3 -c %s -u -t 5" % test_vm.guest_ip
    output = _run_iperf_on_local(iperf_cmd)
    logging.debug(output)

    iperf_cmd = "iperf3 -c %s -t 5 -R" % test_vm.guest_ip
    output = _run_iperf_on_local(iperf_cmd)
    logging.debug(output)

    iperf_cmd = "iperf3 -c %s -u -t 5 -R" % test_vm.guest_ip
    output = _run_iperf_on_local(iperf_cmd)
    logging.debug(output)


@pytest.mark.system
def test_standvm_vnet_stop_cont(standvm):
    """
    Test virtio-net stop and continue, check vnet with mac:

    1) Launch to testvm
    2) Test the vnet by ping
    3) Restart vnet and execute step 2 again
    4) Stop and continue test_vm
    5) Execute step 2 again
    """
    test_vm = standvm
    test_vm.basic_config()
    test_vm.launch()
    # test ICMP (ping to vm)
    run("ping -c 2 %s" % test_vm.guest_ip, shell=True, check=True)
    status, _ = test_vm.serial_cmd("ping -c 2 %s" % NETWORKS.ipaddr)
    assert status == 0
    test_vm.serial_cmd("systemctl restart network")
    # test ICMP (ping to vm)
    run("ping -c 2 %s" % test_vm.guest_ip, shell=True, check=True)
    status, _ = test_vm.serial_cmd("ping -c 2 %s" % NETWORKS.ipaddr)
    assert status == 0
    test_vm.stop()
    test_vm.event_wait(name='STOP')
    test_vm.cont()
    test_vm.event_wait(name='RESUME')
    # test ICMP (ping to vm)
    run("ping -c 2 %s" % test_vm.guest_ip, shell=True, check=True)
    status, _ = test_vm.serial_cmd("ping -c 2 %s" % NETWORKS.ipaddr)
    assert status == 0


@pytest.mark.standvm_accept
@pytest.mark.parametrize("usemac", [True, False])
def test_standvm_with_multi_vnet(standvm, usemac):
    """
    Test standvm with multi vnet:

    1) Configure some vnets for test_vm
    2) Check mac address
    3) Check nic numbers
    4) Test vnets by ping
    5) Delete vnet from test_vm
    """
    test_vm = standvm
    test_vm.basic_config(vnetnums=2, withmac=usemac)
    test_vm.launch()
    # check mac address
    _cmd = "ls"
    for tap in test_vm.taps:
        _cmd += " && (ip addr | grep %s) " % tap["mac"]
    status = test_vm.serial_session.run_func("cmd_status", _cmd)
    expect_status = 0 if usemac else 1
    assert status == expect_status

    # check nic numbers
    _cmd = "ls /sys/bus/virtio/drivers/virtio_net/ | grep -c virtio[0-9]*"
    _, output = test_vm.serial_cmd(_cmd)
    virtio_net_number_in_guest = int(output.split('\n')[-2].strip())
    assert virtio_net_number_in_guest == len(test_vm.get_interfaces_inner())
    # test ICMP (ping to vm)
    run("ping -c 2 %s" % test_vm.guest_ip, shell=True, check=True)
    status, output = test_vm.serial_cmd("ping -c 2 %s" % NETWORKS.ipaddr)
    assert status == 0
