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
"""Test microvm cmdline"""

import os
import logging
import platform
from subprocess import run
from subprocess import PIPE
from subprocess import getstatusoutput
import pytest
import utils.exception
import utils.utils_common
from utils.config import CONFIG
from utils.utils_logging import TestLog

LOG = TestLog.get_global_log()

def _get_corefilesize(vm_pid, dump_guestcore):
    """
    Check corefile size

    Args:
        dump_guestcore: enable the capability, when it is true

    Returns:
        corefilesize
    """
    (status, output) = getstatusoutput("coredumpctl -r info %s" % vm_pid)
    if status == 0:
        (status, output) = getstatusoutput("coredumpctl -r info %s | grep Storage | head -1" % vm_pid)
        if "truncated" in output and not dump_guestcore:
            logging.error("corefile is truncated, test failed!")
            assert False
        corefile = str(output).split()[1]
        (status, output) = getstatusoutput("ls -s %s | awk '{print $1}'" % corefile)
        assert status == 0
    else:
        (status, output) = getstatusoutput("cat /proc/sys/kernel/core_pattern")
        assert status == 0
        coredirectory = os.path.dirname(str(output))
        (status, output) = getstatusoutput("ls -s %s | awk '/_%s_/' | awk '{print $1}'" % (coredirectory, vm_pid))
        assert status == 0
    return  output

@pytest.mark.acceptance
def test_microvm_with_unsupported_param():
    """
    1) Launch microvm with a unsupported param.
    2) Expect run with error code, but not panic.
    """
    _cmd = "%s --unsupport" % CONFIG.stratovirt_microvm_bin
    try:
        _result = run(_cmd, shell=True, capture_output=True, check=False)
    except TypeError:
        _result = run(_cmd, shell=True, stderr=PIPE, stdout=PIPE, check=False)
    assert 'panicked' not in str(_result.stderr, encoding='utf-8')
    assert _result.returncode != 0


@pytest.mark.acceptance
def test_microvm_start_with_initrd(test_microvm_with_initrd):
    """
    Use -initrd to replace -drive for boot device:

    1) Set vcpu_count to 4.
    2) Launch to test_vm by "-initrd".
    3) Assert vcpu_count is 4.
    """
    test_vm = test_microvm_with_initrd
    test_vm.basic_config(vcpu_count=4, vnetnums=0)
    test_vm.launch()
    rsp = test_vm.query_cpus()
    assert len(rsp.get("return", [])) == 4
    rsp = test_vm.query_hotpluggable_cpus()
    logging.debug(rsp)
    test_vm.shutdown()



@pytest.mark.acceptance
def test_microvm_with_pidfile(microvm):
    """Test microvm start with pidfile"""
    test_vm = microvm
    test_vm.basic_config(withpid=True)
    test_vm.launch()
    assert test_vm.get_pid() == test_vm.get_pid_from_file()
    test_vm.shutdown()
    test_vm.launch()
    assert test_vm.get_pid() == test_vm.get_pid_from_file()


@pytest.mark.acceptance
def test_microvm_without_daemonize(microvm):
    """Test microvm without daemonize"""
    test_vm = microvm
    test_vm.basic_config(daemon=False, vcpu_count=4)
    test_vm.launch()
    rsp = test_vm.query_cpus()
    assert len(rsp.get("return", [])) == 4
    test_vm.stop()
    test_vm.event_wait(name='STOP')
    test_vm.cont()
    test_vm.event_wait(name='RESUME')


@pytest.mark.acceptance
def test_microvm_freeze(microvm):
    """
    Test freeze a normal microvm's CPU at startup:

    1) Set CPU freeze.
    2) Launch to test_vm but Login Timeout.
    3) Resume test_vm successfully.
    """
    test_vm = microvm
    test_vm.basic_config(freeze=True)
    try:
        test_vm.launch()
    except utils.exception.LoginTimeoutError:
        test_vm.qmp_reconnect()
        test_vm.cont()
        test_vm.event_wait(name='RESUME')
        test_vm.launch()
        ret, _ = test_vm.serial_cmd("ls")
        assert ret == 0



@pytest.mark.acceptance
@pytest.mark.parametrize("dump_guestcore", [True, False])
def test_microvm_with_dump_guestcore(microvm, dump_guestcore):
    """
    Test microvm without memdump:

    1) Set dump_guest_core configure up.
    2) Launch to test_vm.
    3) Get core file size as expect.

    Args:
        dump_guestcore: enable the capability, when it is true
    """
    test_vm = microvm
    test_vm.basic_config(_machine="microvm", dump_guest_core=dump_guestcore)
    test_vm.launch()
    vm_pid = test_vm.pid
    test_vm.destroy(signal=6)
    output = _get_corefilesize(vm_pid, dump_guestcore)
    logging.debug("coredump size is %s", output)
    assert (int(output) < 102400 or dump_guestcore)


@pytest.mark.acceptance
@pytest.mark.parametrize("mem_size", [2 * 1024])
def test_lightvm_mem_hugepage(microvm, mem_size):
    """
    Test lightvm with hugepage configuration for guest RAM.
    Test lightvm with hugepages by set memory backend.

    1) Prepare environment: mount hugetlbfs and set count of hugepages.
    2) Launch vm and test the count of remaining free hugepages,
       the count must less that the origin count.
    3) Recover the environment: umount hugetlbfs if necessary.
    """
    default_hp_path = "/dev/hugepages/"

    def set_host_hugepages(vm_mem_size):
        """Prepare hugepage-relevant settings on host."""

        mount_dir = None
        is_mounted = True

        output = run("mount -l | grep hugetlbfs", shell=True, capture_output=True, check=False).stdout.strip()
        out = output.decode('utf-8').split(" ")
        if len(out) > 2:
            mount_dir = out[2]

        if not mount_dir:
            is_mounted = False
            mount_dir = default_hp_path
            run("mount -t hugetlbfs hugetlbfs %s" % mount_dir, shell=True, check=False)

        output = run("cat /proc/meminfo | grep Hugepagesize", shell=True,
                     capture_output=True, check=False).stdout.strip()
        hugepage_size = output.decode('utf-8').lstrip("Hugepagesize:").rstrip("kB").strip()

        output = run("cat /proc/meminfo | grep HugePages_Total", shell=True,
                     capture_output=True, check=False).stdout.strip()
        _old_hugepages_count = output.decode('utf-8').lstrip("HugePages_Total:").rstrip("kB").strip()
        output = run("cat /proc/meminfo | grep HugePages_Free", shell=True,
                     capture_output=True, check=False).stdout.strip()
        _old_hugepages_free = output.decode('utf-8').lstrip("HugePages_Free:").rstrip("kB").strip()

        target_hugepages_count = int(_old_hugepages_count) + vm_mem_size / (int(hugepage_size) * 1024) + 1
        run("sysctl vm.nr_hugepages=%s" % int(target_hugepages_count), shell=True, check=False)

        # Make sure that setting hugepage count is successful, otherwise recover environment and exit.
        output = run("cat /proc/meminfo | grep HugePages_Total", shell=True,
                     capture_output=True, check=False).stdout.strip()
        new_hugepages_count = output.decode('utf-8').lstrip("HugePages_Total:").rstrip("kB").strip()
        if int(new_hugepages_count) < target_hugepages_count:
            recover_host_hugepages(mount_dir, _old_hugepages_count, is_mounted)
            pytest.skip("No enough memory left in host to launch VM with hugepages")

        return mount_dir, _old_hugepages_count, _old_hugepages_free, is_mounted

    def recover_host_hugepages(_old_mount_dir, _old_hugepages_count, is_mounted):
        """Recover hugepage-relevant settings on host."""

        run("sysctl vm.nr_hugepages=%s" % _old_hugepages_count, shell=True, check=False)
        if not is_mounted:
            run("umount hugetlbfs", shell=True, check=False)

    mount_dir, old_huge_cnt, old_huge_free, is_mounted = set_host_hugepages(vm_mem_size=mem_size)

    test_vm = microvm
    test_vm.basic_config(mem_size=mem_size, mem_path=mount_dir)
    test_vm.launch()

    # Check remaining hugepages count on host.
    output = run("cat /proc/meminfo | grep HugePages_Free", shell=True,
                 capture_output=True, check=False).stdout.strip()
    remain_free_count = output.decode('utf-8').lstrip("HugePages_Free:").rstrip("kB").strip()

    check_failed = False
    if int(remain_free_count) < int(old_huge_free):
        check_failed = True

    test_vm.shutdown()
    recover_host_hugepages(mount_dir, old_huge_cnt, is_mounted)
    if check_failed:
        pytest.xfail(reason="Reduction of hugepages is abnormal: current free cnt %d, old free cnt %d" %
                            (int(remain_free_count), int(old_huge_free)))
