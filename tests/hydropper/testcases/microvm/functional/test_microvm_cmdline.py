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

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='/var/log/pytest.log', level=logging.DEBUG, format=LOG_FORMAT)

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
        (status, output) = getstatusoutput("ls -s %s | awk '/-%s-/' | awk '{print $1}'" % (coredirectory, vm_pid))
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
def test_microvm_with_json(microvm):
    """Test microvm start with json"""
    test_vm = microvm
    test_vm.basic_config(with_json=True)
    test_vm.launch()
    test_vm.query_cpus()
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
@pytest.mark.parametrize("with_seccomp", [True, False])
@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="psyscall tools fail to run on aarch64."
)
def test_microvm_with_seccomp(microvm, with_seccomp):
    """
    Test microvm with seccomp:

    1) Set seccomp up.
    2) Launch to test_vm.
    3) Excute some system call that not in seccomp.
    4) seccomp will shutdown VM

    Args:
        with_seccomp: secure computing mode
    """
    test_vm = microvm
    test_vm.basic_config(seccomp=with_seccomp)
    test_vm.launch()
    vm_pid = test_vm.pid

    # Get psyscall
    try:
        path = os.path.realpath(os.path.dirname(__file__))
        psyscall_path = "{}/{}".format(path, "psyscall")
        run(
            "git clone https://gitee.com/EulerRobot/psyscall.git %s"
            % psyscall_path,
            shell=True,
            check=True
            )
        run("cd %s && make" % psyscall_path, shell=True, check=True)

        # bad syscall
        _cmd = "%s/psyscall %s dup2 3 4" % (psyscall_path, vm_pid)
        logging.debug("execute command %s", _cmd)
        status, output = getstatusoutput(_cmd)
        logging.debug("bad syscall output: %s", output)
        assert status == 0
        if with_seccomp:
            test_vm.wait_pid_exit()
    finally:
        utils.utils_common.remove_existing_dir(psyscall_path)
