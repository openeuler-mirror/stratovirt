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
"""conftest"""

import os
import uuid
import shutil
import tempfile
import time
from subprocess import run
import pytest
from virt.microvm import MicroVM
from monitor.monitor_thread import MonitorThread
from utils.config import CONFIG

TIMESTAMP = time.strftime('%Y%m%d_%H%M%S', time.localtime(time.time()))
SESSION_PATH = os.path.join(CONFIG.test_dir, TIMESTAMP)
CONFIG.test_session_root_path = SESSION_PATH
if not os.path.exists(CONFIG.test_session_root_path):
    os.makedirs(CONFIG.test_session_root_path)

@pytest.fixture(autouse=True, scope='session')
def test_session_root_path():
    """Create a new test path in each session"""
    created_test_session_root_path = False

    delete_test_session = CONFIG.delete_test_session
    monitor_thread = MonitorThread()
    monitor_thread.start()
    if "stratovirt" in CONFIG.vmtype:
        _cmd = "cp %s %s.bak" % (CONFIG.stratovirt_rootfs, CONFIG.stratovirt_rootfs)
        run(_cmd, shell=True, check=True)

    yield CONFIG.test_session_root_path

    if "stratovirt" in CONFIG.vmtype:
        _cmd = "cp %s.bak %s" % (CONFIG.stratovirt_rootfs, CONFIG.stratovirt_rootfs)
        run(_cmd, shell=True, check=True)
    monitor_thread.stop()
    monitor_thread.join()
    if delete_test_session and created_test_session_root_path:
        shutil.rmtree(CONFIG.test_session_root_path)


@pytest.fixture
def test_session_tmp_path(test_session_root_path):
    """Generate a temporary directory on Setup. Remove on teardown."""
    # pylint: disable=redefined-outer-name
    # The pytest.fixture triggers a pylint rule.

    temp_path = tempfile.mkdtemp(prefix=test_session_root_path)
    yield temp_path
    shutil.rmtree(temp_path)


def init_microvm(root_path, bin_path=CONFIG.stratovirt_microvm_bin, **kwargs):
    """Auxiliary to init a microvm"""
    vm_uuid = str(uuid.uuid4())
    testvm = MicroVM(root_path, "microvm", vm_uuid,
                     bin_path=bin_path,
                     **kwargs
                     )

    return testvm


def init_microvm_with_json(root_path, vm_config_json, vmtag):
    """Init a microvm from a json file"""
    vm_uuid = str(uuid.uuid4())
    vmname = "microvm" + "_" + vmtag
    testvm = MicroVM(root_path, vmname, vm_uuid, bin_path=CONFIG.stratovirt_microvm_bin,
                     vmconfig=vm_config_json)
    return testvm


def _gcc_compile(src_file, output_file):
    """Build a source file with gcc."""
    compile_cmd = 'gcc {} -o {} -O3'.format(
        src_file,
        output_file
    )
    run(
        compile_cmd,
        shell=True,
        check=True
    )


@pytest.fixture()
def nc_vsock_path(test_session_root_path):
    """Wget nc-vsock.c and build a nc-vsock app."""
    # pylint: disable=redefined-outer-name
    # The pytest.fixture triggers a pylint rule.
    path = os.path.realpath(os.path.dirname(__file__))
    nc_path = "{}/{}".format(
        path,
        "nc-vsock.c"
    )
    if not os.path.exists(nc_path):
        run(
            "wget https://gitee.com/EulerRobot/nc-vsock/raw/master/nc-vsock.c -O %s"
            % nc_path,
            shell=True,
            check=True
        )
    nc_vsock_bin_path = os.path.join(
        test_session_root_path,
        'nc-vsock'
    )
    _gcc_compile(
        'nc-vsock.c',
        nc_vsock_bin_path
    )
    yield nc_vsock_bin_path


@pytest.fixture()
def microvm(test_session_root_path):
    """Instantiate a microvm"""
    # pylint: disable=redefined-outer-name
    # The pytest.fixture triggers a pylint rule.
    testvm = init_microvm(test_session_root_path)
    yield testvm
    testvm.kill()


@pytest.fixture()
def microvm_with_tcp(test_session_root_path):
    """Init a microvm"""
    # pylint: disable=redefined-outer-name
    # The pytest.fixture triggers a pylint rule.
    testvm = init_microvm(test_session_root_path, socktype='tcp')
    yield testvm
    testvm.kill()


@pytest.fixture()
def microvms(test_session_root_path):
    """Init multi microvms"""
    # pylint: disable=redefined-outer-name
    # The pytest.fixture triggers a pylint rule.
    micro_vms = []
    for index in range(CONFIG.concurrent_quantity):
        tempvm = init_microvm_with_json(test_session_root_path,
                                        CONFIG.get_microvm_by_tag('initrd'),
                                        "initrd%d" % index)
        micro_vms.append(tempvm)

    yield micro_vms
    for tempvm in micro_vms:
        tempvm.kill()


@pytest.fixture()
def directvm(request):
    """Get vm fixture value"""
    return request.getfixturevalue(request.param)


TEST_MICROVM_CAP_FIXTURE_TEMPLATE = (
    "@pytest.fixture()\n"
    "def test_microvm_with_CAP(test_session_root_path):\n"
    "    microvm = init_microvm_with_json(test_session_root_path,\n"
    "                                     CONFIG.get_microvm_by_tag(\"CAP\"), \"CAP\")\n"
    "    yield microvm\n"
    "    microvm.kill()"
)

for capability in CONFIG.list_microvm_tags():
    test_microvm_cap_fixture = (
        TEST_MICROVM_CAP_FIXTURE_TEMPLATE.replace('CAP', capability)
    )

    exec(test_microvm_cap_fixture)
