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
"""Test standvm vhost vsock"""

import os
import time
import logging
from subprocess import run
from threading import Thread
import pytest
# Constants for nc-vsock setup and usage
NC_VSOCK_DIR = '/tmp/nc-vsock'
NC_VSOCK_CMD = os.path.join(NC_VSOCK_DIR, 'nc-vsock')
NC_VSOCK_SRV_OUT = os.path.join(NC_VSOCK_DIR, "server_out.txt")
NC_VSOCK_CLI_TXT = "/tmp/client_in.txt"
VSOCK_PORT = 1234
BLOB_SIZE = 2000


def _check_vsock_enable(standvm):
    """Check vhost vsock device in Guest"""
    _cmd = "ls /dev/vsock"
    status, _ = standvm.serial_cmd(_cmd)
    if status != 0:
        status1, _ = standvm.serial_cmd("modprobe vhost_vsock")
        if status1 != 0:
            logging.debug("vsock can't enable in guest, ignore to test")
            return False

    status, _ = standvm.serial_cmd(_cmd)
    assert  status == 0
    return True


def _start_vsock_server_in_guest(standvm):
    """Start vsock server in guest"""
    _cmd = "%s -l %s > %s" % (NC_VSOCK_CMD, VSOCK_PORT, NC_VSOCK_SRV_OUT)
    try:
        ssh_session = standvm.create_ssh_session()
        _ = ssh_session.cmd(_cmd, timeout=10, internal_timeout=10)
    finally:
        if ssh_session is not None:
            ssh_session.close()


def _write_from_host_to_guest(nc_vsock_path, cid):
    """Write data from host to guest"""
    msg = "message from client"
    _cmd = "echo %s > %s" % (msg, NC_VSOCK_CLI_TXT)
    logging.debug("start to run %s", _cmd)
    run(_cmd, shell=True, check=False)
    _cmd = "%s %d %s < %s" % (nc_vsock_path, int(cid), VSOCK_PORT, NC_VSOCK_CLI_TXT)
    logging.debug("start to run %s", _cmd)
    output = run(_cmd, shell=True, check=False).stdout
    logging.debug(output)
    return msg


def _get_recv_data_from_guest(standvm):
    _cmd = "cat %s" % NC_VSOCK_SRV_OUT
    try:
        ssh_session = standvm.create_ssh_session()
        _, output = ssh_session.cmd_status_output(_cmd)
        logging.debug("recv data from guest is %s", output.strip())
        return output.strip()
    finally:
        if ssh_session is not None:
            ssh_session.close()

@pytest.mark.acceptance
def test_standvm_vhost_vsock(standvm, nc_vsock_path, test_session_root_path):
    """Test vhost vsock device"""
    test_vm = standvm
    test_vm.basic_config(vsocknums=1)
    test_vm.launch()

    # check vhost vsock device
    if not _check_vsock_enable(test_vm):
        pytest.skip("vhost-vsock init failed, skip this testcase")

    # generate the blob file.
    blob_path = os.path.join(test_session_root_path, "vsock-test.blob")
    run("rm -rf %s; dd if=/dev/urandom of=%s bs=1 count=%d" %
        (blob_path, blob_path, BLOB_SIZE), shell=True, check=True)
    vm_blob_path = "/tmp/nc-vsock/test.blob"

    #  set up a tmpfs drive on the guest, then we can copy the blob file there.
    session = test_vm.create_ssh_session()
    cmd = "mkdir -p /tmp/nc-vsock"
    cmd += " && mount -t tmpfs tmpfs -o size={} /tmp/nc-vsock".format(
        BLOB_SIZE + 1024*1024
    )
    status, _ = session.cmd_status_output(cmd)
    session.close()
    assert status == 0

    # copy nc-vsock tool and the blob file to the guest.
    test_vm.scp_file(nc_vsock_path, NC_VSOCK_CMD)
    test_vm.scp_file(blob_path, vm_blob_path)

    # start vsock server in guest
    server = Thread(target=_start_vsock_server_in_guest, args=(test_vm,))
    server.start()
    time.sleep(5)

    # write data from host to guest
    msg = _write_from_host_to_guest(nc_vsock_path, test_vm.vsock_cid[0])

    server.join(10)
    if server.is_alive():
        logging.error("The server thread is still running in the guest")
    msg_recv = _get_recv_data_from_guest(test_vm)
    assert msg == msg_recv
