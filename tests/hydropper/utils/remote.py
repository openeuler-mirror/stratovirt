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
"""
Functions and classes used for logging into guests and transferring files.
"""
from __future__ import division
import logging
import pipes
import aexpect
from utils.exception import SSHError
from utils.exception import SCPTransferTimeoutError
from utils.exception import SCPTransferError
from utils.exception import SCPAuthenticationTimeoutError

def _scp_operation(session, password, transfer_timeout=600, login_timeout=300):
    """
    Get questions from console, and provide answer(such as password).

    Args:
        session: An Expect instance from aexpect
    """
    timeout = login_timeout
    authentication = False

    while True:
        try:
            index, text = session.read_until_last_line_matches(
                [r"yes/no/", r"[Pp]assword:\s*$", r"lost connection"],
                timeout=timeout, internal_timeout=0.5)
            # yes/no
            if index == 0:
                session.sendline("yes")
                continue
            # "password:"
            if index == 1:
                logging.debug("Got password prompt, sending '%s'", password)
                session.sendline(password)
                timeout = transfer_timeout
                authentication = True
                continue
            # "lost connection"
            if index == 2:
                raise SSHError("SCP client said 'lost connection'", text)
        except aexpect.ExpectTimeoutError as err:
            if authentication:
                raise SCPTransferTimeoutError(err.output)
            raise SCPAuthenticationTimeoutError(err.output)
        except aexpect.ExpectProcessTerminatedError as err:
            if err.status == 0:
                logging.debug("SCP process terminated with status 0")
                break
            raise SCPTransferError(err.status, err.output)

def scp_to_remote(host, port, username, password, local_path, remote_path,
                  limit="", output_func=None, timeout=600):
    """
    Copy files to a remote host (guest) through scp.

    Args:
        limit: Speed limit of file transfer, it means bandwidth.
    """
    transfer_timeout = timeout
    login_timeout = 60
    if limit != "":
        limit = "-l %s" % (limit)

    command = "scp"
    command += (" -r "
                "-v -o UserKnownHostsFile=/dev/null "
                "-o StrictHostKeyChecking=no "
                "-o PreferredAuthentications=password %s "
                r"-P %s %s %s@\[%s\]:%s" %
                (limit, port, pipes.quote(local_path), username, host, pipes.quote(remote_path)))
    logging.debug("Trying to SCP with command '%s', timeout %ss", command, transfer_timeout)
    output_params = ()
    session = aexpect.Expect(command,
                             output_func=output_func,
                             output_params=output_params)
    try:
        _scp_operation(session, password, transfer_timeout, login_timeout)
    finally:
        session.close()
