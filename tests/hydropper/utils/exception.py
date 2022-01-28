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
"""Exceptions"""

class UnknownFeatureException(Exception):
    """Exception Class for invalid build feature."""

    def __init__(self):
        """Just a constructor."""
        Exception.__init__(
            self,
            "Trying to get build binaries for unknown feature!"
        )

# ssh error
class SSHError(Exception):
    """SSH error exception"""

    def __init__(self, msg, output):
        Exception.__init__(self, msg, output)
        self.msg = msg
        self.output = output

    def __str__(self):
        return "->message: %s    ->(output: %r)" % (self.msg, self.output)


class LoginAuthenticationError(SSHError):
    """Login authentication error exception"""



class LoginTimeoutError(SSHError):
    """Login timeout error exception"""

    def __init__(self, output):
        SSHError.__init__(self, "Login timeout expired", output)


class LoginProcessTerminatedError(SSHError):
    """Login process terminated error exception"""

    def __init__(self, status, output):
        SSHError.__init__(self, None, output)
        self.status = status

    def __str__(self):
        return ("Client process terminated    (status: %s,    output: %r)" %
                (self.status, self.output))


class LoginBadClientError(SSHError):
    """Login bad client error exception"""

    def __init__(self, client):
        SSHError.__init__(self, None, None)
        self.client = client

    def __str__(self):
        return "Unknown remote shell client: %r" % self.client


class SCPAuthenticationError(SSHError):
    """SCP authentication error exception"""


class SCPAuthenticationTimeoutError(SCPAuthenticationError):
    """SCP authentication timeout error exception"""
    def __init__(self, output):
        SCPAuthenticationError.__init__(self, "Authentication timeout expired",
                                        output)


class SCPTransferTimeoutError(SSHError):
    """SCP transfer timeout error exception"""
    def __init__(self, output):
        SSHError.__init__(self, "Transfer timeout expired", output)


class SCPTransferError(SSHError):
    """SCP transfer failed exception"""
    def __init__(self, status, output):
        SSHError.__init__(self, None, output)
        self.status = status

    def __str__(self):
        return ("SCP transfer failed    (status: %s,    output: %r)" %
                (self.status, self.output))

# console error
class ConsoleError(Exception):
    """Console base exception"""


class NoConsoleError(ConsoleError):
    """No Console Error"""
    def __str__(self):
        return "No console available"


class ConsoleBusyError(ConsoleError):
    """Console Busy Error"""
    def __str__(self):
        return "Console is in use"

# qmp error
class QMPError(Exception):
    """QMP base exception"""


class QMPConnectError(QMPError):
    """QMP connection exception"""


class QMPCapabilitiesError(QMPError):
    """QMP negotiate capabilities exception"""


class QMPTimeoutError(QMPError):
    """QMP timeout exception"""


class VMLifeError(Exception):
    """Vmlife error exception"""

# standvm error
class PflashError(Exception):
    "Lack of code storage file"
    def __str__(self):
        return "code_storage_file is not found"

class PcierootportError(Exception):
    """Insufficient slots"""
    def __str__(self):
        return "Insufficient pcie root port slots!!!"