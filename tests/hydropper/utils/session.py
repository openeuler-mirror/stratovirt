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
"""Create session"""

import threading
import time
import aexpect
from utils.utils_logging import TestLog
from utils.exception import ConsoleBusyError
from utils.exception import NoConsoleError
from utils.exception import LoginAuthenticationError
from utils.exception import LoginTimeoutError
from utils.exception import LoginProcessTerminatedError

LOG = TestLog.get_global_log()

def lock(function):
    """
    Get the ConsoleManager lock, run the function, then release the lock.

    Args:
        function: Function to package.
    """
    def package(*args, **kwargs):
        console_manager = args[0]
        if console_manager.console_lock.acquire_lock(False) is False:
            raise ConsoleBusyError
        try:
            return function(*args, **kwargs)
        finally:
            console_manager.console_lock.release_lock()
    return package


class ConsoleManager():
    """A class for console session communication pipeline."""

    def __init__(self):
        self._console = None
        self.status_test_command = None
        self.console_lock = threading.Lock()

    @lock
    def login_session(self, status_test_command, prompt, username, password, timeout):
        """Login session by handle_session()"""
        self._console.set_status_test_command(status_test_command)
        self.handle_session(self._console, username, password, prompt, timeout, True)

    def create_session(self, status_test_command,
                       prompt, username, password, timeout):
        """Return a console session with itself as the manager."""
        if self._console is None:
            raise NoConsoleError
        self.login_session(status_test_command, prompt, username, password, timeout)
        return ConsoleSession(self)

    def config_console(self, console):
        """Configure console"""
        self._console = console
        self.status_test_command = self._console.status_test_command

    def close(self):
        """Close console"""
        self._console.close()

    @lock
    def get_func(self, func, *args, **kwargs):
        """
        Get the func provided by a Console.

        Args:
            func: function name
        """
        _func = getattr(self._console, func)
        return _func(*args, **kwargs)

    @staticmethod
    def handle_session(session, username, password, prompt, timeout=10,
                       debug=False):
        """
        Connect to a remote host (guest) using SSH or Telnet or else.
        Provide answers to each questions.
        """
        password_prompt_count = 0
        login_prompt_count = 0
        last_chance = False
        last_line = [r"[Aa]re you sure", # continue connect
                     r"[Pp]assword:\s*", # password:
                     r"(?<![Ll]ast )[Ll]ogin:\s*$", # login:
                     r"[Ee]nter.*username", # login:
                     r"[Ee]nter.*password", # password:
                     prompt, # prompt
                     r"[Ww]arning"] # Warning added RSA

        output = ""

        def _continue_connect(debug, session):
            if debug:
                LOG.debug("Got 'Are you sure...', sending 'yes'")
            session.sendline("yes")

        def _send_passwd(debug, session, password):
            if debug:
                LOG.debug("Got password prompt, sending '%s'",
                          password)
            session.sendline(password)

        def _send_username(debug, session, username):
            if debug:
                LOG.debug("Got username prompt, sending '%s'",
                          username)
            session.send(username)

        while True:
            try:
                session.sendline()
                match, text = session.read_until_last_line_matches(last_line, timeout=timeout,
                                                                   internal_timeout=0.5, print_func=None)
                output += text
                if match == 0:
                    _continue_connect(debug, session)
                    continue
                if match in (1, 4):
                    if password_prompt_count == 0:
                        _send_passwd(debug, session, password)
                        password_prompt_count += 1
                        continue
                    raise LoginAuthenticationError("Got password prompt twice", text)
                if match in (2, 3):
                    if login_prompt_count == 0 and password_prompt_count == 0:
                        _send_username(debug, session, username)
                        login_prompt_count += 1
                        continue
                    if login_prompt_count > 0:
                        raise LoginAuthenticationError("Got username prompt twice", text)
                    raise LoginAuthenticationError("Got username prompt after password prompt", text)
                if match == 5:
                    if debug:
                        LOG.debug("Got shell prompt, logged successfully")
                    break
                if match == 6:
                    if debug:
                        LOG.debug("Got 'Warning added RSA to known host list")
                    continue
            except aexpect.ExpectTimeoutError as err:
                # send a empty line to avoid unexpected login timeout
                # because some message from linux kernel maybe impact match
                if not last_chance:
                    time.sleep(0.5)
                    session.sendline()
                    last_chance = True
                    continue
                raise LoginTimeoutError(err.output)
            except aexpect.ExpectProcessTerminatedError as err:
                raise LoginProcessTerminatedError(err.status, err.output)

        return output


class ConsoleSession():
    """
    The wrapper of ShellSession from aexpect.
    """

    def __init__(self, manager):
        self.__closed = False
        self.__manager = manager
        self.status_test_command = manager.status_test_command

    def __repr__(self):
        return "console session id <%s>" % id(self)

    def run_func(self, name, *args, **kwargs):
        """
        Execute console session function

        Args:
            name: function name. available name: is_responsive cmd_output cmd_output_safe
            cmd_status_output cmd_status cmd close send sendline sendcontrol send_ctrl set_linesep
            read_nonblocking read_until_output_matches read_until_last_line_matches
            read_until_any_line_matches read_up_to_prompt
        """

        if name == "close":
            if self.__closed:
                raise RuntimeError("%s is closed." % self)
            self.__manager.close()
            self.__closed = True
        else:
            return self.__manager.get_func(name, *args, **kwargs)
        return None
