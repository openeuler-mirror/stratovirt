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
"""container class"""

import os
import subprocess
from subprocess import PIPE
import logging
import aexpect
from utils.config import CONFIG
from utils.utils_logging import TestLog

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="/var/log/pytest.log", level=logging.DEBUG, format=LOG_FORMAT)
LOG = TestLog.get_global_log()
LOGIN_TIMEOUT = 60
LOGIN_WAIT_TIMEOUT = 60

class KataContainer:
    """This class provides methods to operate kata container"""

    def __init__(self):
        self.config_path = CONFIG.kata_config_path
        self.isula_session = None
        self.isula_run_cmd = None

    def create_isula_shellsession(self, name):
        """Create session to isula container"""
        self.isula_session = aexpect.ShellSession(
            "isula exec -ti %s sh" % name,
            auto_close=False,
            output_func=LOG.debug,
            prompt=r"[\#\$]",
            status_test_command="echo $?"
        )
        return self.isula_session

    def basic_config(self, **kwargs):
        """get kata configuration items"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def make_isula_cmd(self, options, runtime, image, **kwargs):
        """make isula command"""
        cmd = 'isula run %s --runtime %s' % (options, runtime)

        for key, value in kwargs.items():
            if isinstance(value, list):
                for elem in value:
                    cmd += " --%s" % key
                    cmd += " %s" % elem
            else:
                cmd += " --%s" % key
                cmd += " %s" % value
        cmd += " %s sh" % image
        LOG.info("run command: %s", cmd)
        self.isula_run_cmd = cmd

    def run_isula(self, options, runtime, image, **kwargs):
        """run a new isula container"""
        self.make_isula_cmd(options, runtime, image, **kwargs)
        LOG.info("isula run:")
        return subprocess.run(self.isula_run_cmd, shell=True, check=True, stdout=PIPE).stdout.decode('utf-8')

    def stop_isula(self, container):
        """stop isula container, input container id or name"""
        LOG.info("isula stop %s" % container)
        cmd = "isula stop %s" % container
        subprocess.run(cmd, shell=True, check=True)

    def remove_isula(self, container):
        """remove isula container, input container id or name"""
        LOG.info("isula rm %s" % container)
        cmd = "isula rm %s" % container
        subprocess.run(cmd, shell=True, check=True)

    def remove_isula_force(self, container):
        """force remove isula container, input container id or name"""
        LOG.info("isula rm -f %s" % container)
        cmd = "isula rm -f %s" % container
        subprocess.run(cmd, shell=True, check=True)

    def replace_configuration(self, cig_name):
        """replace origin kata configuration"""
        target_path = "%s/%s" % (self.config_path, cig_name)
        assert os.path.exists(target_path)

        LOG.info("replace configuration now...")
        replace_cmd = "cp %s %s/configuration.toml" % (target_path, self.config_path)
        subprocess.run(replace_cmd, shell=True, check=True)
