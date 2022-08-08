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
"""Test microvm isula"""

import os
import logging
import subprocess
from utils.utils_logging import TestLog

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="/var/log/pytest.log", level=logging.DEBUG, format=LOG_FORMAT)
LOG = TestLog.get_global_log()
SHELL_TIMEOUT = 10

def test_microvm_isula_initrd(container):
    """
    Test run isula with initrd:

    1) run isula with initrd
    2) execute shell command in isula
    """
    LOG.info("----------test_microvm_isula_initrd----------")
    kata_container = container
    container_id = None
    try:
        kata_container.replace_configuration(cig_name='configuration-initrd.toml')
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                image="busybox:latest",
                                                name="initrd1-hydropper")
        LOG.info("initrd container id:%s", container_id)

        session = kata_container.create_isula_shellsession("initrd1-hydropper")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0

        session.close()
        kata_container.stop_isula("initrd1-hydropper")
    finally:
        kata_container.remove_isula_force("initrd1-hydropper")

def test_microvm_isula_rootfs(container):
    """
    Test run isula with rootfs:

    1) run isula with rootfs
    2) execute shell command in isula
    """
    LOG.info("----------test_microvm_isula_rootfs----------")
    kata_container = container
    container_id = None
    try:
        kata_container.replace_configuration(cig_name='configuration-rootfs.toml')
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                image="busybox:latest",
                                                name="rootfs1-hydropper")
        LOG.info("rootfs container id:%s", container_id)

        session = kata_container.create_isula_shellsession("rootfs1-hydropper")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0

        session.close()
        kata_container.stop_isula("rootfs1-hydropper")
    finally:
        kata_container.remove_isula_force("rootfs1-hydropper")

def test_microvm_isula_ozone(container):
    """
    Test run isula ozone option:

    1) run isula with ozone
    """
    LOG.info("----------test_microvm_isula_ozone----------")
    container_id = None
    kata_container = container
    try:
        kata_container.replace_configuration(cig_name='configuration-ozone.toml')
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                image="busybox:latest",
                                                name="ozone1-hydropper")
        LOG.info("ozone container id:%s", container_id)
        session = kata_container.create_isula_shellsession("ozone1-hydropper")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0

        session.close()
        kata_container.stop_isula("ozone1-hydropper")
    finally:
        kata_container.remove_isula_force("ozone1-hydropper")

def test_microvm_isula_template(container):
    """
    Test run isula with template:

    1) run template isula and create a template auto matically
    2) assert template has been created.
    3) run a new isula container from template
    """
    LOG.info("----------test_microvm_isula_template----------")
    kata_container = container
    container_id1 = container_id2 = None
    if os.path.exists("/run/vc/vm/template/"):
        subprocess.run("rm -rf /run/vc/vm/template/", shell=True, check=True)
    try:
        kata_container.replace_configuration(cig_name='configuration-template.toml')
        container_id1 = kata_container.run_isula(options="-tid",
                                                 runtime="io.containerd.kata.v2",
                                                 image="busybox:latest",
                                                 name="template1-hydropper")
        LOG.info("template container id:%s", container_id1)
        session = kata_container.create_isula_shellsession("template1-hydropper")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0
        session.close()

        assert os.path.exists("/run/vc/vm/template/")

        container_id2 = kata_container.run_isula(options="-tid",
                                                 runtime="io.containerd.kata.v2",
                                                 image="busybox:latest",
                                                 name="template2-hydropper")
        LOG.info("run container from template, id:%s", container_id2)
        session = kata_container.create_isula_shellsession("template2-hydropper")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0
        session.close()

        kata_container.stop_isula("template1-hydropper")
        kata_container.stop_isula("template2-hydropper")
    finally:
        kata_container.remove_isula_force("template1-hydropper")
        kata_container.remove_isula_force("template2-hydropper")
        if os.path.exists("/run/vc/vm/template/"):
            subprocess.run("rm -rf /run/vc/vm/template/", shell=True, check=True)

def test_microvm_isula_sandbox(container):
    """
    Test run isula with sandbox:

    1) run podsandbox container firstly.
    2) run a new container in podsanbox.
    """
    LOG.info("----------test_microvm_isula_sandbox----------")
    kata_container = container
    container_id = podsandbox_id = None
    try:
        podsandbox_id = kata_container.run_isula(options="-tid",
                                                 runtime="io.containerd.kata.v2",
                                                 image="busybox:latest",
                                                 name="sandbox1-hydropper",
                                                 annotation="io.kubernetes.docker.type=podsandbox")
        LOG.info("podsandbox container id:%s", podsandbox_id)

        podsandbox_id = podsandbox_id.strip('\n')
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                image="busybox:latest",
                                                name="sandbox2-hydropper",
                                                annotation=["io.kubernetes.docker.type=container",
                                                            ("io.kubernetes.sandbox.id=%s" % podsandbox_id)])
        LOG.info("container id:%s", container_id)
        session = kata_container.create_isula_shellsession("sandbox2-hydropper")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0
        session.close()

        kata_container.stop_isula("sandbox2-hydropper")
        kata_container.stop_isula("sandbox1-hydropper")
    finally:
        kata_container.remove_isula_force("sandbox2-hydropper")
        kata_container.remove_isula_force("sandbox1-hydropper")
