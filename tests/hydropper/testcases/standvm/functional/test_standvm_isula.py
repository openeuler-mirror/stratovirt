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
"""Test standvm isula"""

import os
import logging
import subprocess
import pytest
import utils.utils_common as utils
from utils.utils_logging import TestLog

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="/var/log/pytest.log", level=logging.DEBUG, format=LOG_FORMAT)
LOG = TestLog.get_global_log()
SHELL_TIMEOUT = 10

def test_standvm_isula_initrd(container):
    """
    Test run isula with initrd:

    1) run isula with initrd
    2) execute shell command in isula
    """
    LOG.info("----------test_standvm_isula_initrd----------")
    kata_container = container
    container_id = None
    try:
        kata_container.replace_configuration(cig_name='configuration-initrd-stand.toml')
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                image="busybox:latest",
                                                name="initrd1-hydropper-stand")
        LOG.info("initrd-stand container id:%s", container_id)

        session = kata_container.create_isula_shellsession("initrd1-hydropper-stand")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0

        session.close()
        kata_container.stop_isula("initrd1-hydropper-stand")
    finally:
        kata_container.remove_isula_force("initrd1-hydropper-stand")

def test_standvm_isula_rootfs(container):
    """
    Test run isula with rootfs:

    1) run isula with rootfs
    2) execute shell command in isula
    """
    LOG.info("----------test_standvm_isula_rootfs----------")
    kata_container = container
    container_id = None
    try:
        kata_container.replace_configuration(cig_name='configuration-rootfs-stand.toml')
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                image="busybox:latest",
                                                name="rootfs1-hydropper-stand")
        LOG.info("rootfs-stand container id:%s", container_id)

        session = kata_container.create_isula_shellsession("rootfs1-hydropper-stand")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0

        session.close()
        kata_container.stop_isula("rootfs1-hydropper-stand")
    finally:
        kata_container.remove_isula_force("rootfs1-hydropper-stand")

def test_standvm_isula_template(container):
    """
    Test run isula with template:

    1) run template isula and create a template auto matically
    2) assert template has been created.
    3) run a new isula container from template
    """
    LOG.info("----------test_standvm_isula_template----------")
    kata_container = container
    container_id1 = container_id2 = None
    if os.path.exists("/run/vc/vm/template/"):
        subprocess.run("rm -rf /run/vc/vm/template/", shell=True, check=True)
    try:
        kata_container.replace_configuration(cig_name='configuration-template-stand.toml')
        container_id1 = kata_container.run_isula(options="-tid",
                                                 runtime="io.containerd.kata.v2",
                                                 image="busybox:latest",
                                                 name="template1-hydropper-stand")
        LOG.info("template container id:%s", container_id1)
        session = kata_container.create_isula_shellsession("template1-hydropper-stand")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0
        session.close()

        assert os.path.exists("/run/vc/vm/template/")

        container_id2 = kata_container.run_isula(options="-tid",
                                                 runtime="io.containerd.kata.v2",
                                                 image="busybox:latest",
                                                 name="template2-hydropper-stand")
        LOG.info("run container from template, id:%s", container_id2)
        session = kata_container.create_isula_shellsession("template2-hydropper-stand")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0
        session.close()

        kata_container.stop_isula("template1-hydropper-stand")
        kata_container.stop_isula("template2-hydropper-stand")
    finally:
        kata_container.remove_isula_force("template1-hydropper-stand")
        kata_container.remove_isula_force("template2-hydropper-stand")
        if os.path.exists("/run/vc/vm/template/"):
            subprocess.run("rm -rf /run/vc/vm/template/", shell=True, check=True)

def test_standvm_isula_sandbox(container):
    """
    Test run isula with sandbox:

    1) run podsandbox container firstly.
    2) run a new container in podsanbox.
    """
    LOG.info("----------test_standvm_isula_sandbox----------")
    kata_container = container
    container_id = podsandbox_id = None
    try:
        kata_container.replace_configuration(cig_name='configuration-initrd-stand.toml')
        podsandbox_id = kata_container.run_isula(options="-tid",
                                                 runtime="io.containerd.kata.v2",
                                                 image="busybox:latest",
                                                 name="sandbox1-hydropper-stand",
                                                 annotation="io.kubernetes.docker.type=podsandbox")
        LOG.info("podsandbox container id:%s", podsandbox_id)

        podsandbox_id = podsandbox_id.strip('\n')
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                image="busybox:latest",
                                                name="sandbox2-hydropper-stand",
                                                annotation=["io.kubernetes.docker.type=container",
                                                            ("io.kubernetes.sandbox.id=%s" % podsandbox_id)])
        LOG.info("container id:%s", container_id)
        session = kata_container.create_isula_shellsession("sandbox2-hydropper-stand")
        status, _ = session.cmd_status_output("ls", timeout=SHELL_TIMEOUT)
        assert status == 0
        session.close()

        kata_container.stop_isula("sandbox2-hydropper-stand")
        kata_container.stop_isula("sandbox1-hydropper-stand")
    finally:
        kata_container.remove_isula_force("sandbox2-hydropper-stand")
        kata_container.remove_isula_force("sandbox1-hydropper-stand")

@pytest.mark.skip
@pytest.mark.parametrize("net_type, bdf, pf_name",
                         [('1822', '0000:03:00.0', 'enp3s0')])
def test_standvm_isula_vfionet(container, net_type, bdf, pf_name):
    """
    Test run isula with vfio net device:
    """
    LOG.info("----------test_standvm_isula_vfionet----------")
    kata_container = container
    container_id = None
    vf_bdf = bdf.split('.')[0] + '.1'
    try:
        kata_container.replace_configuration(cig_name='configuration-initrd-stand.toml')
        utils.config_host_vfio(net_type=net_type, number='2', bdf=bdf)
        utils.check_vf(pf_name=pf_name)
        subprocess.run("modprobe vfio-pci", shell=True, check=True)
        utils.rebind_vfio_pci(bdf=vf_bdf)
        iommu_group = utils.get_iommu_group(vf_bdf)
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                device="/dev/vfio/%s" % iommu_group,
                                                net="none",
                                                image="busybox:latest",
                                                name="vfionet1-hydropper-stand")
        LOG.info("vfio net container id:%s", container_id)

        session = kata_container.create_isula_shellsession("vfionet1-hydropper-stand")
        status, _ = session.cmd_status_output("ip a", timeout=SHELL_TIMEOUT)
        assert status == 0

        session.close()
        kata_container.stop_isula("vfionet1-hydropper-stand")
    finally:
        utils.clean_vf(bdf=bdf)
        kata_container.remove_isula_force("vfionet1-hydropper-stand")

@pytest.mark.skip
def test_standvm_isula_virtiofs(container):
    """
    Test run isula with virtio fs:
    """
    LOG.info("----------test_standvm_isula_virtiofs----------")
    kata_container = container
    container_id = None
    test_dir = "/tmp/hydropper_virtio_fs"
    if not os.path.exists(test_dir):
        subprocess.run("mkdir %s" % test_dir, shell=True, check=True)
    subprocess.run("touch %s/hydropper1.log" % test_dir, shell=True, check=True)
    try:
        kata_container.replace_configuration(cig_name='configuration-virtiofs-stand.toml')
        container_id = kata_container.run_isula(options="-tid",
                                                runtime="io.containerd.kata.v2",
                                                net="none -v %s:/tmp/" % test_dir,
                                                image="busybox:latest",
                                                name="virtiofs1-hydropper-stand")
        LOG.info("virtio fs container id:%s", container_id)

        session = kata_container.create_isula_shellsession("virtiofs1-hydropper-stand")
        status, _ = session.cmd_status_output("ls /tmp/hydropper1.log", timeout=SHELL_TIMEOUT)
        assert status == 0

        session.close()
        kata_container.stop_isula("virtiofs1-hydropper-stand")
    finally:
        kata_container.remove_isula_force("virtiofs1-hydropper-stand")
        subprocess.run("rm -rf /tmp/hydropper_virtio_fs", shell=True, check=True)
