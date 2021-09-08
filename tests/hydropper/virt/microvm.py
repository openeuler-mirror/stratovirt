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
"""class microvm"""

import os
import json
import logging
from virt.basevm import BaseVM
from utils.config import CONFIG
from monitor.mem_usage_info import MemoryUsageExceededInfo

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="/var/log/pytest.log", level=logging.DEBUG, format=LOG_FORMAT)

class MicroVM(BaseVM):
    """Class to represent a microvm"""
    def __init__(self, root_path, name, uuid, bin_path=CONFIG.stratovirt_microvm_bin,
                 vmconfig=CONFIG.get_default_microvm_vmconfig(),
                 vmlinux=CONFIG.stratovirt_vmlinux, rootfs=CONFIG.stratovirt_rootfs, initrd=CONFIG.stratovirt_initrd,
                 vcpus=4, max_vcpus=8, memslots=0, maxmem=None,
                 memsize=2048, socktype="unix", loglevel="info"):
        self.name = name
        self.vmid = uuid
        if "unix" in socktype:
            sock_path = os.path.join(root_path, self.name + "_" + self.vmid + ".sock")
        else:
            sock_path = ("127.0.0.1", 32542)
        self.vmconfig_template_file = vmconfig
        self.vm_json_file = None
        self.vmlinux = vmlinux
        self.rootfs = rootfs
        self.initrd = initrd
        self.vcpus = vcpus
        self.max_vcpus = max_vcpus
        self.memslots = memslots
        self.memsize = memsize
        self.maxmem = maxmem
        self.inited = False
        self.init_vmjson(root_path)
        self._args = list()
        super(MicroVM, self).__init__(root_path=root_path,
                                      name=name,
                                      uuid=uuid,
                                      args=self._args,
                                      bin_path=bin_path,
                                      mon_sock=sock_path,
                                      daemon=True,
                                      config=self.vm_json_file)
        self.add_env("RUST_BACKTRACE", "1")
        if CONFIG.rust_san_check:
            self.add_env("RUSTFLAGS", "-Zsanitizer=address")
        self.add_env("STRATOVIRT_LOG_LEVEL", loglevel)
        if CONFIG.memory_usage_check:
            self.memory_check = MemoryUsageExceededInfo(0)
            self.memory_check.disable()
            self.memory_check.start()

    def _post_launch(self):
        super(MicroVM, self)._post_launch()
        if CONFIG.memory_usage_check:
            self.memory_check.update_pid(self.pid)
            self.memory_check.enable()

    def _post_shutdown(self):
        super(MicroVM, self)._post_shutdown()
        if CONFIG.memory_usage_check:
            self.memory_check.update_pid(0)
            self.memory_check.disable()

    def kill(self):
        if CONFIG.memory_usage_check:
            self.memory_check.set_state("stop")
            self.memory_check.join()
        super(MicroVM, self).kill()

    def init_vmjson(self, root_path):
        """Generate a temp vm json file"""
        self.vm_json_file = os.path.join(root_path, self.name + "_" + self.vmid + ".json")
        with open(self.vmconfig_template_file, "r") as cfp:
            _vm_json = json.load(cfp)
            if "boot-source" in _vm_json:
                _vm_json["boot-source"]["kernel_image_path"] = self.vmlinux
                if "initrd" in _vm_json["boot-source"]:
                    _vm_json["boot-source"]["initrd"] = self.initrd
            if "drive" in _vm_json:
                _vm_json["drive"][0]["path_on_host"] = self.rootfs
            if "machine-config" in _vm_json:
                _vm_json["machine-config"]["vcpu_count"] = int(self.vcpus)
                _vm_json["machine-config"]["mem_size"] = self.memsize
                if "max_vcpus" in _vm_json["machine-config"]:
                    _vm_json["machine-config"]["max_vcpus"] = int(self.max_vcpus)
                if "mem_slots" in _vm_json["machine-config"]:
                    _vm_json["machine-config"]["mem_slots"] = int(self.memslots)
                if self.maxmem is None and "max_mem" in _vm_json["machine-config"]:
                    _vm_json["machine-config"]["max_mem"] = self.memsize

            with open(self.vm_json_file, "w") as fpdest:
                json.dump(_vm_json, fpdest)
                self.inited = True

    def add_fake_pci_bridge_args(self):
        """Add fake pcibridge config"""
        self._args.extend(['-serial'])
