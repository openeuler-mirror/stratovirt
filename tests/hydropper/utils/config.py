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
"""global config parser"""


import os
import configparser
from queue import Queue
from utils.decorators import Singleton

CONFIG_FILE = "../config/config.ini"


class ParserConfig(Singleton):
    """Global settings class"""

    def __init__(self, cfg_file=CONFIG_FILE):
        """
        Constructor

        Args:
            cfg_file: set the global config file
        """
        self.conf = configparser.ConfigParser()
        _tempfile = os.path.join(os.path.dirname(__file__), cfg_file)
        self.conf.read(_tempfile)
        self.flush()
        self.vmconfigs = dict()
        self.init_vmconfig_files()
        self.test_session_root_path = self.test_dir
        self.event_queue = Queue()

    def get_option(self, section, option, default=None):
        """
        Get item value

        Args:
            section:  set the section value
            option:   set the option value
            default:  set the default value
        """
        try:
            return str(self.conf.get(section, option))
        except configparser.NoSectionError:
            return default
        except configparser.NoOptionError:
            return default

    def flush(self):
        """Read config from self.conf file"""
        # parser global env config
        self.test_dir = self.get_option("env.params", "TEST_DIR", "/var/tmp/")
        self.vmtype = self.get_option("env.params", "VMTYPE", "stratovirt")
        self.vm_templ_dir = self.get_option("env.params", "VM_TEMPL_DIR",
                                            "../config/test_config/vm_config")
        self.vm_username = self.get_option("env.params", "VM_USERNAME", "root")
        self.vm_password = self.get_option("env.params", "VM_PASSWORD", "openEuler12#$")
        self.timeout_factor = int(self.get_option("env.params", "TIMEOUT_FACTOR", "1"))
        self.delete_test_session = bool(self.get_option("env.params", "DELETE_TEST_SESSION",
                                                        "false") == "true")
        self.concurrent_quantity = int(self.get_option("env.params", "CONCURRENT_QUANTITY", "10"))

        # parser stratovirt config
        self.stratovirt_microvm_bin = self.get_option("stratovirt.params", "STRATOVIRT_MICROVM_BINARY", None)
        self.stratovirt_standvm_bin = self.get_option("stratovirt.params", "STRATOVIRT_STANDVM_BINARY", None)
        self.stratovirt_microvm_boottime_bin = self.get_option("stratovirt.params",
                                                               "STRATOVIRT_MICROVM_BOOTTIME_BINARY", None)
        self.stratovirt_microvm_config = self.get_option("stratovirt.params", "STRATOVIRT_MICROVM_CONFIG",
                                                         "config/test_config/vm_config/micro_vm.json")
        self.stratovirt_standvm_config = self.get_option("stratovirt.params", "STRATOVIRT_STANDVM_CONFIG",
                                                         "config/test_config/vm_config/stand_vm.json")
        self.stratovirt_binary_name = self.get_option("stratovirt.params",
                                                      "STRATOVIRT_BINARY_NAME", "microvm")
        self.stratovirt_vmlinux = self.get_option("stratovirt.params", "STRATOVIRT_VMLINUX", None)
        self.stratovirt_stand_vmlinux = self.get_option("stratovirt.params", "STRATOVIRT_STAND_VMLINUX", None)
        self.stratovirt_rootfs = self.get_option("stratovirt.params", "STRATOVIRT_ROOTFS", None)
        self.stratovirt_stand_rootfs = self.get_option("stratovirt.params", "STRATOVIRT_STAND_ROOTFS", None)
        self.stratovirt_initrd = self.get_option("stratovirt.params", "STRATOVIRT_INITRD", None)
        self.stratovirt_use_config_file = bool(self.get_option("stratovirt.params", "STRATOVIRT_USE_CONFIG_FILE",
                                                               "false") == "true")
        self.stratovirt_feature = self.get_option("stratovirt.params", "STRATOVIRT_FEATURE", "mmio")
        self.memory_usage_check = bool(self.get_option("stratovirt.params", "MEMORY_USAGE_CHECK",
                                                       "true") == "true")
        self.rust_san_check = bool(self.get_option("stratovirt.params", "RUST_SAN_CHECK",
                                                   "false") == "true")
        self.code_storage_file = self.get_option("stratovirt.params", "CODE_STORAGE_FILE", None)


        # parser network params
        self.bridge_name = self.get_option("network.params", "BRIDGE_NAME", "stratobr0")
        self.nets_num = int(self.get_option("network.params", "NETS_NUMBER", "10"))
        self.ip_prefix = self.get_option("network.params", "IP_PREFIX", "192.168")
        self.ip_3rd = int(self.get_option("network.params", "IP_3RD", "133"))
        self.dhcp_lower_limit = int(self.get_option("network.params", "DHCP_LOWER_LIMIT", "100"))
        self.dhcp_top_limit = int(self.get_option("network.params", "DHCP_TOP_LIMIT", "240"))
        self.static_ip_lower_limit = int(self.get_option("network.params", "STATIC_IP_LOWER_LIMIT", "10"))
        self.static_ip_top_limit = int(self.get_option("network.params", "STATIC_IP_TOP_LIMIT", "100"))
        self.netmasklen = self.get_option("network.params", "NETMASK_LEN", "24")
        self.netmask = self.get_option("network.params", "NETMASK", "255.255.255.0")

        # parser katacontainer params
        self.kata_config_path = self.get_option("katacontainer.params", "KATA_CONFIG_PATH",
                                                "/usr/share/defaults/kata-containers")

    def init_vmconfig_files(self):
        """
        Init vmconfig files(self.vmconfigs) as follow:
            {"microvm": {"cpuhotplug": "microvm_cpuhotplug.json",
                         "seccomp": "microvm_seccomp.json"}
            }
        """
        for cfg_file in os.listdir(self.vm_templ_dir):
            for vmtype in ["microvm", "standvm"]:
                if cfg_file.startswith(vmtype):
                    if vmtype not in self.vmconfigs:
                        self.vmconfigs[vmtype] = dict()
                    tag = str(cfg_file).replace(vmtype + "_", "").replace(".json", "")
                    self.vmconfigs[vmtype][tag] = os.path.join(self.vm_templ_dir, cfg_file)
                    break

    def list_vmconfigs(self, vmtype="microvm"):
        """
        Get list of vmconfig file

        Args:
            vmtype: specify prefix of filename
        """
        if vmtype in self.vmconfigs:
            return self.vmconfigs[vmtype].values()

        return list()

    def _list_vmconfig_with_vmtype_tag(self, vmtype, tag):
        if vmtype in self.vmconfigs:
            return self.vmconfigs[vmtype].get(tag, None)

        return None

    def get_microvm_by_tag(self, tag):
        """
        Get microvm config by tag

        Args:
            tag: such as -boottime, -initrd.
        """
        return self._list_vmconfig_with_vmtype_tag("microvm", tag)

    def get_standvm_by_tag(self, tag):
        """
        Get standvm config by tag
        """
        return self._list_vmconfig_with_vmtype_tag("standvm", tag)

    def list_microvm_tags(self):
        """List microvm all tags"""
        if "microvm" in self.vmconfigs:
            return self.vmconfigs["microvm"].keys()

        return list()

    def list_standvm_tags(self):
        """List standvm all tags"""
        if "standvm" in self.vmconfigs:
            return self.vmconfigs["standvm"].keys()

        return list()

    def get_default_microvm_vmconfig(self):
        """Get default microvm vmconfig file"""
        return self.stratovirt_microvm_config

    def get_default_standvm_vmconfig(self):
        """Get default standvm vmconfig file"""
        return self.stratovirt_standvm_config


CONFIG = ParserConfig()
