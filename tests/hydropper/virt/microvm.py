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
import subprocess
from virt.basevm import BaseVM
from utils.utils_logging import TestLog
from utils.config import CONFIG
from utils.resources import NETWORKS
from utils.resources import VSOCKS
from monitor.mem_usage_info import MemoryUsageExceededInfo

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename="/var/log/pytest.log", level=logging.DEBUG, format=LOG_FORMAT)
LOG = TestLog.get_global_log()

class MicroVM(BaseVM):
    """Class to represent a microvm"""
    def __init__(self, root_path, name, uuid, bin_path=CONFIG.stratovirt_microvm_bin,
                 vmconfig=CONFIG.get_default_microvm_vmconfig(),
                 vmlinux=CONFIG.stratovirt_vmlinux, rootfs=CONFIG.stratovirt_rootfs, initrd=CONFIG.stratovirt_initrd,
                 vcpus=4, memsize=2048, socktype="unix", loglevel="info"):
        self._args = list()
        self._console_address = None
        self._popen = None
        self.full_command = None
        self.name = name
        self.vmid = uuid
        if "unix" in socktype:
            sock_path = os.path.join(root_path, self.name + "_" + self.vmid + ".sock")
        else:
            sock_path = ("127.0.0.1", 32542)
        self.vmconfig_template_file = vmconfig
        self.vm_json_file = None
        self.vmlinux = vmlinux
        self.vhost_type = None
        self.rootfs = rootfs
        self.pid = None
        self.initrd = initrd
        self.vcpus = vcpus
        self.memsize = memsize
        self.inited = False
        self.init_vmjson(root_path)
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
            if "block" in _vm_json:
                # one by default
                _vm_json["block"][0]["drive"][0]["path_on_host"] = self.rootfs
            if "machine-config" in _vm_json:
                _vm_json["machine-config"]["vcpu_count"] = int(self.vcpus)
                _vm_json["machine-config"]["mem_size"] = self.memsize

            with open(self.vm_json_file, "w") as fpdest:
                json.dump(_vm_json, fpdest)
                self.inited = True

    def add_fake_pci_bridge_args(self):
        """Add fake pcibridge config"""
        self._args.extend(['-serial'])

    def launch(self):
        """Start a microvm and establish a qmp connection"""
        del self._args
        self._args = list(self.init_args)
        self._pre_launch()
        self.parser_config_to_args()
        self.full_command = ([self.bin_path] + self._base_args() + self._args)
        LOG.debug(self.full_command)
        if not self.env.keys():
            self._popen = subprocess.Popen(self.full_command,
                                           stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           shell=False,
                                           close_fds=True)
        else:
            _tempenv = os.environ.copy()
            for key, _ in self.env.items():
                _tempenv[key] = self.env[key]
            self._popen = subprocess.Popen(self.full_command,
                                           stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           shell=False,
                                           close_fds=True,
                                           env=_tempenv)

        if self.daemon:
            self._popen.wait()
            self.pid = self.get_pid()
        else:
            self.pid = self._popen.pid
        if not self.error_test:
            self._post_launch()

    def _base_args(self):
        args = self._common_args()
        if self._console_set:
            self._console_address = os.path.join(self._sock_dir,
                                                 self._name + "_" + self.vmid + "-console.sock")
            # It doesn't need to create it first.
            self._remove_files.append(self._console_address)
            args.extend(['-device', 'virtio-serial-device', '-chardev',
                         'socket,path=%s,id=virtioconsole0,server,nowait' % self._console_address,
                         '-device', 'virtconsole,chardev=virtioconsole0,id=console_0'])

        if self.vnetnums > 0:
            for _ in range(self.vnetnums - len(self.taps)):
                tapinfo = NETWORKS.generator_tap()
                LOG.debug("current tapinfo is %s" % tapinfo)
                self.taps.append(tapinfo)

            for tapinfo in self.taps:
                tapname = tapinfo["name"]
                _temp_net_args = "tap,id=%s,ifname=%s" % (tapname, tapname)
                if self.vhost_type:
                    _temp_net_args += ",vhost=on"
                if self.vhostfd:
                    _temp_net_args += ",vhostfd=%s" % self.vhostfd
                _temp_device_args = "virtio-net-device,netdev=%s,id=%s" % (tapname, tapname)
                if self.net_iothread:
                    _temp_device_args += ",iothread=%s" % self.net_iothread
                    self.iothreads += 1
                if self.withmac:
                    _temp_device_args += ",mac=%s" % tapinfo["mac"]
                args.extend(['-netdev', _temp_net_args, '-device', _temp_device_args])

        if self.rng:
            _temp_rng_args = 'rng-random,id=objrng0,filename=%s' % self.rng_files
            if self.max_bytes == 0:
                _temp_device_args = 'virtio-rng-device,rng=objrng0'
            else:
                _temp_device_args = 'virtio-rng-device,rng=objrng0,max-bytes=%s,period=1000' % self.max_bytes
            args.extend(['-object', _temp_rng_args, '-device', _temp_device_args])

        if self.vsocknums > 0:
            if VSOCKS.init_vsock():
                for _ in range(self.vsocknums - len(self.vsock_cid)):
                    sockcid = VSOCKS.find_contextid()
                    self.vsock_cid.append(sockcid)
                    args.extend(['-device',
                                 'vhost-vsock-device,id=vsock-%s,'
                                 'guest-cid=%s' % (sockcid, sockcid)])

        if self.balloon:
            _temp_balloon_args = 'virtio-balloon-device'
            if self.deflate_on_oom:
                _temp_balloon_args += ',deflate-on-oom=true'
            else:
                _temp_balloon_args += ',deflate-on-oom=false'
            if self.free_page_reporting:
                _temp_balloon_args += ',free-page-reporting=true'
            else:
                _temp_balloon_args += ',free-page-reporting=false'
            args.extend(['-device', _temp_balloon_args])

        if self.iothreads > 0:
            args = self.make_iothread_cmd(args)

        return args

    def basic_config(self, **kwargs):
        """Change configdict"""
        if "vcpu_count" in kwargs:
            self.configdict["machine-config"]["vcpu_count"] = kwargs.get("vcpu_count")
            del kwargs["vcpu_count"]
        if "mem_size" in kwargs:
            self.configdict["machine-config"]["mem_size"] = kwargs.get("mem_size")
            del kwargs["mem_size"]
        if "mem_path" in kwargs:
            self.configdict["machine-config"]["mem_path"] = kwargs.get("mem_path")
            del kwargs["mem_path"]
        if "vhost_type" in kwargs:
            self.vhost_type = kwargs.get("vhost_type")
            del kwargs["vhost_type"]
        if "cpu_features" in kwargs:
            self.configdict["machine-config"]["cpu_features"] = kwargs.get("cpu_features")
            del kwargs["cpu_features"]

        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def parser_config_to_args(self):
        """Parser json config to args"""
        if self.configdict is None:
            return

        configdict = self.configdict
        if "boot-source" in configdict:
            if "kernel_image_path" in configdict["boot-source"]:
                self.add_args('-kernel', configdict["boot-source"]["kernel_image_path"])
            if "boot_args" in configdict["boot-source"]:
                self.add_args('-append', configdict["boot-source"]["boot_args"])
            if "initrd" in configdict["boot-source"]:
                self.add_args('-initrd', configdict["boot-source"]["initrd"])

        if "machine-config" in configdict:
            # make smp cmdline
            _temp_cpu_args = ""
            if "vcpu_count" in configdict["machine-config"]:
                _temp_cpu_args = str(configdict["machine-config"]["vcpu_count"])
            if _temp_cpu_args != "":
                self.add_args('-smp', _temp_cpu_args)
            # make mem cmdline
            _temp_mem_args = ""
            if "mem_size" in configdict["machine-config"]:
                _temp_mem_args = str(configdict["machine-config"]["mem_size"])
            if _temp_mem_args != "":
                self.add_args('-m', _temp_mem_args)
            if "mem_path" in configdict["machine-config"]:
                self.add_args('-mem-path', configdict["machine-config"]["mem_path"])
            # make CPU feature cmdline
            if "cpu_features" in configdict["machine-config"]:
                self.add_args('-cpu', configdict["machine-config"]["cpu_features"])


        # make block cmdline
        for block in configdict.get("block", []):
            # make drive cmdline
            for drive in block.get("drive", []):
                _temp_drive_args = ""
                if "drive_id" in drive:
                    _temp_drive_args = "id=%s" % drive["drive_id"]
                if "path_on_host" in drive:
                    _temp_drive_args += ",file=%s" % drive["path_on_host"]
                if "read_only" in drive:
                    _temp = "on" if drive["read_only"] else "off"
                    _temp_drive_args += ",readonly=%s" % _temp
                if "direct" in drive:
                    _temp = "on" if drive["direct"] else "off"
                    _temp_drive_args += ",direct=%s" % _temp
                if "iops" in drive:
                    _temp_drive_args += ",throttling.iops-total=%s" % drive["iops"]
                if _temp_drive_args != "":
                    self.add_args('-drive', _temp_drive_args)

            # make block device cmdline
            for device in block.get("device", []):
                _temp_device_args = ""
                _temp_device_args = "virtio-blk-device,drive=%s,id=%s" % (device["drive_id"], device["drive_id"])
                if "iothread" in device:
                    _temp_device_args += ",iothread=%s" % device["iothread"]
                    self.iothreads += 1
                if "serial" in device:
                    _temp_device_args += ",serial=%s" % device["serial"]
                if _temp_device_args != "":
                    self.add_args('-device', _temp_device_args)
