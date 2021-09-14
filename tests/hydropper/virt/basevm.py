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
"""basic virtual machine class"""

import os
import time
import subprocess
import json
import logging
import socket
import errno
import aexpect
from aexpect.exceptions import ExpectError
from retrying import retry
from utils.config import CONFIG
from utils import utils_common
from utils import utils_network
from utils import remote
from utils.utils_logging import TestLog
from utils.session import ConsoleManager
from utils.resources import NETWORKS
from utils.resources import VSOCKS
from utils.exception import VMLifeError
from utils.exception import QMPError
from utils.exception import QMPConnectError
from utils.exception import QMPCapabilitiesError
from utils.exception import QMPTimeoutError
from utils.exception import SSHError
from utils.exception import LoginTimeoutError

LOG = TestLog.get_global_log()
LOGIN_TIMEOUT = 10
LOGIN_WAIT_TIMEOUT = 60 * CONFIG.timeout_factor
SERIAL_TIMEOUT = 0.5 if CONFIG.timeout_factor > 1 else None


class BaseVM:
    """Class to represent a extract base vm."""
    logger = TestLog.get_global_log()

    def __init__(self, root_path, name, uuid, bin_path,
                 wrapper=None, args=None, mon_sock=None,
                 vnetnums=1, rng=False, max_bytes=0, vsocknums=0, balloon=False,
                 vmtype=CONFIG.vmtype, machine=None, freeze=False,
                 daemon=False, config=None, ipalloc="static", incoming=False,
                 error_test=False, dump_guest_core=True, mem_share=True):
        if wrapper is None:
            wrapper = []
        if args is None:
            args = []
        self.__qmp = None
        self.__qmp_set = True
        # Copy args in case ew modify them.
        self._args = list(args)
        self._console_address = None
        self._console_device_index = None
        self._console_device_type = None
        self._console_set = True
        self._events = []
        self._launched = False
        self._machine = machine
        self._monitor_address = mon_sock
        self._name = name
        self._popen = None
        self._remove_files = list()
        self._vm_monitor = None
        self.bin_path = bin_path
        self.config_json = config
        self.configdict = json.load(fp=open(self.config_json, "r"))
        self.console_manager = ConsoleManager()
        self.daemon = daemon
        self.dump_guest_core = dump_guest_core
        self.env = dict()
        self.error_test = error_test
        self.freeze = freeze
        self.full_command = None
        self.guest_ip = None
        self.guest_ips = list()
        self.incoming = incoming
        self.init_args = args
        self.interfaces = []
        self.ipalloc_type = ipalloc
        self.logpath = '/var/log/stratovirt'
        self.mem_share = mem_share
        self.mon_sock = mon_sock
        self.pid = None
        self.pidfile = None
        self.root_path = root_path
        self._sock_dir = self.root_path
        self.seccomp = True
        self.serial_console = None
        self.serial_log = TestLog.get_log_handle(self._name + "_serial")
        self.serial_session = None
        self.ssh_session = None
        self.taps = list()
        self.vhost_type = None
        self.vmid = uuid
        self.vmtype = vmtype
        self.vnetnums = vnetnums
        self.rng = rng
        self.max_bytes = max_bytes
        self.vsock_cid = list()
        self.vsocknums = vsocknums
        self.with_json = False
        self.withmac = False
        self.withpid = False
        self.wrapper = wrapper
        self.balloon = balloon
        self.deflate_on_oom = False

    def __enter__(self):
        return self

    def __del__(self):
        self.kill()

    def get_pid(self):
        """Get pid from ps"""
        _cmd = "ps -ef | grep %s | grep %s | " \
               "awk '{print $2}' | head -1" % (self.bin_path, self.vmid)
        output = subprocess.getoutput(_cmd)
        LOG.debug("get output %s" % output.strip())
        return int(output.strip())

    def get_pid_from_file(self):
        """Get pid from file"""
        if self.pidfile is not None:
            with open(self.pidfile, 'r') as pidf:
                return int(pidf.read())

        return None

    def _pre_shutdown(self):
        pass

    def shutdown(self, has_quit=False):
        """Terminate the VM and clean up"""
        if not self._launched:
            return

        self._pre_shutdown()
        if self.daemon or self.is_running():
            if self.__qmp:
                try:
                    if not has_quit:
                        self.cmd('quit')
                        self.event_wait(name='SHUTDOWN', timeout=10,
                                        match={'data': {'guest': False, 'reason': 'host-qmp-quit'}})
                # Kill popen no matter what exception occurs
                # pylint: disable=broad-except
                except Exception:
                    logging.error('match failed!')
                    self._popen.kill()
            else:
                self._popen.kill()
        if not self.daemon:
            self._popen.wait()
        else:
            self.wait_pid_exit()
        self._post_shutdown()
        self._launched = False

    def destroy(self, signal=9):
        """Destroy the vm by send signal"""
        if not self._launched:
            return

        self._pre_shutdown()
        subprocess.run("kill -%d %s" % (signal, self.pid), shell=True, check=True)
        if not self.daemon:
            self._popen.wait()
        else:
            self.wait_pid_exit()
        self._post_shutdown()
        self._launched = False

    def inshutdown(self):
        """Terminate the vm from inner"""
        if not self._launched:
            return

        self._pre_shutdown()
        if self.daemon or self.is_running():
            if self.serial_session:
                try:
                    self.serial_session.run_func("cmd_output", "reboot")
                    self.event_wait(name='SHUTDOWN')
                # pass no matter what exception occurs
                # pylint: disable=broad-except
                except Exception:
                    pass
            else:
                return
        if not self.daemon:
            self._popen.wait()
        else:
            self.wait_pid_exit()
        self._post_shutdown()
        self._launched = False

    def _post_shutdown(self):
        """Post shutdown"""
        exitcode = self.exitcode()
        if exitcode is not None and exitcode < 0:
            msg = 'received signal %i: %s'
            if self.full_command:
                command = ' '.join(self.full_command)
            else:
                command = ''
            LOG.warning(msg, exitcode, command)

        if self.__qmp:
            self.close_sock()

        if self.serial_session:
            self.serial_session.run_func("close")

        if self.ssh_session:
            self.ssh_session.close()

        for _file in self._remove_files:
            utils_common.remove_existing_file(_file)

        if self.withpid:
            subprocess.run("rm -rf %s" % self.pidfile, shell=True, check=True)

    def _pre_launch(self):
        if self.__qmp_set:
            if self._monitor_address is not None:
                self._vm_monitor = self._monitor_address
                if not isinstance(self._vm_monitor, tuple):
                    self._remove_files.append(self._vm_monitor)
            else:
                self._vm_monitor = os.path.join(self._sock_dir,
                                                self._name + "_" + self.vmid + ".sock")
                self._remove_files.append(self._vm_monitor)

        self.parser_config_to_args()

    def create_serial_control(self):
        """Create serial control"""
        self._wait_console_create()
        self.serial_console = aexpect.ShellSession(
            "/usr/bin/nc -U %s" % self._console_address,
            auto_close=False,
            output_func=self.serial_log.debug,
            prompt=r"[\#\$]",
            status_test_command="echo $?"
        )
        self.console_manager.config_console(self.serial_console)

    def create_ssh_session(self):
        """Create ssh session"""
        user_known_hosts_file = '/dev/null'
        port = 22
        _, output = self.serial_cmd("ping -c 2 %s" % NETWORKS.ipaddr)
        LOG.debug("check ping result %s" % output)
        ssh_session = aexpect.ShellSession(
            "ssh %s -o UserKnownHostsFile=%s -o StrictHostKeyChecking=no -p %s" % (
                self.guest_ip, user_known_hosts_file, port
            ),
            auto_close=False,
            output_func=self.serial_log.debug,
            prompt=r"[\#\$]",
            status_test_command="echo $?"
        )

        try:
            self.console_manager.handle_session(ssh_session,
                                                username=CONFIG.vm_username,
                                                password=CONFIG.vm_password,
                                                prompt=r"[\#\$]", timeout=60.0)
        except Exception:
            ssh_session.close()
            raise Exception("handle_prompts ssh session failed!")

        return ssh_session

    def scp_file(self, local_file, dest_file):
        """
        Send file to guest

        Args:
            local_file: local file in host
            dest_file: dest file in guest
        """
        remote.scp_to_remote(self.guest_ip, 22, CONFIG.vm_username,
                             CONFIG.vm_password, local_file, dest_file,
                             output_func=self.serial_log.debug, timeout=60.0)

    def launch(self):
        """Start a vm and establish a qmp connection"""
        del self._args
        self._args = list(self.init_args)
        self._pre_launch()
        self.full_command = (self.wrapper + [self.bin_path] + self._base_args() + self._args)
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

    def post_launch_serial(self):
        """Create a serial and wait for active"""
        if self._console_set:
            self.create_serial_control()
            self._wait_for_active()
        else:
            time.sleep(2)

    def post_launch_qmp(self):
        """Set a QMPMonitorProtocol"""
        if isinstance(self.mon_sock, tuple):
            self.qmp_monitor_protocol(self.mon_sock)
        else:
            self.qmp_monitor_protocol(self._vm_monitor)
        if self.__qmp:
            self.connect()

    def post_launch_vnet(self):
        """Nothing is needed at present"""
        pass

    def _post_launch(self):
        self._launched = True
        if self.incoming:
            return

        self.post_launch_serial()
        self.post_launch_qmp()
        if self.vnetnums > 0:
            self.post_launch_vnet()
            self.config_network(self.ipalloc_type)
            if self.ssh_session:
                self.ssh_session.close()
            self.ssh_session = self.create_ssh_session()

    @retry(wait_fixed=200, stop_max_attempt_number=50)
    def _wait_console_create(self):
        os.stat(self._console_address)

    @retry(wait_fixed=1000, stop_max_attempt_number=30)
    def wait_pid_exit(self):
        """Wait vm pid when vm exit"""
        LOG.debug("===== check pid %s exit" % self.pid)
        if os.path.exists("/proc/%d" % self.pid):
            raise VMLifeError("check pid exit failed, vm shutdown/destroy failed!")

    def _wait_for_active(self):
        """Wait vm for active"""
        self.serial_session = self.wait_for_serial_login()

    def config_network(self, model='dhcp', index=0):
        """Config vm network"""
        self.interfaces = self.get_interfaces_inner()
        if 'stratovirt' in self.vmtype:
            self.serial_session.run_func("cmd_output", 'systemctl stop NetworkManager')
            self.serial_session.run_func("cmd_output", 'systemctl stop firewalld')
            # enable ssh login
            _cmd = "sed -i \"s/^PermitRootLogin.*/PermitRootLogin yes/g\" /etc/ssh/sshd_config"
            self.serial_cmd(_cmd)
            self.serial_cmd("systemctl restart sshd")
        if 'dhcp' in model:
            self.serial_session.run_func("cmd_output", ("dhclient %s" % self.interfaces[index]))
            _cmd = "ifconfig %s | awk '/inet/ {print $2}' | cut -f2 -d ':' | " \
                   "awk 'NR==1 {print $1}'" % self.interfaces[index]
            output = self.serial_session.run_func("cmd_output", _cmd)
            self.guest_ips.append(output)
            if index == 0:
                self.guest_ip = output
        elif 'static' in model:
            _cmd = "ip addr show %s | grep inet | awk '{print $2}' | xargs -i -n1 ip addr del {} dev %s" % (
                self.interfaces[index], self.interfaces[index])
            self.serial_console.cmd_output(_cmd)
            _cmd = "ip link set %s up" % self.interfaces[index]
            self.serial_console.cmd_output(_cmd)
            ipinfo = NETWORKS.alloc_ipaddr(self.taps[index]["name"], index=index)
            _cmd = "ip addr add %s/%s dev %s" % (ipinfo["ipaddr"],
                                                 ipinfo["netmasklen"], self.interfaces[index])
            self.serial_console.cmd_output(_cmd)
            _cmd = "ip route add default gw %s" % ipinfo["gateway"]
            self.serial_console.cmd_output(_cmd)
            self.guest_ips.append(ipinfo["ipaddr"])
            if index == 0:
                self.guest_ip = ipinfo["ipaddr"]
        LOG.debug("==== check ip addr info in Guest ======\n %s" %
                  self.serial_session.run_func("cmd_output", "ip addr"))

    def kill(self):
        """Kill vm"""
        try:
            self.shutdown()
        # destroy vm no matter what exception occurs
        # pylint: disable=broad-except
        except Exception as err:
            LOG.warning("got exception %s, try to destroy vm" % err)
            self.destroy()

        for tap in self.taps:
            NETWORKS.clean_tap(tap["name"])

    def _machine_args(self, args):
        if self._machine == "microvm":
            _dumpcore = "on" if self.dump_guest_core else "off"
            _memshare = "on" if self.mem_share else "off"
            args.extend(['-machine', '%s,dump-guest-core=%s,mem-share=%s'
                         % (self._machine, _dumpcore, _memshare)])
        else:
            args.extend(['-machine', self._machine])

    def _base_args(self):
        args = []
        if self._name:
            args.extend(['-name', self._name])
        # uuid is not supported yet, no need to add uuid
        if self.logpath:
            args.extend(['-D', self.logpath])
        if self.__qmp_set:
            if "stratovirt" in self.vmtype:
                if isinstance(self.mon_sock, tuple):
                    args.extend(['-qmp',
                                 "tcp:" + str(self.mon_sock[0]) + ":" + str(self.mon_sock[1])])
                else:
                    args.extend(['-qmp', "unix:" + self.mon_sock + ",server,nowait"])
            else:
                moncdev = 'socket,id=mon,path=%s' % self.mon_sock
                args.extend(['-chardev', moncdev, '-mon',
                             'chardev=mon,mode=control'])

        if self.withpid:
            self.pidfile = os.path.join(self._sock_dir, self._name + "_" + "pid.file")
            args.extend(['-pidfile', self.pidfile])
        if self._machine is not None:
            self._machine_args(args)

        if self._console_set:
            self._console_address = os.path.join(self._sock_dir,
                                                 self._name + "_" + self.vmid + "-console.sock")
            # It doesn't need to create it first.
            self._remove_files.append(self._console_address)
            args.extend(['-device', 'virtio-serial-device', '-chardev', 'socket,path=%s,id=virtioconsole0,server,nowait' % self._console_address, '-device', 'virtconsole,chardev=virtioconsole0,id=console_0'])

        if self.vnetnums > 0:
            for _ in range(self.vnetnums - len(self.taps)):
                tapinfo = NETWORKS.generator_tap()
                LOG.debug("current tapinfo is %s" % tapinfo)
                self.taps.append(tapinfo)

            for tapinfo in self.taps:
                tapname = tapinfo["name"]
                _tempargs = "tap,id=%s,ifname=%s" % (tapname, tapname)
                if self.vhost_type:
                    _tempargs += ",vhost=on"
                _devargs = "virtio-net-device,netdev=%s,id=%s" % (tapname, tapname)
                if self.withmac:
                    _devargs += ",mac=%s" % tapinfo["mac"]
                args.extend(['-netdev', _tempargs, '-device', _devargs])

        if self.rng:
            rngcfg = 'rng-random,id=objrng0,filename=/dev/urandom'
            if self.max_bytes == 0:
                devcfg = 'virtio-rng-device,rng=objrng0'
            else:
                devcfg = 'virtio-rng-device,rng=objrng0,max-bytes=%s,period=1000' % self.max_bytes
            args.extend(['-object', rngcfg, '-device', devcfg])

        if self.vsocknums > 0:
            if VSOCKS.init_vsock():
                for _ in range(self.vsocknums - len(self.vsock_cid)):
                    sockcid = VSOCKS.find_contextid()
                    self.vsock_cid.append(sockcid)
                    args.extend(['-device',
                                 'vsock,id=vsock-%s,'
                                 'guest-cid=%s' % (sockcid, sockcid)])

        if self.balloon:
            if self.deflate_on_oom:
                ballooncfg = 'deflate-on-oom=true'
            else:
                ballooncfg = 'deflate-on-oom=false'
            args.extend(['-device', 'virtio-balloon-device', ballooncfg])

        if "stratovirt" in self.vmtype and not self.seccomp:
            self._args.append('-disable-seccomp')

        if self.daemon:
            self._args.append('-daemonize')

        if self.freeze:
            self._args.extend(['-S'])
        return args

    def is_running(self):
        """Returns true if the VM is running."""
        return self._popen is not None and self._popen.poll() is None

    def exitcode(self):
        """Returns the exit code if possible, or None."""
        if self._popen is None:
            return None
        return self._popen.poll()

    def add_drive(self, **kwargs):
        """Add drive"""
        drivetemp = dict()
        drivetemp["drive_id"] = kwargs.get("drive_id", utils_network.generate_random_name())
        drivetemp["path_on_host"] = kwargs.get('path_on_host', None)
        drivetemp["read_only"] = kwargs.get("read_only", "true")
        if "drive" in self.configdict:
            self.configdict["drive"].append(drivetemp)
        else:
            self.configdict["drive"] = [drivetemp]

    def basic_config(self, **kwargs):
        """Change configdict"""
        if "vcpu_count" in kwargs:
            self.configdict["machine-config"]["vcpu_count"] = kwargs.get("vcpu_count")
            del kwargs["vcpu_count"]
        if "max_vcpus" in kwargs:
            self.configdict["machine-config"]["max_vcpus"] = kwargs.get("max_vcpus")
            del kwargs["max_vcpus"]
        if "mem_size" in kwargs:
            self.configdict["machine-config"]["mem_size"] = kwargs.get("mem_size")
            del kwargs["mem_size"]
        if "mem_path" in kwargs:
            self.configdict["machine-config"]["mem_path"] = kwargs.get("mem_path")
            del kwargs["mem_path"]
        if "vhost_type" in kwargs:
            self.vhost_type = kwargs.get("vhost_type")
            del kwargs["vhost_type"]

        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def parser_config_to_args(self):
        """Parser json config to args"""
        if self.configdict is None:
            return

        if self.with_json:
            with open(self.config_json, "w") as fpdest:
                json.dump(self.configdict, fpdest)
            self.add_args('-config', self.config_json)
        else:
            configdict = self.configdict
            if "boot-source" in configdict:
                if "kernel_image_path" in configdict["boot-source"]:
                    self.add_args('-kernel', configdict["boot-source"]["kernel_image_path"])
                if "boot_args" in configdict["boot-source"]:
                    self.add_args('-append', configdict["boot-source"]["boot_args"])
                if "initrd" in configdict["boot-source"]:
                    self.add_args('-initrd', configdict["boot-source"]["initrd"])

            if "machine-config" in configdict:
                _temp_cpu_value = ""
                if "vcpu_count" in configdict["machine-config"]:
                    _temp_cpu_value = str(configdict["machine-config"]["vcpu_count"])
                if "max_vcpus" in configdict["machine-config"]:
                    _temp_cpu_value += ",maxcpus=%s" % configdict["machine-config"]["max_vcpus"]
                if _temp_cpu_value != "":
                    self.add_args('-smp', _temp_cpu_value)
                _temp_mem_value = ""
                if "mem_size" in configdict["machine-config"]:
                    _temp_mem_value = str(configdict["machine-config"]["mem_size"])
                if "mem_slots" in configdict["machine-config"] and \
                        "max_mem" in configdict["machine-config"]:
                    _temp_mem_value += ",slots=%s,maxmem=%s" % \
                                       (configdict["machine-config"]["mem_slots"],
                                        configdict["machine-config"]["max_mem"])
                if _temp_mem_value != "":
                    self.add_args('-m', _temp_mem_value)
                if "mem_path" in configdict["machine-config"]:
                    self.add_args('-mem-path', configdict["machine-config"]["mem_path"])

            for drive in configdict.get("drive", []):
                _temp_drive_value = ""
                if "drive_id" in drive:
                    _temp_drive_value = "id=%s" % drive["drive_id"]
                if "path_on_host" in drive:
                    _temp_drive_value += ",file=%s" % drive["path_on_host"]
                if "read_only" in drive:
                    _temp = "on" if drive["read_only"] else "off"
                    _temp_drive_value += ",readonly=%s" % _temp
                if _temp_drive_value != "":
                    self.add_args('-drive', _temp_drive_value)
                    self.add_args('-device', 'virtio-blk-device,drive=%s' % drive["drive_id"])

    def add_env(self, key, value):
        """Add key, value to self.env"""
        self.env[key] = value

    def add_args(self, *args):
        """Adds to the list of extra arguments to cmdline"""
        self._args.extend(args)

    def add_machine(self, machine_type):
        """Add the machine type to cmdline"""
        self._machine = machine_type

    def console_enable(self):
        """Set console"""
        self._console_set = True

    def console_disable(self):
        """Unset console"""
        self._console_set = False

    def set_device_type(self, device_type):
        """Set device type"""
        self._console_device_type = device_type

    def set_console_device_index(self, console_device_index):
        """Set console device index"""
        if not console_device_index:
            console_device_index = 0
        self._console_device_index = console_device_index

    def serial_login(self, timeout=LOGIN_TIMEOUT, username=CONFIG.vm_username,
                     password=CONFIG.vm_password):
        """Log into vm by virtio-console"""
        prompt = r"[\#\$]\s*$"
        status_test_command = "echo $?"
        return self.console_manager.create_session(status_test_command,
                                                   prompt, username, password,
                                                   timeout)

    def wait_for_serial_login(self, timeout=LOGIN_WAIT_TIMEOUT,
                              internal_timeout=LOGIN_TIMEOUT,
                              username=CONFIG.vm_username, password=CONFIG.vm_password):
        """
        Make multiple attempts to log into the guest via serial console.

        Args:
            timeout: Time (seconds) to keep trying to log in.
            internal_timeout: Timeout to pass to serial_login().

        Returns:
            ConsoleSession instance.
        """
        LOG.debug("Attempting to log into '%s' via serial console "
                  "(timeout %ds)", self._name, timeout)
        end_time = time.time() + timeout
        while time.time() < end_time and (self.daemon or self.is_running()):
            try:
                session = self.serial_login(internal_timeout,
                                            username,
                                            password)
                break
            except SSHError:
                time.sleep(0.5)
                continue
        else:
            self.console_manager.close()
            raise LoginTimeoutError('exceeded %s s timeout' % timeout)
        return session

    def get_interfaces_inner(self):
        """Get interfaces list from guest inner"""
        cmd = "cat /proc/net/dev"
        status, output = self.serial_cmd(cmd)
        interfaces = []
        if status != 0:
            return interfaces
        for line in output.splitlines():
            temp = line.split(":")
            if len(temp) != 2:
                continue
            if "lo" not in temp[0] and "virbr0" not in temp[0]:
                interfaces.append(temp[0].strip())

        interfaces.sort()
        return interfaces

    def serial_cmd(self, cmd):
        """
        Run a cmd in vm via serial console session

        Args:
            cmd: cmd run in vm

        Returns:
            A tuple (status, output) where status is the exit status
            and output is the output of cmd
        """
        LOG.debug("Attempting to run cmd '%s' in vm" % cmd)
        return self.serial_session.run_func("cmd_status_output", cmd, internal_timeout=SERIAL_TIMEOUT)

    def get_guest_hwinfo(self):
        """
        Get guest hwinfo via ssh_session

        Returns:
            {"cpu": {"vcpu_count": xx, "maxvcpu": xx},
            "mem": {"memsize": xx, "maxmem": xx},
            "virtio": {"virtio_blk": [{"name": "virtio0"}],
                    "virtio_console": [{"name": "virtio1"}],
                    "virtio_net": [{"name": "virtio2"}],
                    "virtio_rng": [{"name": "virtio3"}],
                    }
            }
        """
        retdict = {"cpu": {}, "mem": {}, "virtio": {}}
        if self.ssh_session is not None:
            vcpu_count = int(self.ssh_session.cmd_output("grep -c processor /proc/cpuinfo"))
            memsize = int(self.ssh_session.cmd_output("grep MemTotal /proc/meminfo | awk '{print $2}'"))
            retdict["cpu"] = {"vcpu_count": vcpu_count, "maxvcpu": vcpu_count}
            retdict["mem"] = {"memsize": memsize, "maxmem": memsize}
            # ignore virtio_rng device now
            for dev in ["virtio_blk", "virtio_net", "virtio_console"]:
                devdir = "/sys/bus/virtio/drivers/%s" % dev
                _cmd = "test -d %s && ls %s | grep virtio" % (devdir, devdir)
                virtiodevs = self.ssh_session.cmd_output(_cmd).strip().split()
                for virtiodev in virtiodevs:
                    _tempdev = {"name": virtiodev}
                    if dev not in retdict["virtio"]:
                        retdict["virtio"][dev] = list()
                    retdict["virtio"][dev].append(_tempdev)

        return retdict

    def get_lsblk_info(self):
        """
        Get lsblk info

        Returns:
            {
                "vdx": {"size": xx, "readonly": xx},
            }
        """
        retdict = {}
        if self.ssh_session is not None:
            _output = self.ssh_session.cmd_output("lsblk")
            for line in _output.split("\n"):
                temp = line.split()
                if len(temp) == 6:
                    name = temp[0]
                    size = temp[3]
                    readonly = temp[4]
                    if name not in retdict:
                        retdict[name] = {"size": size, "readonly": readonly}

        return retdict

    def stop(self):
        """Pause all vcpu"""
        return self.qmp_command("stop")

    def cont(self):
        """Resume paused vcpu"""
        return self.qmp_command("cont")

    def device_add(self, **kwargs):
        """Hotplug device"""
        return self.qmp_command("device_add", **kwargs)

    def device_del(self, **kwargs):
        """Unhotplug device"""
        return self.qmp_command("device_del", **kwargs)

    def netdev_add(self, **kwargs):
        """Hotplug a netdev"""
        return self.qmp_command("netdev_add", **kwargs)

    def netdev_del(self, **kwargs):
        """Unhotplug a netdev"""
        return self.qmp_command("netdev_del", **kwargs)

    def add_disk(self, diskpath, index=1, check=True):
        """Hotplug a disk to vm"""
        LOG.debug("hotplug disk %s to vm" % diskpath)
        devid = "drive-%d" % index
        resp = self.qmp_command("blockdev-add", node_name="drive-%d" % index,
                                file={"driver": "file", "filename": diskpath})

        LOG.debug("blockdev-add return %s" % resp)
        if check:
            assert "error" not in resp
        resp = self.device_add(id=devid, driver="virtio-blk-mmio", addr=str(hex(index)))
        LOG.debug("device_add return %s" % resp)
        if check:
            assert "error" not in resp

        return resp

    def del_disk(self, index=1, check=True):
        """Unplug a disk"""
        LOG.debug("unplug diskid %d to vm" % index)
        devid = "drive-%d" % index
        resp = self.device_del(id=devid)
        if check:
            assert "error" not in resp

    def add_net(self, check=True, config_addr=True):
        """Hotplug a net device"""
        tapinfo = NETWORKS.generator_tap()
        LOG.debug("hotplug tapinfo is %s" % tapinfo)
        self.taps.append(tapinfo)
        tapname = tapinfo["name"]
        resp = self.netdev_add(id=tapname, ifname=tapname)
        if check:
            assert "error" not in resp
        LOG.debug("netdev_add return %s" % resp)
        resp = self.device_add(id=tapname, driver="virtio-net-mmio", addr="0x1")
        if check:
            assert "error" not in resp
        if config_addr:
            self.config_network(index=1, model=self.ipalloc_type)
        LOG.debug("device_add return %s" % resp)
        return resp

    def del_net(self, check=True):
        """Del net"""
        tapinfo = self.taps[-1]
        tapname = tapinfo["name"]
        # clean ip addr in guest

        resp = self.device_del(id=tapname)
        if check:
            assert "error" not in resp
        if "error" not in resp:
            NETWORKS.clean_tap(tapinfo["name"])
            self.taps.pop()
            if len(self.guest_ips) > 1:
                self.guest_ips.pop()
        LOG.debug("device_del return %s", resp)

    def query_hotpluggable_cpus(self):
        """Query hotpluggable cpus"""
        return self.qmp_command("query-hotpluggable-cpus")

    def query_cpus(self):
        """Query cpus"""
        return self.qmp_command("query-cpus")

    def query_status(self):
        """Query status"""
        return self.qmp_command("query-status")

    def query_balloon(self):
        """Query balloon size"""
        return self.qmp_command("query-balloon")

    def balloon_set(self, **kwargs):
        """Set balloon size"""
        return self.qmp_command("balloon", **kwargs)

    def qmp_monitor_protocol(self, address):
        """Set QMPMonitorProtocol"""
        self.__qmp = {'events': [],
                      'address': address,
                      'sock': socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                      }

    def enable_qmp_set(self):
        """
        Enable qmp monitor
        set in preparation phase
        """
        self.__qmp_set = True

    def disable_qmp_set(self):
        """
        Disable qmp monitor
        set in preparation phase
        """
        self.__qmp = None
        self.__qmp_set = False

    def __sock_recv(self, only_event=False):
        """Get data from socket"""
        recv = self.__qmp['sock'].recv(1024).decode('utf-8').split('\n')
        if recv and not recv[-1]:
            recv.pop()
        resp = None
        while recv:
            resp = json.loads(recv.pop(0))
            if 'event' not in resp:
                return resp
            self.logger.debug("-> %s", resp)
            self.__qmp['events'].append(resp)
            if only_event:
                return resp
        return resp

    def get_events(self, wait=False, only_event=False):
        """
        Get new events or event from socket.
        Push them to __qmp['events']

        Args:
            wait (bool): block until an event is available.
            wait (float): If wait is a float, treat it as a timeout value.

        Raises:
            QMPTimeoutError: If a timeout float is provided and the timeout
            period elapses.
            QMPConnectError: If wait is True but no events could be retrieved
            or if some other error occurred.
        """

        # Wait for new events, if needed.
        # if wait is 0.0, this means "no wait" and is also implicitly false.
        if not self.__qmp['events'] and wait:
            if isinstance(wait, float):
                self.__qmp['sock'].settimeout(wait)
            try:
                ret = self.__sock_recv(only_event=True)
            except socket.timeout:
                raise QMPTimeoutError("Timeout waiting for event")
            except:
                raise QMPConnectError("Error while receiving from socket")
            if ret is None:
                raise QMPConnectError("Error while receiving from socket")
            self.__qmp['sock'].settimeout(None)

        if self.__qmp['events']:
            if only_event:
                return self.__qmp['events'].pop(0)
            return self.__qmp['events']
        return None

    def connect(self):
        """
        Connect to the QMP Monitor and perform capabilities negotiation.

        Returns:
            QMP greeting if negotiate is true
            None if negotiate is false

        Raises:
            QMPConnectError if the greeting is not received or QMP not in greetiong
            QMPCapabilitiesError if fails to negotiate capabilities
        """
        self.__qmp['sock'].connect(self.__qmp['address'])
        greeting = self.__sock_recv()
        if greeting is None or "QMP" not in greeting:
            raise QMPConnectError
        # Greeting seems ok, negotiate capabilities
        resp = self.cmd('qmp_capabilities')
        if resp and "return" in resp:
            return greeting
        raise QMPCapabilitiesError

    def qmp_reconnect(self):
        """Reconnect qmp when sock is dead"""
        if self.__qmp:
            self.close_sock()

        if isinstance(self.mon_sock, tuple):
            self.qmp_monitor_protocol(self.mon_sock)
        else:
            self.qmp_monitor_protocol(self._vm_monitor)
        if self.__qmp:
            self.connect()

    def cmd(self, name, args=None, cmd_id=None):
        """
        Build a QMP command and send it to the monitor.

        Args:
            name: command name
            args: command arguments
            cmd_id: command id
        """
        qmp_cmd = {'execute': name}
        if args:
            qmp_cmd.update({'arguments': args})
        if cmd_id:
            qmp_cmd.update({'id': cmd_id})

        self.logger.debug("<- %s", qmp_cmd)
        try:
            self.__qmp['sock'].sendall(json.dumps(qmp_cmd).encode('utf-8'))
        except OSError as err:
            if err.errno == errno.EPIPE:
                return None
            raise err
        resp = self.__sock_recv()
        self.logger.debug("-> %s", resp)
        return resp

    def error_cmd(self, cmd, **kwds):
        """Build and send a QMP command to the monitor, report errors if any"""
        ret = self.cmd(cmd, kwds)
        if "error" in ret:
            raise Exception(ret['error']['desc'])
        return ret['return']

    def clear_events(self):
        """Clear current list of pending events."""
        self.__qmp['events'] = []

    def close_sock(self):
        """Close the socket and socket file."""
        if self.__qmp['sock']:
            self.__qmp['sock'].close()

    def settimeout(self, timeout):
        """Set the socket timeout."""
        self.__qmp['sock'].settimeout(timeout)

    def is_af_unix(self):
        """Check if the socket family is AF_UNIX."""
        return socket.AF_UNIX == self.__qmp['sock'].family

    def qmp_command(self, cmd, **args):
        """Run qmp command"""
        qmp_dict = dict()
        for key, value in args.items():
            if key.find("_") != -1:
                qmp_dict[key.replace('_', '-')] = value
            else:
                qmp_dict[key] = value

        rep = self.cmd(cmd, args=qmp_dict)
        if rep is None:
            raise QMPError("Monitor was closed")

        return rep

    def qmp_event_acquire(self, wait=False, return_list=False):
        """
        Get qmp event or events.

        Args:
            return_list: if return_list is True, then return qmp
            events. Else, return a qmp event.
        """
        if not return_list:
            if not self._events:
                return self.get_events(wait=wait, only_event=True)
            return self._events.pop(0)
        event_list = self.get_events(wait=wait)
        event_list.extend(self._events)
        self._events.clear()
        self.clear_events()
        return event_list

    def event_wait(self, name, timeout=60.0, match=None):
        """
        Wait for an qmp event to match exception event.

        Args:
            match: qmp match event, such as
            {'data':{'guest':False,'reason':'host-qmp-quit'}}
        """
        while True:
            event = self.get_events(wait=timeout, only_event=True)
            try:
                if event['event'] == name:
                    for key in match:
                        if key in event and match[key] == event[key]:
                            return event
            except TypeError:
                if event['event'] == name:
                    return event
            self._events.append(event)
