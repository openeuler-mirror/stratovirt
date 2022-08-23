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
from retrying import retry
from utils.config import CONFIG
from utils import utils_common
from utils import utils_network
from utils import remote
from utils.utils_logging import TestLog
from utils.session import ConsoleManager
from utils.resources import NETWORKS
from utils.exception import VMLifeError
from utils.exception import QMPError
from utils.exception import QMPConnectError
from utils.exception import QMPCapabilitiesError
from utils.exception import QMPTimeoutError
from utils.exception import SSHError
from utils.exception import LoginTimeoutError
from subprocess import getstatusoutput

LOG = TestLog.get_global_log()
LOGIN_TIMEOUT = 10
LOGIN_WAIT_TIMEOUT = 60 * CONFIG.timeout_factor
SERIAL_TIMEOUT = 0.5 if CONFIG.timeout_factor > 1 else None


class BaseVM:
    """Class to represent a extract base vm."""

    def __init__(self, root_path, name, uuid, bin_path, args=None, mon_sock=None,
                 vnetnums=1, rng=False, max_bytes=0, vsocknums=0, balloon=False,
                 vmtype=CONFIG.vmtype, machine=None, freeze=False,
                 daemon=False, config=None, ipalloc="static", incoming=False,
                 error_test=False, dump_guest_core=True, mem_share=True):
        if args is None:
            args = []
        self.qmp = None
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
        self.vhostfd = None
        self.net_iothread = None
        self.iothreads = 0
        self.vmid = uuid
        self.vmtype = vmtype
        self.vnetnums = vnetnums
        self.rng = rng
        self.max_bytes = max_bytes
        self.rng_files = '/dev/urandom'
        self.vsock_cid = list()
        self.vsocknums = vsocknums
        self.withmac = False
        self.withpid = False
        self.balloon = balloon
        self.deflate_on_oom = False
        self.free_page_reporting = False
        self.quickstart_incoming = None

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

    def get_rss_with_status_check(self):
        INVALID_VALUE = -1
        cmd = "ps -q %d -o rss=" % self.pid
        status, output = getstatusoutput(cmd)
        assert status == 0
        return int(output)

    def memory_stress(self, thread_num=2, vm_bytes='1G', timeout=20):
        status, _ = self.serial_cmd("stress-ng --vm %d --vm-bytes %s --vm-keep --timeout %d" % (thread_num, vm_bytes, timeout))
        if status != 0:
            logging.error("Cannot execute stress in stratovirt.")
            assert status == 0
        time.sleep(20)

    def _pre_shutdown(self):
        pass

    def shutdown(self, has_quit=False):
        """Terminate the VM and clean up"""
        if not self._launched:
            return

        self._pre_shutdown()
        if self.daemon or self.is_running():
            if self.qmp:
                try:
                    if not has_quit:
                        self.qmp.qmp_command('quit')
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

        if self.qmp:
            self.qmp.close_sock()

        if self.serial_session:
            self.serial_session.run_func("close")

        if self.ssh_session:
            self.ssh_session.close()

        for _file in self._remove_files:
            utils_common.remove_existing_file(_file)

        if self.withpid:
            subprocess.run("rm -rf %s" % self.pidfile, shell=True, check=True)

    def _pre_launch(self):
        if self._monitor_address is not None:
            self._vm_monitor = self._monitor_address
            if not isinstance(self._vm_monitor, tuple):
                self._remove_files.append(self._vm_monitor)
        else:
            self._vm_monitor = os.path.join(self._sock_dir,
                                            self._name + "_" + self.vmid + ".sock")
            self._remove_files.append(self._vm_monitor)

    def make_iothread_cmd(self, args):
        """make iothread cmdline"""
        _temp_iothread_args = ""
        for i in range(1, self.iothreads + 1):
            _temp_iothread_args = "iothread,id=iothread%s" % i
            args.extend(["-object", _temp_iothread_args])

        return args

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


    def post_launch_serial(self):
        """Create a serial and wait for active"""
        if self._console_set:
            self.create_serial_control()
            self._wait_for_active()
        else:
            time.sleep(2)

    def post_launch_qmp(self):
        """Set a QMPMonitorProtocol"""
        self.qmp = QMPProtocol(self._vm_monitor)
        if self.qmp:
            self.qmp.connect()

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

    @retry(wait_fixed=1000, stop_max_attempt_number=70)
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
            _cmd = "ip address show %s | awk '/inet/ {print $2}' | cut -f2 -d ':' | " \
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

    def _common_args(self):
        args = []
        if self._name:
            args.extend(['-name', self._name])
        # uuid is not supported yet, no need to add uuid
        if self.logpath:
            args.extend(['-D', self.logpath])

        if "stratovirt" in self.vmtype:
            args.extend(['-qmp', "unix:" + self.mon_sock + ",server,nowait"])

        if self.withpid:
            self.pidfile = os.path.join(self._sock_dir, self._name + "_" + "pid.file")
            args.extend(['-pidfile', self.pidfile])

        if self._machine is not None:
            self._machine_args(args)

        if "stratovirt" in self.vmtype and not self.seccomp:
            args.append('-disable-seccomp')

        if self.daemon:
            args.append('-daemonize')

        if self.freeze:
            args.extend(['-S'])

        if self.quickstart_incoming:
            args.extend(['-incoming', self.quickstart_incoming])

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
        """Add drive and device"""
        drivetemp = dict()
        devicetemp = dict()
        drivetemp["drive_id"] = kwargs.get("drive_id", utils_network.generate_random_name())
        devicetemp["drive_id"] = drivetemp["drive_id"]
        drivetemp["path_on_host"] = kwargs.get('path_on_host', None)
        drivetemp["read_only"] = kwargs.get("read_only", "true")
        if "drive" in self.configdict["block"][0]:
            self.configdict["block"][0]["drive"].append(drivetemp)
        else:
            self.configdict["block"][0]["drive"] = [drivetemp]

        if "device" in self.configdict["block"][0]:
            self.configdict["block"][0]["device"].append(devicetemp)
        else:
            self.configdict["block"][0]["device"] = [devicetemp]


    def add_env(self, key, value):
        """Add key, value to self.env"""
        self.env[key] = value

    def add_args(self, *args):
        """Adds to the list of extra arguments to cmdline"""
        self._args.extend(args)

    def add_machine(self, machine_type):
        """Add the machine type to cmdline"""
        self._machine = machine_type


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

    def stop(self):
        """Pause all vcpu"""
        return self.qmp.qmp_command("stop")

    def migrate(self, **kwargs):
        """save a template"""
        return self.qmp.qmp_command("migrate", **kwargs)

    def cont(self):
        """Resume paused vcpu"""
        return self.qmp.qmp_command("cont")

    def device_add(self, **kwargs):
        """Hotplug device"""
        return self.qmp.qmp_command("device_add", **kwargs)

    def device_del(self, **kwargs):
        """Unhotplug device"""
        return self.qmp.qmp_command("device_del", **kwargs)

    def netdev_add(self, **kwargs):
        """Hotplug a netdev"""
        return self.qmp.qmp_command("netdev_add", **kwargs)

    def netdev_del(self, **kwargs):
        """Unhotplug a netdev"""
        return self.qmp.qmp_command("netdev_del", **kwargs)

    def add_disk(self, diskpath, index=1, check=True):
        """Hotplug a disk to vm"""
        LOG.debug("hotplug disk %s to vm" % diskpath)
        devid = "drive-%d" % index
        resp = self.qmp.qmp_command("blockdev-add", node_name="drive-%d" % index,
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
        return self.qmp.qmp_command("query-hotpluggable-cpus")

    def query_cpus(self):
        """Query cpus"""
        return self.qmp.qmp_command("query-cpus")

    def query_status(self):
        """Query status"""
        return self.qmp.qmp_command("query-status")

    def query_balloon(self):
        """Query balloon size"""
        return self.qmp.qmp_command("query-balloon")

    def balloon_set(self, **kwargs):
        """Set balloon size"""
        return self.qmp.qmp_command("balloon", **kwargs)

    def qmp_reconnect(self):
        """Reconnect qmp when sock is dead"""
        if self.qmp:
            self.qmp.close_sock()
        self.qmp = QMPProtocol(self._vm_monitor)
        if self.qmp:
            self.qmp.connect()

    def event_wait(self, name, timeout=60.0, match=None):
        """
        Wait for an qmp event to match exception event.

        Args:
            match: qmp match event, such as
            {'data':{'guest':False,'reason':'host-qmp-quit'}}
        """
        while True:
            event = self.qmp.get_events(wait=timeout, only_event=True)
            try:
                if event['event'] == name:
                    for key in match:
                        if key in event and match[key] == event[key]:
                            return event
            except TypeError:
                if event['event'] == name:
                    return event
            self._events.append(event)

class QMPProtocol:

    '''Set qmp monitor protocol'''
    def __init__(self, address):
        self.events = list()
        self.address = address
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def __sock_recv(self, only_event=False):
        """Get data from socket"""
        recv = self.sock.recv(1024).decode('utf-8').split('\n')
        if recv and not recv[-1]:
            recv.pop()
        resp = None
        while recv:
            resp = json.loads(recv.pop(0))
            if 'event' not in resp:
                return resp
            LOG.debug("-> %s", resp)
            self.events.append(resp)
            if only_event:
                return resp
        return resp

    def _cmd(self, name, args=None, cmd_id=None):
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

        LOG.debug("<- %s", qmp_cmd)
        try:
            self.sock.sendall(json.dumps(qmp_cmd).encode('utf-8'))
        except OSError as err:
            if err.errno == errno.EPIPE:
                return None
            raise err
        resp = self.__sock_recv()
        LOG.debug("-> %s", resp)
        return resp

    def qmp_command(self, cmd, **args):
        """Run qmp command"""
        qmp_dict = dict()
        for key, value in args.items():
            if key.find("_") != -1:
                qmp_dict[key.replace('_', '-')] = value
            else:
                qmp_dict[key] = value

        rep = self._cmd(cmd, args=qmp_dict)
        if rep is None:
            raise QMPError("Monitor was closed")

        return rep

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
        self.sock.connect(self.address)
        greeting = self.__sock_recv()
        if greeting is None or "QMP" not in greeting:
            raise QMPConnectError
        # Greeting seems ok, negotiate capabilities
        resp = self._cmd('qmp_capabilities')
        if resp and "return" in resp:
            return greeting
        raise QMPCapabilitiesError

    def clear_events(self):
        """Clear current list of pending events."""
        self.events = []

    def close_sock(self):
        """Close the socket and socket file."""
        if self.sock:
            self.sock.close()

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
        if not self.events and wait:
            if isinstance(wait, float):
                self.sock.settimeout(wait)
            try:
                ret = self.__sock_recv(only_event=True)
            except socket.timeout:
                raise QMPTimeoutError("Timeout waiting for event")
            except:
                raise QMPConnectError("Error while receiving from socket")
            if ret is None:
                raise QMPConnectError("Error while receiving from socket")
            self.sock.settimeout(None)

        if self.events:
            if only_event:
                return self.events.pop(0)
            return self.events
        return None
