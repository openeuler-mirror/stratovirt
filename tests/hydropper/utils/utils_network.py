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
"""utils common ops"""

import random
import socket
from subprocess import CalledProcessError
from subprocess import run

def generate_random_name():
    """Generate a random name for tap"""
    _code_list = []
    for i in range(10):
        _code_list.append(str(i))
    for i in range(97, 123):
        _code_list.append(chr(i))

    ret = 't'
    _prefix = random.sample(_code_list, 7)
    ret += ''.join(_prefix)
    _postfix = random.sample(_code_list, 2)
    ret += '-'
    ret += ''.join(_postfix)
    return ret

def generate_random_mac():
    """Generate random mac address"""
    try:
        output = run("ip route | grep default", shell=True, capture_output=True, check=True).stdout
        hostdev = str(output).split()[-1]
        hostmac = run(r"cat /sys/devices/virtual/net/%s/address" % hostdev,
                      shell=True, capture_output=True, check=False).stdout.strip()
        first_mac = hostmac.split(":")[0]
        second_mac, third_mac, fourth_mac = hostmac.split(":")[1:3]
    except (TypeError, KeyError, IndexError, CalledProcessError):
        first_mac, second_mac, third_mac = "00", "00", "00"
        fourth_mac = hex(random.randint(0x00, 0xff))[2:].zfill(2)

    fifth_mac = hex(random.randint(0x00, 0xff))[2:].zfill(2)
    mac = [first_mac, second_mac, third_mac, fourth_mac,
           fifth_mac, hex(random.randint(0x00, 0xff))[2:].zfill(2)]

    return ':'.join(mac)

def is_port_free(port, address):
    """
    Return True if the given port is available
    Currently we only check for TCP/UDP connections on IPv4/6

    Args:
        port: Port number
        address: Socket address to connect
    """
    families = (socket.AF_INET, socket.AF_INET6)
    protocols_type = (socket.SOCK_STREAM, socket.SOCK_DGRAM)
    sock = None
    localhost = True

    if address and address != "localhost":
        localhost = False
        # sock.connect always connects for UDP
        protocols_type = (socket.SOCK_STREAM, )

    try:
        for family in families:
            for protocol in protocols_type:
                try:
                    sock = socket.socket(family, protocol)
                    sock.connect((address, port))
                    return False
                except socket.error as exc:
                    # Unsupported combinations
                    if exc.errno in (93, 94):
                        continue
                    if localhost:
                        return True
                sock.close()
        return True
    finally:
        if sock is not None:
            sock.close()

def get_free_port(port_start=1024, port_end=65535, count=1, address='localhost', randomport=False):
    """
    Return a host free port or counts of host free ports in the range [port_start, port_end].

    Args:
        port_start: Header of candidate port range, defaults to 1024
        port_end: Ender of candidate port range, defaults to 65535
        count: The number of available ports to get
        address: Socket address to connect
        random: Find port random, in order if it's False

    Returns:
        Int if count=1, port_list if count > 1, None if no free port found
    """
    free_ports = []
    port_list = range(port_start, port_end)
    if randomport:
        randomport.shuffle(list(port_list))
    for _, port in enumerate(port_list):
        if is_port_free(port, address):
            free_ports.append(port)
        if len(free_ports) >= count:
            break
    if free_ports:
        if count == 1:
            return free_ports[0]
        return free_ports
    return None
