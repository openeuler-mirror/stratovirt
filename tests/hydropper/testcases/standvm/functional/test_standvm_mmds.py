# Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
#
# StratoVirt is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#         http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
"""MMDS end-to-end tests for StandVM (StdMachine) — aarch64 and x86_64."""

import json
import logging
import os
import re
import subprocess
import pytest

MMDS_IP = "169.254.169.254"
# FAT image containing GRUB EFI that loads the kernel from rootfs.
# Required because the available OVMF lacks QemuKernelLoader DXE.
EFI_BOOT_IMG = "/home/efi-boot.img"

METADATA = {
    "instanceID": "inst-stand-001",
    "envID": "env-stand-xyz",
    "address": "192.168.1.100",
}

_VT100_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]|\[\?[0-9;]*[lh]')


def _clean(s):
    return _VT100_RE.sub('', s)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _read_file(vm, path):
    _, raw = vm.serial_cmd("cat %s 2>/dev/null && echo" % path)
    cleaned = _clean(raw)
    lines = [line.strip() for line in cleaned.split('\n')
             if line.strip() and not line.strip().endswith('#') and not line.strip().endswith('$')]
    return '\n'.join(lines)


def _standvm_net_id(tap_index=0):
    """Return the virtio-net-pci device ID for a given tap slot.

    StandVM builds the device arg as:
        virtio-net-pci,netdev=<tap>,id=net-<i+24>,...
    where i is the enumerate index over taps.  With a single NIC the first
    tap gets i=0, so the device ID is "net-24".
    """
    return "net-%d" % (tap_index + 24)


def _launch_standvm(vm, **basic_config_kwargs):
    """Configure and launch a StandVM.

    Log files are written to /home/ for crash diagnosis:
      /home/standvm_stratovirt.log  - StratoVirt process log (FwCfg reads, boot steps)
      /home/standvm_serial.log      - ISA serial COM1 (OVMF/GRUB console output)
    """
    vm.basic_config(**basic_config_kwargs)

    # Each test kills the VM without a clean shutdown, leaving the ext4 rootfs
    # with a dirty journal.  Repair it now so journal recovery doesn't inflate
    # the boot time across successive tests.
    subprocess.run(['/usr/sbin/e2fsck', '-p', vm.rootfs],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # console=hvc0 crashes the host in nested KVM (virtio-serial MSI-X path).
    # Workaround: use ttyS0 as kernel console + let systemd start getty on hvc0.
    # serial_cmd() connects to the virtconsole chardev socket (hvc0), so the
    # shell must be on hvc0 — serial-getty@hvc0.service provides that.
    if "boot-source" in vm.configdict and "boot_args" in vm.configdict["boot-source"]:
        args = vm.configdict["boot-source"]["boot_args"]
        args = args.replace("console=hvc0", "console=ttyS0")
        if "serial-getty@hvc0" not in args:
            args += " systemd.wants=serial-getty@hvc0.service"
        vm.configdict["boot-source"]["boot_args"] = args

    # logpath is used by _common_args() to add '-D <path>' before launch().
    vm.logpath = '/home/standvm_stratovirt.log'

    # init_args persists through launch()'s _args reset; add_args() does not.
    vm.init_args.extend(['-serial', 'file,path=/home/standvm_serial.log'])

    vm.launch()


def _put_mmds_config(vm, iface_id, version="V1", ipv4_address=None):
    args = {"version": version, "network_interfaces": [iface_id]}
    if ipv4_address is not None:
        args["ipv4_address"] = ipv4_address
    resp = vm.qmp.qmp_command("put-mmds-config", **args)
    assert "error" not in resp, "put-mmds-config failed: %s" % resp
    return resp


def _put_mmds_data(vm):
    resp = vm.qmp.qmp_command(
        "put-mmds",
        instanceID=METADATA["instanceID"],
        envID=METADATA["envID"],
        address=METADATA["address"],
    )
    assert "error" not in resp, "put-mmds failed: %s" % resp


def _add_mmds_route(vm):
    iface = vm.interfaces[0]
    vm.serial_cmd("ip route add %s dev %s 2>/dev/null; true" % (MMDS_IP, iface))


def _curl_get(vm, token=None, max_time=5):
    header = ""
    if token is not None:
        header = "-H 'X-metadata-token: %s' " % token
    vm.serial_cmd(
        "curl -sf --max-time %d %shttp://%s/ -o /tmp/mmds_body.txt 2>/dev/null; "
        "echo $? > /tmp/mmds_exit.txt" % (max_time, header, MMDS_IP)
    )
    exit_raw = _read_file(vm, "/tmp/mmds_exit.txt")
    body = _read_file(vm, "/tmp/mmds_body.txt")
    try:
        status = int(exit_raw.strip())
    except (ValueError, IndexError):
        status = 1
    return status, body.strip()


def _curl_get_http_code(vm, token=None, max_time=5):
    header = ""
    if token is not None:
        header = "-H 'X-metadata-token: %s' " % token
    vm.serial_cmd(
        "curl -s -o /dev/null --max-time %d %shttp://%s/ "
        "-w '%%{http_code}' > /tmp/mmds_code.txt 2>/dev/null; true"
        % (max_time, header, MMDS_IP)
    )
    return _read_file(vm, "/tmp/mmds_code.txt").strip()


def _curl_put_token(vm, ttl=21600, max_time=5):
    vm.serial_cmd(
        "curl -sf --max-time %d -X PUT "
        "-H 'X-metadata-token-ttl-seconds: %d' "
        "http://%s/latest/api/token "
        "-o /tmp/mmds_token.txt 2>/dev/null; echo $? > /tmp/mmds_token_exit.txt"
        % (max_time, ttl, MMDS_IP)
    )
    exit_raw = _read_file(vm, "/tmp/mmds_token_exit.txt")
    token_body = _read_file(vm, "/tmp/mmds_token.txt")
    try:
        status = int(exit_raw.strip())
    except (ValueError, IndexError):
        status = 1
    assert status == 0, "Token PUT failed (exit %d): %s" % (status, token_body)
    return token_body.strip()


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.standvm_accept
def test_mmds_standvm_basic_metadata_v1(standvm):
    """
    Integration: StandVM (aarch64 / x86_64) with MMDS (V1) returns expected
    metadata.

    1. Launch standvm
    2. Configure MMDS V1 on the virtio-net-pci interface via QMP
    3. Write metadata via put-mmds QMP
    4. Add route to 169.254.169.254 inside the guest
    5. curl http://169.254.169.254/ and verify JSON fields
    """
    test_vm = standvm
    _launch_standvm(test_vm)

    net_id = _standvm_net_id(tap_index=0)
    _put_mmds_config(test_vm, net_id, version="V1")
    _put_mmds_data(test_vm)
    _add_mmds_route(test_vm)

    status, body = _curl_get(test_vm)
    assert status == 0, "curl to MMDS failed (exit %d): %s" % (status, body)

    data = json.loads(body)
    assert data["instanceID"] == METADATA["instanceID"]
    assert data["envID"] == METADATA["envID"]
    assert data["address"] == METADATA["address"]
    logging.info("MMDS V1 metadata validated on StandVM: %s", data)


@pytest.mark.standvm_accept
def test_mmds_standvm_imdsv2(standvm):
    """
    IMDSv2 flow on StandVM:

    1. Configure MMDS V2 on the virtio-net-pci interface
    2. GET without token  -> HTTP 401
    3. PUT /latest/api/token with TTL -> receive opaque token
    4. GET with valid token -> returns expected metadata (200)
    5. GET with wrong token -> HTTP 401
    """
    test_vm = standvm
    _launch_standvm(test_vm)

    net_id = _standvm_net_id(tap_index=0)
    _put_mmds_config(test_vm, net_id, version="V2")
    _put_mmds_data(test_vm)
    _add_mmds_route(test_vm)

    # Step 2: no token -> 401
    code = _curl_get_http_code(test_vm)
    assert code == "401", "Expected HTTP 401 without token, got: %s" % code

    # Step 3: obtain token
    token = _curl_put_token(test_vm, ttl=21600)
    assert token.startswith("mmds-token-"), "Unexpected token format: %s" % token
    logging.info("Obtained IMDSv2 token successfully")

    # Step 4: valid token -> 200 + correct JSON
    status, body = _curl_get(test_vm, token=token)
    assert status == 0, "GET with valid token failed (exit %d): %s" % (status, body)
    data = json.loads(body)
    assert data["instanceID"] == METADATA["instanceID"]

    # Step 5: wrong token -> 401
    code = _curl_get_http_code(test_vm, token="wrongtoken123")
    assert code == "401", "Expected HTTP 401 with wrong token, got: %s" % code


@pytest.mark.standvm_accept
@pytest.mark.skipif(
    not os.path.exists("/dev/vhost-net"),
    reason="/dev/vhost-net not present; vhost-kernel unsupported on this host",
)
def test_mmds_standvm_vhost_rejected(standvm):
    """
    put-mmds-config must reject vhost-kernel interfaces.

    A vhost device bypasses the virtio TX handler and therefore cannot
    intercept MMDS traffic.  The StdMachine handler refuses any interface ID
    that is not in the net_devs map; vhost devices are excluded from that map.

    1. Launch standvm with vhost-kernel NIC
    2. Call put-mmds-config with the vhost device ID
    3. Expect a GenericError response
    """
    test_vm = standvm
    _launch_standvm(test_vm, vhost_type="vhost-kernel")

    net_id = _standvm_net_id(tap_index=0)
    resp = test_vm.qmp.qmp_command("put-mmds-config",
                                   version="V1",
                                   network_interfaces=[net_id])
    assert "error" in resp, \
        "Expected error for vhost interface, got success: %s" % resp
    err_msg = resp["error"].get("desc", "")
    assert "vhost" in err_msg.lower() or "not found" in err_msg.lower(), \
        "Error message does not mention vhost or not-found: %s" % err_msg
    logging.info("vhost rejection verified: %s", err_msg)


@pytest.mark.standvm_accept
def test_mmds_standvm_hotswap(standvm):
    """
    Hot-swap: re-calling put-mmds-config on a running StandVM updates
    interception immediately without reboot.

    1. Configure MMDS (V1) on the interface; verify curl works
    2. Reconfigure with empty network_interfaces -> interception removed
    3. curl fails (timeout / connection refused)
    4. Re-enable MMDS on the same interface
    5. curl works again
    """
    test_vm = standvm
    _launch_standvm(test_vm)

    net_id = _standvm_net_id(tap_index=0)
    _put_mmds_config(test_vm, net_id, version="V1")
    _put_mmds_data(test_vm)
    _add_mmds_route(test_vm)

    # Baseline: MMDS reachable
    status, body = _curl_get(test_vm)
    assert status == 0, "Initial MMDS curl failed: %s" % body

    # Hot-swap #1: disable MMDS on all interfaces
    resp = test_vm.qmp.qmp_command("put-mmds-config",
                                   version="V1",
                                   network_interfaces=[])
    assert "error" not in resp, "Hot-swap disable failed: %s" % resp

    status, _ = _curl_get(test_vm, max_time=3)
    assert status != 0, "Expected curl to fail after MMDS disabled"

    # Hot-swap #2: re-enable MMDS
    _put_mmds_config(test_vm, net_id, version="V1")

    status, body = _curl_get(test_vm)
    assert status == 0, "curl failed after MMDS re-enabled: %s" % body
    data = json.loads(body)
    assert data["instanceID"] == METADATA["instanceID"]
    logging.info("Hot-swap re-enable validated on StandVM: %s", data)
