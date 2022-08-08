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
"""Some common functions"""
import os
import errno
import ctypes
import shutil
from subprocess import run
from subprocess import PIPE
from utils.utils_logging import TestLog

LOG = TestLog.get_global_log()

def stop_thread(thread):
    """Raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(thread.ident)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(SystemExit))
    if res == 0:
        raise ValueError("invalid thread id")
    if res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

def remove_existing_file(filepath):
    """Remove file path if it exists"""
    try:
        os.remove(filepath)
    except OSError as err:
        if err.errno == errno.ENOENT:
            return
        raise

def remove_existing_dir(dirpath):
    """Remove dir path if it exists"""
    try:
        shutil.rmtree(dirpath)
    except OSError as err:
        if err.errno == errno.ENOENT:
            return
        raise

def get_timestamp(timestamp):
    """Get timestamp"""
    timestr = timestamp[11:29]
    mill = timestr.split('.')[1]
    datetime = timestr.split('.')[0]
    hour = int(datetime.split(':')[0])
    minute = int(datetime.split(':')[1])
    second = int(datetime.split(':')[2])

    return float(str(second + minute * 60 + hour * 60 * 24) + '.' + mill)


def config_host_vfio(net_type, number, bdf):
    """configure vf in host"""
    ret = run("lspci -v | grep 'Eth' | grep %s" % net_type, shell=True, check=True).stdout
    LOG.debug(ret)
    ret = run("echo %s > /sys/bus/pci/devices/%s/sriov_numvfs" % (number, bdf), shell=True, check=True)

def rebind_vfio_pci(bdf):
    """unbind old driver and bind a new one"""
    run("echo %s > /sys/bus/pci/devices/%s/driver/unbind" % (bdf, bdf), shell=True, check=True)
    run("echo `lspci -ns %s | awk -F':| ' '{print $5\" \"$6}'` > /sys/bus/pci/drivers/vfio-pci/new_id"\
        %bdf, shell=True, check=True)

def check_vf(pf_name):
    """check whether vf is enabled"""
    run("ip link show %s | grep vf" % pf_name, shell=True, check=True)

def clean_vf(bdf):
    """clean host vf"""
    ret = run("echo 0 > /sys/bus/pci/devices/%s/sriov_numvfs" % bdf, shell=True, check=True)

def get_iommu_group(bdf):
    """get iommu group id"""
    read_cmd = "readlink /sys/bus/pci/devices/%s/iommu_group" % bdf
    return run(read_cmd, shell=True, check=True, stdout=PIPE) \
               .stdout.decode('utf-8').splitlines()[0].split('/')[-1]
