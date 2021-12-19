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