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
"""monitor vm memory usage"""

import logging
from subprocess import run
from subprocess import CalledProcessError
from subprocess import PIPE
from monitor import monitor_info
from monitor import MEMORY_USAGE_EXCEEDED


class MemoryUsageExceededInfo(monitor_info.MonitorInfo):
    """Check vm memory usage"""

    def __init__(self, pid, max_memory=4096):
        """Max memory default value is 4096Kib"""
        _monitor_type = MEMORY_USAGE_EXCEEDED
        _monitor_cycle = 10
        super(MemoryUsageExceededInfo, self).__init__(_monitor_type,
                                                      _monitor_cycle,
                                                      "vm")
        self._pid = pid
        self.max_memory = max_memory
        # guest memory top limit is 131072(128M)
        self.guest_memory_limit = 131072

    def update_pid(self, pid):
        """Update vm pid"""
        self._pid = pid

    def check(self):
        """
        Check memory usage exceeded or not(overwrite to the monitorinfo)

        Returns:
            (bool, level, err_msg)
        """
        exceeded = False
        level = "info"
        err_msg = ""
        pmap_cmd = "pmap -xq {}".format(self._pid)
        mem_total = 0
        try:
            pmap_out = run(pmap_cmd, shell=True, check=True,
                           stdout=PIPE).stdout.decode('utf-8').split("\n")
        except CalledProcessError:
            return exceeded
        for line in pmap_out:
            tokens = line.split()
            if not tokens:
                break
            try:
                total_size = int(tokens[1])
                rss = int(tokens[2])
            except ValueError:
                continue
            if total_size > self.guest_memory_limit:
                # this is the guest memory region
                continue
            mem_total += rss

        logging.debug("mem_total:%s", mem_total)

        if mem_total >= self.max_memory:
            exceeded = True
            level = "error"
            err_msg = "memory usage is %s, it's greater than %s" % (mem_total, self.max_memory)

        return exceeded, level, err_msg
