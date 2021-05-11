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
"""common monitor info"""

import threading
import time
from queue import Full
import monitor
from utils.utils_logging import TestLog
from utils.config import CONFIG

LOG = TestLog.get_monitor_log()


class MonitorInfo(threading.Thread):
    """Monitor info(basic class)"""

    def __init__(self, monitor_type, monitor_cycle, monitor_level, e_queue=CONFIG.event_queue):
        self.monitor_type = monitor_type
        self.monitor_cycle = monitor_cycle
        self.monitor_level = monitor_level
        self._state = 'init'
        self.state_lock = threading.Lock()
        self._enable = False
        self.e_queue = e_queue
        super(MonitorInfo, self).__init__()

    def enable(self):
        """Enable monitor item"""
        self._enable = True

    def disable(self):
        """Disable monitor item"""
        self._enable = False

    def set_state(self, state):
        """Set state atomic"""
        with self.state_lock:
            self._state = state

    def run(self):
        """Run monitor"""
        self.set_state('running')
        while self._state != 'stop':
            time.sleep(self.monitor_cycle)

    def check(self):
        """
        Check it's normal or not

        Returns:
            (bool, level, err_msg)
        """
        return False, monitor.MONITOR_LEVEL_INFO, "not implement"

    def enqueue(self, level, err):
        """Put event into queue"""
        _item = {"type": self.monitor_type,
                 "level": level,
                 "errmsg": err}
        try:
            self.e_queue.put(_item, False)
        except Full:
            LOG.debug("insert alarm(%s) to queue failed!" % _item)
