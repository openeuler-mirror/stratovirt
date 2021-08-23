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
"""monitor thread"""

import threading
from queue import Empty
from utils.utils_logging import TestLog
from utils.config import CONFIG

LOG = TestLog.get_monitor_log()


class MonitorThread(threading.Thread):
    """Monitor thread"""

    items = dict()

    def __init__(self):
        """Constructor"""
        super(MonitorThread, self).__init__()
        self.state_lock = threading.Lock()
        self._state = 'init'

    def set_state(self, state):
        """Set state atomic"""
        with self.state_lock:
            self._state = state

    def stop(self):
        """Stop monitor"""
        self.set_state('stop')

    @classmethod
    def add_item(cls, monitoritem):
        """
        Add item to cls.items, and start this monitor

        Args:
            monitoritem: the monitor item class name

        Returns:
            True/False
        """
        cls.items[monitoritem.monitor_type] = monitoritem
        monitoritem.run()
        return True

    @classmethod
    def del_item(cls, monitoritem):
        """
        Del item from cls.items, and stop this monitor

        Args:
            monitoritem: the monitor item class name

        Returns:
            True/False
        """
        timeout = 300
        monitoritem.stop()
        monitoritem.join(timeout=timeout)
        if monitoritem.monitor_type in cls.items:
            del cls.items[monitoritem.monitor_type]
        if monitoritem.isAlive():
            LOG.debug("stop monitor thread [%s] failed within %d seconds" % \
                     (monitoritem.monitor_type, timeout))
            return False
        LOG.debug("stop monitor thread [%s] successfully" % monitoritem.monitor_type)
        return True

    def run(self):
        self.set_state('running')
        while self._state != 'stop':
            try:
                alarm_info = CONFIG.event_queue.get(block=False, timeout=1)
                self.event_handler(alarm_info)
            except Empty:
                pass

    @classmethod
    def event_handler(cls, alarm_info):
        """Event handler to process the alarm/monitor info"""
        monitor_type = alarm_info["type"]
        if monitor_type in cls.items:
            if hasattr(cls.items[monitor_type], "event_handler"):
                handler = getattr(cls.items[monitor_type], "event_handler")
                handler(alarm_info)
            elif "fatal" in alarm_info["level"] or "error" in alarm_info["level"]:
                LOG.error("get error alarm %s" % alarm_info)
