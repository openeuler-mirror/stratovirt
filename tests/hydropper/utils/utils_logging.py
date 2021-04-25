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
"""utils logging module"""

import threading
import logging
import logging.handlers
from utils.config import CONFIG

# Configuring Colors
RESET = '\033[1;0m'
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[1;34m'

# Defining Log Colors
COLORS_SETTING = {
    'DEBUG': BLUE + '%s' + RESET,
    'INFO': GREEN + '%s' + RESET,
    'WARNING': YELLOW + '%s' + RESET,
    'ERROR': RED + '%s' + RESET,
    'CRITICAL': RED + '%s' + RESET,
    'EXCEPTION': RED + '%s' + RESET,
}


class ColoredFormatter(logging.Formatter):
    """Color print"""

    def __init__(self, fmt=None, datefmt=None):
        logging.Formatter.__init__(self, fmt, datefmt)

    def format(self, record):
        log_level = record.levelname
        msg = logging.Formatter.format(self, record)

        return COLORS_SETTING.get(log_level, '%s') % msg


class Logger():
    """Test logging class"""

    def __init__(self, name=None, file_path=None, level=None,
                 fmt=None, mode=None, backup_count=None,
                 limit=None, when=None, console=True):

        self.logger = None
        self.name = name
        self.file_path = file_path
        self.level = level
        self.console = console

        if not fmt:
            self.fmt = "[%(asctime)s][%(levelname)s]%(filename)s" \
                       ":%(funcName)s L%(lineno)-.4d => %(message)s"
        else:
            self.fmt = fmt

        self.s_level = 'DEBUG'
        self.f_level = 'DEBUG'

        if level:
            level = level.split('|')
            if len(level) == 1:
                # Both set to the same level
                self.s_level = self.f_level = level[0]
            else:
                # StreamHandler log level
                self.s_level = level[0]
                # FileHandler log level
                self.f_level = level[1]

        self.msg = "Hello Word, just test"

        if not mode:
            self.mode = r'a'
        else:
            self.mode = mode
        if not backup_count:
            self.backup_count = 5
        else:
            self.backup_count = backup_count

        if not limit:
            self.limit = 10 * 1024 * 1024
        else:
            self.limit = limit

        self.when = when

        self.set_logger()

    def _add_handler(self, cls, level, colorful, **kwargs):
        """Add handler"""

        if isinstance(level, str):
            level = getattr(logging, level.upper(), logging.DEBUG)

        handler = cls(**kwargs)
        handler.setLevel(level)

        if colorful:
            formatter = ColoredFormatter(self.fmt)
        else:
            formatter = logging.Formatter(self.fmt)

        handler.setFormatter(formatter)

        # check whether the log handle of the avocado is inherited
        # if not, add a handle
        if not logging.getLogger("avocado.test").handlers:
            self.logger.addHandler(handler)

    def _add_streamhandler(self):
        """Add stream handler"""
        self._add_handler(logging.StreamHandler, self.s_level, True)

    def _add_filehandler(self):
        """Add file handler"""

        kwargs = {'filename': self.file_path}

        # choose the file handler based on the passed arguments
        if self.backup_count == 0:
            # use FileHandler
            cls = logging.FileHandler
            kwargs['mode'] = self.mode
        elif self.when is None:
            # use RotatingFileHandler
            cls = logging.handlers.RotatingFileHandler
            kwargs['maxBytes'] = self.limit
            kwargs['backupCount'] = self.backup_count
            kwargs['mode'] = self.mode
        else:
            # use TimedRotatingFileHandler
            cls = logging.handlers.TimedRotatingFileHandler
            kwargs['when'] = self.when
            kwargs['interval'] = self.limit
            kwargs['backupCount'] = self.backup_count

        self._add_handler(cls, self.f_level, True, **kwargs)

    def set_logger(self, name=None, file_path=None, level=None,
                   fmt=None, mode=None, backup_count=None,
                   limit=None, when=None, console=None):
        """Set logger params"""
        if level:
            level = level.split('|')
            if len(level) == 1:
                # both set to the same level
                self.s_level = self.f_level = level[0]
            else:
                # StreamHandler log level
                self.s_level = level[0]
                # FileHandler log level
                self.f_level = level[1]

        if fmt:
            self.fmt = fmt

        if name:
            self.name = name

        if console is not None:
            self.console = console

        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.DEBUG)

        if self.console:
            self._add_streamhandler()

        if file_path:
            self.file_path = file_path

        if self.file_path:
            if mode:
                self.mode = mode
            if backup_count:
                self.backup_count = backup_count
            if limit:
                self.limit = limit

            self.when = when
            self._add_filehandler()

        self.import_log_funcs()

    def import_log_funcs(self):
        """Import logging func"""
        log_funcs = ['debug', 'info', 'warn', 'error', 'critical', 'exception', 'warning']

        for func_name in log_funcs:
            func = getattr(self.logger, func_name)
            setattr(self, func_name, func)


class TestLog():
    """Test log"""
    def __init__(self):
        self.name = 'Testlog'

    _logmaps = dict()
    _logmap_lock = threading.Lock()

    @classmethod
    def get_log_handle(cls, logkey, root_path=CONFIG.test_session_root_path):
        """Get log handle with logkey"""
        try:
            cls._logmap_lock.acquire()
            loghandle = cls._logmaps.get(logkey)
            if loghandle is None:
                logpath = root_path + "/" + logkey + ".log"
                loghandle = Logger(logkey, file_path=logpath, console=False, backup_count=10)
                cls._logmaps[logkey] = loghandle
            return loghandle
        finally:
            cls._logmap_lock.release()

    @classmethod
    def get_log_handle_bypath(cls, logpath):
        """Get log handle by logpath"""
        try:
            cls._logmap_lock.acquire()
            loghandle = cls._logmaps.get(logpath)
            if loghandle is None:
                loghandle = Logger(logpath, file_path=logpath, console=False, backup_count=10)
                cls._logmaps[logpath] = loghandle
            return loghandle
        finally:
            cls._logmap_lock.release()

    @classmethod
    def get_global_log(cls):
        """Get global log"""
        return cls.get_log_handle("global")

    @classmethod
    def get_monitor_log(cls):
        """Get monitor log"""
        return cls.get_log_handle("monitor")
