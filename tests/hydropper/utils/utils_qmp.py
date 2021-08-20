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
"""Some qmp functions"""

import re
from utils.exception import QMPError

def dictpath(dictionary, path):
    """Traverse a path in a nested dict"""
    index_re = re.compile(r'([^\[]+)\[([^\]]+)\]')
    for component in path.split('/'):
        match = index_re.match(component)
        if match:
            component, idx = match.groups()
            idx = int(idx)

        if not isinstance(dictionary, dict) or component not in dictionary:
            raise QMPError('failed path traversal for "%s" in "%s"' % (path, str(dictionary)))
        dictionary = dictionary[component]

        if match:
            if not isinstance(dictionary, list):
                raise QMPError('path component "%s" in "%s" is not a list in "%s"' %
                               (component, path, str(dictionary)))
            try:
                dictionary = dictionary[idx]
            except IndexError:
                raise QMPError('invalid index "%s" in path "%s" in "%s"' % (idx, path, str(dictionary)))
    return dictionary

def assert_qmp_absent(dictionary, path):
    """Assert that the path is invalid in 'dictionary'"""
    try:
        result = dictpath(dictionary, path)
    except AssertionError:
        return
    raise QMPError('path "%s" has value "%s"' % (path, str(result)))

def assert_qmp(dictionary, path, value):
    """
    Assert that the value for a specific path in a QMP dict
    matches.  When given a list of values, assert that any of
    them matches.
    """
    result = dictpath(dictionary, path)

    # [] makes no sense as a list of valid values, so treat it as
    # an actual single value.
    if isinstance(value, list) and value != []:
        for val in value:
            if result == val:
                return
        raise QMPError('no match for "%s" in %s' % (str(result), str(value)))

    assert result == value
