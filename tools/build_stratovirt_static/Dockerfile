# Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

from openeuler/openeuler:22.03-lts-sp2

ARG ARCH

RUN yum update -y && \
    yum upgrade -y && \
    yum install -y cargo musl-gcc cyrus-sasl-devel && \
    yum install -y libcap-devel libcap-ng-devel libseccomp-devel && \
    if [ "${ARCH}" == aarch64 ]; then yum install -y dtc-devel; fi && \
    yum clean all

