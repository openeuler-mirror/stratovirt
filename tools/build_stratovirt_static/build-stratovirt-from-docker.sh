#!/bin/bash
#
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

set -o errexit
set -o nounset
set -o pipefail

build_stratovirt() {
	sudo "${container_engine}" run \
		--rm -i \
		--env ARCH="${ARCH}" \
		-v "${repo_root_dir}:/root/stratovirt" \
		"${container_image}" \
		bash -c "cd /root/stratovirt && ${CARGO} build --workspace --bin stratovirt --release --target=${RUST_TARGET}"
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root_dir="$(cd ${script_dir}/../.. && pwd)"

ARCH=${ARCH:-$(uname -m)}
CARGO="/usr/bin/env CARGO_HOME=.cargo RUSTC_BOOTSTRAP=1 /usr/bin/cargo"
container_engine="${container_engine:-docker}"
container_image="${container_image:-$1}"

if [ "${ARCH}" == "x86_64" ]; then RUST_TARGET="x86_64-unknown-linux-musl"; fi
if [ "${ARCH}" == "aarch64" ]; then RUST_TARGET="aarch64-unknown-linux-musl"; fi

echo "Building StratoVirt with ${RUST_TARGET}"

sudo "${container_engine}" build \
	--build-arg ARCH="${ARCH}" \
	"${repo_root_dir}" \
	-f "${script_dir}/Dockerfile" \
	-t "${container_image}" && \

build_stratovirt

