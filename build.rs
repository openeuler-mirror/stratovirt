// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

fn ohos_env_configure() {
    if let Ok(ohos_sdk_path) = std::env::var("OHOS_SDK") {
        println!("cargo:rustc-link-arg=--target=aarch64-linux-ohos");
        println!("cargo:rustc-link-arg=--verbose");
        println!("cargo:rustc-link-arg=--sysroot={}/sysroot", ohos_sdk_path);
        println!("cargo:rustc-link-arg=-lpixman_static");
        println!(
            "cargo:rustc-link-search={}/sysroot/usr/lib/aarch64-linux-ohos",
            ohos_sdk_path
        );
    }
}

fn main() {
    let target_env_ohos = matches!(std::env::var("CARGO_CFG_TARGET_ENV"), Ok(ret) if ret == "ohos");

    if target_env_ohos {
        println!("cargo:rerun-if-env-changed=OHOS_SDK");
        ohos_env_configure();
    } else if cfg!(any(
        feature = "demo_device",
        feature = "gtk",
        feature = "ramfb",
        feature = "virtio_gpu",
        feature = "vnc",
    )) {
        println!("cargo:rustc-link-arg=-lpixman-1");
    }
}
