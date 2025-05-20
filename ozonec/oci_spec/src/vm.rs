// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use serde::{Deserialize, Serialize};

/// Hypervisor that manages the container virtual machine.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hypervisor {
    /// Path to the hypervisor binary that manages the container
    /// virtual machine.
    pub path: String,
    /// Array of parameters to pass to the hypervisor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<String>>,
}

/// Kernel to boot the container virtual machine with.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Kernel {
    /// Path to the kernel used to boot the container virtual machine.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Array of parameters to pass to the kernel.
    pub parameters: Option<Vec<String>>,
    /// Path to an initial ramdisk to be used by the container
    /// virtual machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd: Option<String>,
}

/// Image that contains the root filesystem for the container
/// virtual machine.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Image {
    /// Path to the container virtual machine root image.
    pub path: String,
    /// Format of the container virtual machine root image.
    pub format: String,
}

/// Configuration for the hypervisor, kernel, and image.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VmPlatform {
    /// Hypervisor that manages the container virtual machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypervisor: Option<Hypervisor>,
    /// Kernel to boot the container virtual machine with.
    pub kernel: Kernel,
    /// Image that contains the root filesystem for the container
    /// virtual machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Image>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_hypervisor() {
        let json = r#"{
            "hypervisor": {
                "path": "/path/to/vmm",
                "parameters": ["opts1=foo", "opts2=bar"]
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            hypervisor: Hypervisor,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.hypervisor.path, "/path/to/vmm");
        let parameters = section.hypervisor.parameters.as_ref().unwrap();
        assert_eq!(parameters.len(), 2);
        assert_eq!(parameters[0], "opts1=foo");
        assert_eq!(parameters[1], "opts2=bar");
    }

    #[test]
    fn test_kernel() {
        let json = r#"{
            "kernel": {
                "path": "/path/to/vmlinuz",
                "parameters": ["foo=bar", "hello world"],
                "initrd": "/path/to/initrd.img"
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            kernel: Kernel,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.kernel.path, "/path/to/vmlinuz");
        let parameters = section.kernel.parameters.as_ref().unwrap();
        assert_eq!(parameters.len(), 2);
        assert_eq!(parameters[0], "foo=bar");
        assert_eq!(parameters[1], "hello world");
        assert_eq!(
            section.kernel.initrd,
            Some("/path/to/initrd.img".to_string())
        );
    }

    #[test]
    fn test_image() {
        let json = r#"{
            "image": {
                "path": "/path/to/vm/rootfs.img",
                "format": "raw"
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            image: Image,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.image.path, "/path/to/vm/rootfs.img");
        assert_eq!(section.image.format, "raw");
    }
}
