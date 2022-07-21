// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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
pub use serde_json::Value as Any;
use strum_macros::{EnumIter, EnumString, EnumVariantNames};

use super::Version;
use crate::qmp::{Command, Empty, TimeStamp};

/// A error enum for qmp
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QmpErrorClass {
    #[serde(rename = "GenericError")]
    GenericError(String),
    #[serde(rename = "CommandNotFound")]
    CommandNotFound(String),
    #[serde(rename = "DeviceNotActive")]
    DeviceNotActive(String),
    #[serde(rename = "DeviceNotFound")]
    DeviceNotFound(String),
    #[serde(rename = "KVMMissingCap")]
    KVMMissingCap(String),
    #[serde(rename = "OperationThrottled")]
    OperationThrottled(u64),
}

impl QmpErrorClass {
    pub fn to_content(&self) -> String {
        match self {
            QmpErrorClass::GenericError(s) => s.to_string(),
            QmpErrorClass::CommandNotFound(s) => s.to_string(),
            QmpErrorClass::DeviceNotActive(s) => s.to_string(),
            QmpErrorClass::DeviceNotFound(s) => s.to_string(),
            QmpErrorClass::KVMMissingCap(s) => s.to_string(),
            QmpErrorClass::OperationThrottled(nr) => {
                format!("More than {} requests received during 1 second", nr)
            }
        }
    }
}

/// A enum to store all command struct
#[derive(Debug, Clone, Serialize, Deserialize, EnumIter, EnumVariantNames, EnumString)]
#[serde(tag = "execute")]
#[serde(deny_unknown_fields)]
pub enum QmpCommand {
    #[serde(rename = "qmp_capabilities")]
    qmp_capabilities {
        #[serde(default)]
        arguments: qmp_capabilities,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    quit {
        #[serde(default)]
        arguments: quit,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    stop {
        #[serde(default)]
        arguments: stop,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    cont {
        #[serde(default)]
        arguments: cont,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    device_add {
        arguments: Box<device_add>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    device_del {
        arguments: device_del,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    netdev_add {
        arguments: Box<netdev_add>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    netdev_del {
        arguments: netdev_del,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-hotpluggable-cpus")]
    #[strum(serialize = "query-hotpluggable-cpus")]
    query_hotpluggable_cpus {
        #[serde(default)]
        arguments: query_hotpluggable_cpus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-cpus")]
    #[strum(serialize = "query-cpus")]
    query_cpus {
        #[serde(default)]
        arguments: query_cpus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-status")]
    query_status {
        #[serde(default)]
        arguments: query_status,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    getfd {
        arguments: getfd,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "blockdev-add")]
    blockdev_add {
        arguments: Box<blockdev_add>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "blockdev-del")]
    blockdev_del {
        arguments: blockdev_del,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "balloon")]
    balloon {
        #[serde(default)]
        arguments: balloon,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-balloon")]
    query_balloon {
        #[serde(default)]
        arguments: query_balloon,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "migrate")]
    migrate {
        arguments: migrate,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-migrate")]
    query_migrate {
        #[serde(default)]
        arguments: query_migrate,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "migrate_cancel")]
    cancel_migrate {
        #[serde(default)]
        arguments: cancel_migrate,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-version")]
    query_version {
        #[serde(default)]
        arguments: query_version,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-commands")]
    query_commands {
        #[serde(default)]
        arguments: query_commands,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-target")]
    query_target {
        #[serde(default)]
        arguments: query_target,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-kvm")]
    query_kvm {
        #[serde(default)]
        arguments: query_kvm,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-machines")]
    query_machines {
        #[serde(default)]
        arguments: query_machines,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-events")]
    #[strum(serialize = "query-events")]
    query_events {
        #[serde(default)]
        arguments: query_events,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "qom-list-types")]
    list_type {
        #[serde(default)]
        arguments: list_type,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "device-list-properties")]
    device_list_properties {
        #[serde(default)]
        arguments: device_list_properties,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "block-commit")]
    #[strum(serialize = "block-commit")]
    block_commit {
        #[serde(default)]
        arguments: block_commit,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-tpm-models")]
    query_tpm_models {
        #[serde(default)]
        arguments: query_tpm_models,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-tpm-types")]
    query_tpm_types {
        #[serde(default)]
        arguments: query_tpm_types,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-command-line-options")]
    query_command_line_options {
        #[serde(default)]
        arguments: query_command_line_options,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-migrate-capabilities")]
    query_migrate_capabilities {
        #[serde(default)]
        arguments: query_migrate_capabilities,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-qmp-schema")]
    query_qmp_schema {
        #[serde(default)]
        arguments: query_qmp_schema,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-sev-capabilities")]
    query_sev_capabilities {
        #[serde(default)]
        arguments: query_sev_capabilities,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-chardev")]
    #[strum(serialize = "query-chardev")]
    query_chardev {
        #[serde(default)]
        arguments: query_chardev,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "qom-list")]
    #[strum(serialize = "qom-list")]
    qom_list {
        #[serde(default)]
        arguments: qom_list,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "qom_get")]
    #[strum(serialize = "qom_get")]
    qom_get {
        #[serde(default)]
        arguments: qom_get,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-block")]
    #[strum(serialize = "query-block")]
    query_block {
        #[serde(default)]
        arguments: query_block,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-named-block-nodes")]
    #[strum(serialize = "query-named-block-nodes")]
    query_named_block_nodes {
        #[serde(default)]
        arguments: query_named_block_nodes,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-blockstats")]
    #[strum(serialize = "query-blockstats")]
    query_blockstats {
        #[serde(default)]
        arguments: query_blockstats,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-gic-capabilities")]
    #[strum(serialize = "query-gic-capabilities")]
    query_gic_capabilities {
        #[serde(default)]
        arguments: query_gic_capabilities,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    #[serde(rename = "query-iothreads")]
    #[strum(serialize = "query-iothreads")]
    query_iothreads {
        #[serde(default)]
        arguments: query_iothreads,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
}

/// qmp_capabilities
///
/// Enable QMP capabilities.
///
/// # Examples
///
/// ```text
/// -> { "execute": "qmp_capabilities" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct qmp_capabilities {}

impl Command for qmp_capabilities {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// quit
///
/// This command will cause the StratoVirt process to exit gracefully. While every
/// attempt is made to send the QMP response before terminating, this is not
/// guaranteed.  When using this interface, a premature EOF would not be
/// unexpected.
///
/// # Examples
///
/// ```text
/// -> { "execute": "quit" }
/// <- { "return": {}}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct quit {}

impl Command for quit {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// stop
///
/// Stop all guest VCPU execution
///
/// # Examples
///
/// ```text
/// -> { "execute": "stop" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct stop {}

impl Command for stop {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// cont
///
/// Resume guest VCPU execution.
///
/// # Examples
///
/// ```text
/// -> { "execute": "cont" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct cont {}

impl Command for cont {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// device_add
///
/// # Arguments
///
/// * `id` - the device's ID, must be unique.
/// * `driver` - the name of the new device's driver.
/// * `addr` - the address device insert into.
///
/// Additional arguments depend on the type.
///
/// # Examples
///
/// ```text
/// -> { "execute": "device_add",
///      "arguments": { "id": "net-0", "driver": "virtio-net-mmio", "addr": "0x0"}}
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct device_add {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "driver")]
    pub driver: String,
    #[serde(rename = "addr")]
    pub addr: Option<String>,
    #[serde(rename = "lun")]
    pub lun: Option<usize>,
    #[serde(rename = "drive")]
    pub drive: Option<String>,
    #[serde(rename = "romfile")]
    pub romfile: Option<String>,
    #[serde(rename = "share-rw")]
    pub share: Option<String>,
    #[serde(rename = "bus")]
    pub bus: Option<String>,
    #[serde(rename = "mac")]
    pub mac: Option<String>,
    #[serde(rename = "netdev")]
    pub netdev: Option<String>,
    #[serde(rename = "disable-modern")]
    pub disable_modern: Option<String>,
    #[serde(rename = "mq")]
    pub mq: Option<String>,
    #[serde(rename = "vectors")]
    pub vectors: Option<String>,
    #[serde(rename = "serial")]
    pub serial_num: Option<String>,
    pub iothread: Option<String>,
    pub multifunction: Option<bool>,
    pub host: Option<String>,
    #[serde(rename = "num-queues")]
    pub queues: Option<u16>,
    pub boot_index: Option<u8>,
}

pub type DeviceAddArgument = device_add;

impl Command for device_add {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOptions {
    pub driver: String,
    pub filename: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheOptions {
    #[serde(rename = "no-flush")]
    pub no_flush: Option<bool>,
    pub direct: Option<bool>,
}

/// blockdev_add
///
/// # Arguments
///
/// * `node_name` - the device's ID, must be unique.
/// * `file` - the backend file information.
/// * `cache` - if use direct io.
/// * `read_only` - if readonly.
///
/// Additional arguments depend on the type.
///
/// # Examples
///
/// ```text
/// -> { "execute": "blockdev_add",
///      "arguments":  {"node-name": "drive-0",
///                     "file": {"driver": "file", "filename": "/path/to/block"},
///                     "cache": {"direct": true}, "read-only": false }}
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct blockdev_add {
    #[serde(rename = "node-name")]
    pub node_name: String,
    pub file: FileOptions,
    pub cache: Option<CacheOptions>,
    #[serde(rename = "read-only")]
    pub read_only: Option<bool>,
    #[serde(rename = "read-zeros")]
    pub read_zeros: Option<bool>,
    pub driver: Option<String>,
    pub backing: Option<String>,
    pub discard: Option<String>,
    pub id: Option<String>,
    pub options: Option<String>,
    #[serde(rename = "throttling.iops-total")]
    pub iops: Option<u64>,
}

pub type BlockDevAddArgument = blockdev_add;

impl Command for blockdev_add {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// netdev_add
///
/// # Arguments
///
/// * `id` - the device's ID, must be unique.
/// * `ifname` - the backend tap dev name.
/// * `fds` - the file fd opened by upper level.
///
/// Additional arguments depend on the type.
///
/// # Examples
///
/// ```text
/// -> { "execute": "netdev_add",
///      "arguments":  {"id": "net-0", "ifname": "tap0", "fds": 123 }}
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct netdev_add {
    pub id: String,
    #[serde(rename = "ifname")]
    pub if_name: Option<String>,
    pub fds: Option<String>,
    pub dnssearch: Option<String>,
    #[serde(rename = "type")]
    pub net_type: Option<String>,
    pub vhost: Option<String>,
    pub vhostfds: Option<String>,
    pub ifname: Option<String>,
    pub downscript: Option<String>,
    pub script: Option<String>,
    pub queues: Option<u16>,
}

pub type NetDevAddArgument = netdev_add;

impl Command for netdev_add {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// device_del
///
/// Remove a device from a guest
///
/// # Arguments
///
/// * `id` - the device's ID or QOM path.
///
/// # Errors
///
/// If `id` is not a valid device, DeviceNotFound.
///
/// # Notes
///
/// When this command completes, the device may not be removed from the
/// guest. Hot removal is an operation that requires guest cooperation.
/// This command merely requests that the guest begin the hot removal
/// process. Completion of the device removal process is signaled with a
/// DEVICE_DELETED event. Guest reset will automatically complete removal
/// for all devices.
///
/// # Examples
///
/// ```text
/// -> { "execute": "device_del",
///      "arguments": { "id": "net-0" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct device_del {
    pub id: String,
}

impl Command for device_del {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct blockdev_del {
    #[serde(rename = "node-name")]
    pub node_name: String,
}

impl Command for blockdev_del {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// netdev_del
///
/// Remove a network backend.
///
/// # Arguments
///
/// * `id` - The name of the network backend to remove.
///
/// # Errors
///
/// If `id` is not a valid network backend, DeviceNotFound
///
/// # Examples
///
/// ```text
/// -> { "execute": "netdev_del", "arguments": { "id": "net-0" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct netdev_del {
    pub id: String,
}

impl Command for netdev_del {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// query-hotpluggable-cpus:
///
/// # Returns
///
/// A list of Hotpluggable CPU objects.
///
/// # Examples
///
/// For pc machine type started with -smp 1,maxcpus=2:
/// ```text
/// -> { "execute": "query-hotpluggable-cpus" }
/// <- {"return": [
///      {
///         "type": host-x-cpu", "vcpus-count": 1,
///         "props": {"core-id": 0, "socket-id": 1, "thread-id": 0}
///      },
///      {
///         "qom-path": "/machine/unattached/device[0]",
///         "type": "host-x-cpu", "vcpus-count": 1,
///         "props": {"core-id": 0, "socket-id": 0, "thread-id": 0}
///      }
///    ]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_hotpluggable_cpus {}

impl Command for query_hotpluggable_cpus {
    type Res = Vec<HotpluggableCPU>;

    fn back(self) -> Vec<HotpluggableCPU> {
        Default::default()
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct HotpluggableCPU {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "vcpus-count")]
    pub vcpus_count: isize,
    #[serde(rename = "props")]
    pub props: CpuInstanceProperties,
    #[serde(rename = "qom-path", default, skip_serializing_if = "Option::is_none")]
    pub qom_path: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CpuInstanceProperties {
    #[serde(rename = "node-id", default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<isize>,
    #[serde(rename = "socket-id", default, skip_serializing_if = "Option::is_none")]
    pub socket_id: Option<isize>,
    #[serde(rename = "thread-id", default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<isize>,
    #[serde(rename = "core-id", default, skip_serializing_if = "Option::is_none")]
    pub core_id: Option<isize>,
}

/// query-cpus:
///
/// This command causes vCPU threads to exit to userspace, which causes
/// a small interruption to guest CPU execution. This will have a negative
/// impact on realtime guests and other latency sensitive guest workloads.
/// It is recommended to use @query-cpus-fast instead of this command to
/// avoid the vCPU interruption.
///
/// # Returns
///
/// A list of information about each virtual CPU.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-cpus" }
/// <- { "return": [
///          {
///             "CPU":0,
///             "current":true,
///             "halted":false,
///             "qom_path":"/machine/unattached/device[0]",
///             "arch":"x86",
///             "thread_id":3134
///          },
///          {
///             "CPU":1,
///             "current":false,
///             "halted":true,
///             "qom_path":"/machine/unattached/device[2]",
///             "arch":"x86",
///             "thread_id":3135
///          }
///       ]
///    }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_cpus {}

impl Command for query_cpus {
    type Res = Vec<CpuInfo>;

    fn back(self) -> Vec<CpuInfo> {
        Default::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfoCommon {
    #[serde(rename = "current")]
    pub current: bool,
    #[serde(rename = "qom_path")]
    pub qom_path: String,
    #[serde(rename = "halted")]
    pub halted: bool,
    #[serde(rename = "props", default, skip_serializing_if = "Option::is_none")]
    pub props: Option<CpuInstanceProperties>,
    #[serde(rename = "CPU")]
    pub CPU: isize,
    #[serde(rename = "thread_id")]
    pub thread_id: isize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "arch")]
pub enum CpuInfo {
    #[serde(rename = "x86")]
    x86 {
        #[serde(flatten)]
        common: CpuInfoCommon,
        #[serde(flatten)]
        #[serde(rename = "x86")]
        x86: CpuInfoX86,
    },
    #[serde(rename = "arm")]
    Arm {
        #[serde(flatten)]
        common: CpuInfoCommon,
        #[serde(flatten)]
        #[serde(rename = "Arm")]
        arm: CpuInfoArm,
    },
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfoX86 {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfoArm {}

/// query-status
///
/// Query the run status of all VCPUs.
///
/// # Returns
///
/// `StatusInfo` reflecting all VCPUs.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-status" }
/// <- { "return": { "running": true,
///                  "singlestep": false,
///                  "status": "running" } }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_status {}

impl Command for query_status {
    type Res = StatusInfo;

    fn back(self) -> StatusInfo {
        Default::default()
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    #[serde(rename = "singlestep")]
    pub singlestep: bool,
    #[serde(rename = "running")]
    pub running: bool,
    #[serde(rename = "status")]
    pub status: RunState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RunState {
    #[serde(rename = "debug")]
    debug,
    #[serde(rename = "inmigrate")]
    inmigrate,
    #[serde(rename = "internal-error")]
    internal_error,
    #[serde(rename = "io-error")]
    io_error,
    #[serde(rename = "paused")]
    paused,
    #[serde(rename = "postmigrate")]
    postmigrate,
    #[serde(rename = "prelaunch")]
    prelaunch,
    #[serde(rename = "finish-migrate")]
    finish_migrate,
    #[serde(rename = "restore-vm")]
    restore_vm,
    #[serde(rename = "running")]
    running,
    #[serde(rename = "save-vm")]
    save_vm,
    #[serde(rename = "shutdown")]
    shutdown,
    #[serde(rename = "suspended")]
    suspended,
    #[serde(rename = "watchdog")]
    watchdog,
    #[serde(rename = "guest-panicked")]
    guest_panicked,
    #[serde(rename = "colo")]
    colo,
    #[serde(rename = "preconfig")]
    preconfig,
}

impl Default for RunState {
    fn default() -> Self {
        RunState::debug
    }
}

/// migrate
///
/// Migrates the current running guest to another VM or file.
///
/// # Arguments
///
/// * `uri` - the Uniform Resource Identifier of the destination VM or file.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct migrate {
    #[serde(rename = "uri")]
    pub uri: String,
}

impl Command for migrate {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// query-migrate:
///
/// Returns information about current migration.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_migrate {}

impl Command for query_migrate {
    type Res = MigrationInfo;

    fn back(self) -> MigrationInfo {
        Default::default()
    }
}

/// cancel-migrate:
///
/// Cancel migrate the current VM.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct cancel_migrate {}

impl Command for cancel_migrate {
    type Res = MigrationInfo;

    fn back(self) -> MigrationInfo {
        Default::default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationInfo {
    #[serde(rename = "status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// getfd
///
/// Receive a file descriptor via SCM rights and assign it a name
///
/// # Arguments
///
/// * `fdname` - File descriptor name.
///
/// # Examples
///
/// ```text
/// -> { "execute": "getfd", "arguments": { "fdname": "fd1" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct getfd {
    #[serde(rename = "fdname")]
    pub fd_name: String,
}

impl Command for getfd {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// Shutdown
///
/// Emitted when the virtual machine has shut down, indicating that StratoVirt is
/// about to exit.
///
/// # Notes
///
/// If the command-line option "-no-shutdown" has been specified, StratoVirt
/// will not exit, and a STOP event will eventually follow the SHUTDOWN event
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Shutdown {
    /// If true, the shutdown was triggered by a guest request (such as
    /// a guest-initiated ACPI shutdown request or other hardware-specific
    /// action) rather than a host request (such as sending StratoVirt a SIGINT).
    #[serde(rename = "guest")]
    pub guest: bool,
    pub reason: String,
}

/// Reset
///
/// Emitted when the virtual machine is reset
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Reset {
    /// If true, the reset was triggered by a guest request (such as
    /// a guest-initiated ACPI reboot request or other hardware-specific action
    /// ) rather than a host request (such as the QMP command system_reset).
    #[serde(rename = "guest")]
    pub guest: bool,
}

/// Stop
///
/// Emitted when the virtual machine is stopped
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Stop {}

/// Resume
///
/// Emitted when the virtual machine resumes execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Resume {}

/// DeviceDeleted
///
/// Emitted whenever the device removal completion is acknowledged by the guest.
/// At this point, it's safe to reuse the specified device ID. Device removal can
/// be initiated by the guest or by HMP/QMP commands.
///
/// # Examples
///
/// ```text
/// <- { "event": "DEVICE_DELETED",
///      "data": { "device": "virtio-net-mmio-0",
///                "path": "/machine/peripheral/virtio-net-mmio-0" },
///      "timestamp": { "seconds": 1265044230, "microseconds": 450486 } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeviceDeleted {
    /// Device name.
    #[serde(rename = "device", default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Device path.
    #[serde(rename = "path")]
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, EnumIter, EnumVariantNames, EnumString)]
#[serde(tag = "event")]
pub enum QmpEvent {
    #[serde(rename = "SHUTDOWN")]
    Shutdown {
        data: Shutdown,
        timestamp: TimeStamp,
    },
    #[serde(rename = "RESET")]
    Reset { data: Reset, timestamp: TimeStamp },
    #[serde(rename = "STOP")]
    Stop {
        #[serde(default)]
        data: Stop,
        timestamp: TimeStamp,
    },
    #[serde(rename = "RESUME")]
    Resume {
        #[serde(default)]
        data: Resume,
        timestamp: TimeStamp,
    },
    #[serde(rename = "DEVICE_DELETED")]
    DeviceDeleted {
        data: DeviceDeleted,
        timestamp: TimeStamp,
    },
    #[serde(rename = "BALLOON_CHANGED")]
    BalloonChanged {
        data: BalloonInfo,
        timestamp: TimeStamp,
    },
}

/// query-balloon:
///
/// Query the actual size of memory of VM.
///
/// # Returns
///
/// `BalloonInfo` includs the actual size of memory
///
/// # Example
///
/// ```text
/// -> { "execute": "query-balloon" }
/// <- {"return":{"actual":8589934592}}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_balloon {}
impl Command for query_balloon {
    type Res = BalloonInfo;
    fn back(self) -> BalloonInfo {
        Default::default()
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BalloonInfo {
    pub actual: u64,
}

/// balloon:
///
/// Advice VM to change memory size with the argument `value`.
///
/// # Arguments
///
/// * `value` - Memoey size.
///
/// # Notes
///
/// This is only an advice instead of command to VM,
/// therefore, the VM changes its memory according to `value` and its condation.
///
/// # Example
///
/// ```text
/// -> { "execute": "balloon", "arguments": { "value": 589934492 } }
/// <- {"return":{}}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct balloon {
    #[serde(rename = "value")]
    pub value: u64,
}

impl Command for balloon {
    type Res = Empty;
    fn back(self) -> Empty {
        Default::default()
    }
}

/// version:
///
/// Query version of StratoVirt.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-version" }
/// <- {"return":{"package":"StratoVirt-0.3.0","qemu":{"major":4,"micro":0,"minor":1}}}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_version {}

impl Command for query_version {
    type Res = Version;

    fn back(self) -> Version {
        Default::default()
    }
}

/// Query commands:
///
/// Query all qmp commands of StratoVirt.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-commands" }
/// <- {"return":[{"name":"qmp_capabilities"},{"name":"quit"},{"name":"stop"},
/// {"name":"cont"},{"name":"device_add"},{"name":"device_del"},{"name":"netdev_add"},
/// {"name":"netdev_del"},{"name":"query-hotpluggable-cpus"},{"name":"query-cpus"},
/// {"name":"query_status"},{"name":"getfd"},{"name":"blockdev_add"},
/// {"name":"blockdev_del"},{"name":"balloon"},{"name":"query_balloon"},
/// {"name":"migrate"},{"name":"query_migrate"},{"name":"query_version"},
/// {"name":"query_target"},{"name":"query_commands"}]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_commands {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Cmd {
    pub name: String,
}

impl Command for query_commands {
    type Res = Vec<Cmd>;

    fn back(self) -> Vec<Cmd> {
        Default::default()
    }
}

/// Query target:
///
/// Query the target platform where the StratoVirt is running.
///
/// # Example
///
/// ```text
/// # for X86 platform.
/// -> { "execute": "query-target" }
/// <- {"return":{"arch":"x86_64"}}
///
/// # for Aarch64 platform.
/// -> { "execute": "query-target" }
/// <- {"return":{"arch":"aarch64"}}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_target {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub arch: String,
}

impl Command for query_target {
    type Res = Target;

    fn back(self) -> Target {
        Default::default()
    }
}

/// Query machines:
///
/// Query machine information.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-machines" }
/// <- {"return":[{"cpu-max":255,"deprecated":false,"hotpluggable-cpus":true,"name":"none","numa-mem-supported":false},
/// {"cpu-max":255,"deprecated":false,"hotpluggable-cpus":true,"name":"microvm","numa-mem-supported":false},
/// {"cpu-max":255,"deprecated":false,"hotpluggable-cpus":true,"name":"standardvm","numa-mem-supported":false}]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_machines {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MachineInfo {
    #[serde(rename = "hotpluggable-cpus")]
    pub hotplug: bool,
    pub name: String,
    #[serde(rename = "numa-mem-supported")]
    pub numa_mem_support: bool,
    #[serde(rename = "cpu-max")]
    pub cpu_max: u8,
    pub deprecated: bool,
}

impl Command for query_machines {
    type Res = Vec<MachineInfo>;

    fn back(self) -> Vec<MachineInfo> {
        Default::default()
    }
}

/// Query events:
///
/// Query all events of StratoVirt.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-events" }
/// <- {"return":[{"name":"Shutdown"},{"name":"Reset"},
/// {"name":"Stop"},{"name":"Resume"},{"name":"DeviceDeleted"},
/// {"name":"BalloonChanged"}]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Events {
    pub name: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_events {}

impl Command for query_events {
    type Res = Vec<Events>;

    fn back(self) -> Vec<Events> {
        Default::default()
    }
}

/// Query KVM:
///
/// Query if KVM is enabled.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-kvm" }
/// <- {"return":{"enabled":true,"present":true}}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_kvm {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KvmInfo {
    pub enabled: bool,
    pub present: bool,
}

impl Command for query_kvm {
    type Res = KvmInfo;

    fn back(self) -> KvmInfo {
        Default::default()
    }
}

/// List all Qom type.
///
/// # Example
///
/// ```text
/// -> { "execute": "qom-list-types" }
/// <- {"return":[{"name":"ioh3420","parent":"pcie-root-port-base"},
/// {"name":"pcie-root-port","parent":"pcie-root-port-base"},
/// {"name":"pcie-pci-bridge","parent":"base-pci-bridge"},
/// {"name":"pci-bridge","parent":"base-pci-bridge"}]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct list_type {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TypeLists {
    name: String,
    parent: String,
}

impl TypeLists {
    pub fn new(name: String, parent: String) -> Self {
        TypeLists { name, parent }
    }
}

impl Command for list_type {
    type Res = Vec<TypeLists>;

    fn back(self) -> Vec<TypeLists> {
        Default::default()
    }
}

/// Get device list properties.
///
/// # Example
///
/// ```text
/// -> { "execute": "device-list-properties", "arguments": {"typename": "virtio-blk-pci"} }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct device_list_properties {
    pub typename: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProps {
    pub name: String,
    #[serde(rename = "type")]
    pub prop_type: String,
}

impl Command for device_list_properties {
    type Res = Vec<DeviceProps>;

    fn back(self) -> Vec<DeviceProps> {
        Default::default()
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct block_commit {}

impl Command for block_commit {
    type Res = Vec<DeviceProps>;

    fn back(self) -> Vec<DeviceProps> {
        Default::default()
    }
}

/// Query tpm models of StratoVirt.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-tpm-models" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_tpm_models {}

impl Command for query_tpm_models {
    type Res = Vec<String>;

    fn back(self) -> Vec<String> {
        Default::default()
    }
}

/// Query target of StratoVirt.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-tpm-types" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_tpm_types {}

impl Command for query_tpm_types {
    type Res = Vec<String>;

    fn back(self) -> Vec<String> {
        Default::default()
    }
}

/// Query command line options.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-command-line-options" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_command_line_options {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CmdParameter {
    name: String,
    help: String,
    #[serde(rename = "type")]
    paramter_type: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CmdLine {
    pub parameters: Vec<CmdParameter>,
    pub option: String,
}

impl Command for query_command_line_options {
    type Res = Vec<CmdLine>;

    fn back(self) -> Vec<CmdLine> {
        Default::default()
    }
}

/// Query capabilities of migration.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-migrate-capabilities" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_migrate_capabilities {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MigrateCapabilities {
    pub state: bool,
    pub capability: String,
}

impl Command for query_migrate_capabilities {
    type Res = Vec<MigrateCapabilities>;

    fn back(self) -> Vec<MigrateCapabilities> {
        Default::default()
    }
}

/// Query target of StratoVirt.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-qmp-schema" }
/// <- {"return":{}}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_qmp_schema {}

impl Command for query_qmp_schema {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// Query capabilities of sev.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-sev-capabilities" }
/// <- {"return":{}}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_sev_capabilities {}

impl Command for query_sev_capabilities {
    type Res = Empty;

    fn back(self) -> Empty {
        Default::default()
    }
}

/// List all Qom.
///
/// # Example
///
/// ```text
/// -> { "execute": "qom-list" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct qom_list {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PropList {
    pub name: String,
    #[serde(rename = "type")]
    pub prop_type: String,
}

impl Command for qom_list {
    type Res = Vec<PropList>;

    fn back(self) -> Vec<PropList> {
        Default::default()
    }
}

/// Query char devices.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-chardev" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_chardev {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ChardevInfo {
    #[serde(rename = "frontend-open")]
    pub open: bool,
    pub filename: String,
    pub label: String,
}

impl Command for query_chardev {
    type Res = Vec<ChardevInfo>;

    fn back(self) -> Vec<ChardevInfo> {
        Default::default()
    }
}

/// Get qom properties.
///
/// # Example
///
/// ```text
/// -> { "execute": "qom_get" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct qom_get {}

impl Command for qom_get {
    type Res = bool;

    fn back(self) -> bool {
        Default::default()
    }
}

/// Query blocks of StratoVirt.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-block" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_block {}

impl Command for query_block {
    type Res = Vec<Cmd>;

    fn back(self) -> Vec<Cmd> {
        Default::default()
    }
}

/// Query named block node.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-named-block-nodes" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_named_block_nodes {}

impl Command for query_named_block_nodes {
    type Res = Vec<Cmd>;

    fn back(self) -> Vec<Cmd> {
        Default::default()
    }
}

/// Query status of blocks.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-blockstats" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_blockstats {}

impl Command for query_blockstats {
    type Res = Vec<Cmd>;

    fn back(self) -> Vec<Cmd> {
        Default::default()
    }
}

/// Query capabilities of gic.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-gic-capabilities" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_gic_capabilities {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GicCap {
    emulated: bool,
    version: u32,
    kernel: bool,
}

impl Command for query_gic_capabilities {
    type Res = Vec<GicCap>;

    fn back(self) -> Vec<GicCap> {
        Default::default()
    }
}

/// Query information of iothreads.
///
/// # Example
///
/// ```text
/// -> { "execute": "query-iothreads" }
/// <- {"return":[]}
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_iothreads {}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct IothreadInfo {
    #[serde(rename = "poll-shrink")]
    pub shrink: u32,
    #[serde(rename = "thread-id")]
    pub pid: u32,
    #[serde(rename = "poll-grow")]
    pub grow: u32,
    #[serde(rename = "poll-max-ns")]
    pub max: u32,
    pub id: String,
}

impl Command for query_iothreads {
    type Res = Vec<IothreadInfo>;

    fn back(self) -> Vec<IothreadInfo> {
        Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qmp_unexpected_arguments() {
        // qmp: quit.
        let json_msg = r#"
        {
            "execute": "quit"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // unexpected arguments for quit.
        let json_msg = r#"
        {
            "execute": "quit" ,
            "arguments": "isdf"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"invalid type: string "isdf", expected struct quit"#;
        assert!(err_msg == ret_msg);

        // qmp: stop.
        let json_msg = r#"
        {
            "execute": "stop"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // unexpected arguments for stop.
        let json_msg = r#"
        {
            "execute": "stop" ,
            "arguments": "isdf"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"invalid type: string "isdf", expected struct stop"#;
        assert!(err_msg == ret_msg);

        // qmp: cont.
        let json_msg = r#"
        {
            "execute": "cont"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // unexpected arguments for count.
        let json_msg = r#"
        {
            "execute": "cont" ,
            "arguments": "isdf"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"invalid type: string "isdf", expected struct cont"#;
        assert!(err_msg == ret_msg);

        // qmp: query-hotpluggable-cpus.
        let json_msg = r#"
        {
            "execute": "query-hotpluggable-cpus"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // unexpected arguments for query-hotpluggable-cpus.
        let json_msg = r#"
        {
            "execute": "query-hotpluggable-cpus" ,
            "arguments": "isdf"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"invalid type: string "isdf", expected struct query_hotpluggable_cpus"#;
        assert!(err_msg == ret_msg);

        // qmp: query-cpus.
        let json_msg = r#"
        {
            "execute": "query-cpus"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // unexpected arguments for query-cpus.
        let json_msg = r#"
        {
            "execute": "query-cpus" ,
            "arguments": "isdf"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"invalid type: string "isdf", expected struct query_cpus"#;
        assert!(err_msg == ret_msg);

        // qmp: query-ststus.
        let json_msg = r#"
        {
            "execute": "query-status"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // unexpected arguments for query-status.
        let json_msg = r#"
        {
            "execute": "query-status" ,
            "arguments": "isdf"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"invalid type: string "isdf", expected struct query_status"#;
        assert!(err_msg == ret_msg);
    }

    #[test]
    fn test_wrong_qmp_arguments() {
        // right arguments for device_add.
        let json_msg = r#"
        {
            "execute": "device_add" ,
            "arguments": {
                "id":"net-0",
                "driver":"virtio-net-mmio",
                "addr":"0x0"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg.contains(ret_msg));

        // unknow arguments for device_add.
        let json_msg = r#"
        {
            "execute": "device_add" ,
            "arguments": {
                "id":"net-0",
                "driver":"virtio-net-mmio",
                "addr":"0x0",
                "UnknowArg": "should go to error"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"unknown field `UnknowArg`"#;
        assert!(err_msg.contains(ret_msg));

        // wrong spelling arguments for device_add.
        let json_msg = r#"
        {
            "execute": "device_add" ,
            "arguments": {
                "id":"net-0",
                "driv":"virtio-net-mmio",
                "addr":"0x0"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"unknown field `driv`"#;
        assert!(err_msg.contains(ret_msg));

        // right arguments for device_del.
        let json_msg = r#"
        {
            "execute": "device_del" ,
            "arguments": {
                "id": "net-1"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg.contains(ret_msg));

        // wrong arguments for device_del.
        let json_msg = r#"
        {
            "execute": "device_del" ,
            "arguments": {
                "value": "h8i"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let unknow_msg = r#"unknown field `value`"#;
        let expect_msg = r#"expected `id`"#;
        assert!(err_msg.contains(unknow_msg));
        assert!(err_msg.contains(expect_msg));

        // missing arguments for getfd.
        let json_msg = r#"
        {
            "execute": "getfd"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"missing field `arguments`"#;
        assert!(err_msg == ret_msg);

        // unexpected arguments for getfd.
        let json_msg = r#"
        {
            "execute": "getfd" ,
            "arguments": "isdf"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"invalid type: string "isdf", expected struct getfd"#;
        assert!(err_msg == ret_msg);

        // right arguments for getfd.
        let json_msg = r#"
        {
            "execute": "getfd",
            "arguments": {
                "fdname": "fd1"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // right arguments for blockdev-add.
        let json_msg = r#"
        {
            "execute": "blockdev-add",
            "arguments": {
                "node-name": "drive-0",
                "file": {
                    "driver": "file",
                    "filename": "/path/to/block"
                },
                "cache": {
                    "direct": true
                },
                "read-only": false
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // right arguments for device-add.
        let json_msg = r#"
        {
            "execute": "device_add",
            "arguments": {
                "id": "drive-0",
                "driver": "virtio-blk-mmio",
                "addr": "0x1"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // right arguments for netdev-add.
        let json_msg = r#"
        {
            "execute": "netdev_add",
            "arguments": {
                "id": "net-0",
                "ifname":"tap0"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);
    }

    #[test]
    fn test_unsupported_commands() {
        // unsupported qmp command.
        let json_msg = r#"
        {
            "execute": "hello-world" ,
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"unknown variant `hello-world`"#;
        assert!(err_msg.contains(part_msg));

        // unsupported qmp command, and unknow field.
        let json_msg = r#"
        {
            "execute": "hello-world" ,
            "arguments": {
                "msg": "hello",
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"unknown variant `hello-world`"#;
        assert!(err_msg.contains(part_msg));
    }

    #[test]
    fn test_qmp_commands() {
        // query-version
        let json_msg = r#"
        {
            "execute": "query-version"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"ok"#;
        assert!(err_msg.contains(part_msg));

        // query-target
        let json_msg = r#"
        {
            "execute": "query-target"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"ok"#;
        assert!(err_msg.contains(part_msg));

        // query-commands
        let json_msg = r#"
        {
            "execute": "query-commands"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"ok"#;
        assert!(err_msg.contains(part_msg));
    }
}
