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

pub use serde_json::Value as Any;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use strum_macros::{EnumIter, EnumString, EnumVariantNames};

use super::qmp_channel::TimeStamp;
use super::qmp_response::{Empty, Version};
use util::aio::AioEngine;

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

macro_rules! define_qmp_command_enum {
    ($($command:ident($name:expr, $args_type:ty, $need_strum:ident $(, $serde_default:ident)?)),*) => {
        /// A enum to store all command struct
        #[derive(Debug, Clone, Serialize, Deserialize, EnumIter, EnumVariantNames, EnumString)]
        #[serde(tag = "execute")]
        #[serde(deny_unknown_fields)]
        pub enum QmpCommand {
            $(
                #[serde(rename = $name)]
                #[cfg_attr($need_strum, strum(serialize = $name))]
                $command {
                    $(#[serde($serde_default)])?
                    arguments: $args_type,
                    #[serde(default, skip_serializing_if = "Option::is_none")]
                    id: Option<String>,
                },
            )*
        }
    };
}

// QMP command enum definition example: command("name", arguments, ..)
define_qmp_command_enum!(
    qmp_capabilities("qmp_capabilities", qmp_capabilities, FALSE, default),
    quit("quit", quit, FALSE, default),
    stop("stop", stop, FALSE, default),
    cont("cont", cont, FALSE, default),
    system_powerdown("system_powerdown", system_powerdown, FALSE, default),
    system_reset("system_reset", system_reset, FALSE, default),
    device_add("device_add", Box<device_add>, FALSE),
    device_del("device_del", device_del, FALSE),
    chardev_add("chardev-add", chardev_add, FALSE),
    chardev_remove("chardev-remove", chardev_remove, FALSE),
    netdev_add("netdev_add", Box<netdev_add>, FALSE),
    netdev_del("netdev_del", netdev_del, FALSE),
    cameradev_add("cameradev_add", cameradev_add, FALSE),
    cameradev_del("cameradev_del", cameradev_del, FALSE),
    query_hotpluggable_cpus("query-hotpluggable-cpus", query_hotpluggable_cpus, TRUE, default),
    query_cpus("query-cpus", query_cpus, TRUE, default),
    query_status("query-status", query_status, FALSE, default),
    getfd("getfd", getfd, FALSE),
    blockdev_add("blockdev-add", Box<blockdev_add>, FALSE),
    blockdev_del("blockdev-del", blockdev_del, FALSE),
    balloon("balloon", balloon, FALSE, default),
    query_mem("query-mem", query_mem, FALSE, default),
    query_mem_gpa("query-mem-gpa", query_mem_gpa, FALSE, default),
    query_balloon("query-balloon", query_balloon, FALSE, default),
    query_vnc("query-vnc", query_vnc, TRUE, default),
    query_display_image("query-display-image", query_display_image, FALSE, default),
    migrate("migrate", migrate, FALSE),
    query_migrate("query-migrate", query_migrate, FALSE, default),
    cancel_migrate("migrate_cancel", cancel_migrate, FALSE, default),
    query_version("query-version", query_version, FALSE, default),
    query_commands("query-commands", query_commands, FALSE, default),
    query_target("query-target", query_target, FALSE, default),
    query_kvm("query-kvm", query_kvm, FALSE, default),
    query_machines("query-machines", query_machines, FALSE, default),
    query_events("query-events", query_events, TRUE, default),
    list_type("qom-list-types", list_type, FALSE, default),
    device_list_properties("device-list-properties", device_list_properties, FALSE, default),
    block_commit("block-commit", block_commit, TRUE, default),
    query_tpm_models("query-tpm-models", query_tpm_models, FALSE, default),
    query_tpm_types("query-tpm-types", query_tpm_types, FALSE, default),
    query_command_line_options("query-command-line-options", query_command_line_options, FALSE, default),
    query_migrate_capabilities("query-migrate-capabilities", query_migrate_capabilities, FALSE, default),
    query_qmp_schema("query-qmp-schema", query_qmp_schema, FALSE, default),
    query_sev_capabilities("query-sev-capabilities", query_sev_capabilities, FALSE, default),
    query_chardev("query-chardev", query_chardev, TRUE, default),
    qom_list("qom-list", qom_list, TRUE, default),
    qom_get("qom-get", qom_get, TRUE, default),
    query_block("query-block", query_block, TRUE, default),
    query_named_block_nodes("query-named-block-nodes", query_named_block_nodes, TRUE, default),
    query_blockstats("query-blockstats", query_blockstats, TRUE, default),
    query_block_jobs("query-block-jobs", query_block_jobs, TRUE, default),
    query_gic_capabilities("query-gic-capabilities", query_gic_capabilities, TRUE, default),
    query_iothreads("query-iothreads", query_iothreads, TRUE, default),
    update_region("update_region", update_region, TRUE, default),
    input_event("input_event", input_event, FALSE, default),
    human_monitor_command("human-monitor-command", human_monitor_command, FALSE),
    blockdev_snapshot_internal_sync("blockdev-snapshot-internal-sync", blockdev_snapshot_internal, FALSE),
    blockdev_snapshot_delete_internal_sync("blockdev-snapshot-delete-internal-sync", blockdev_snapshot_internal, FALSE),
    query_vcpu_reg("query-vcpu-reg", query_vcpu_reg, FALSE),
    trace_event_get_state("trace-event-get-state", trace_event_get_state, FALSE),
    trace_event_set_state("trace-event-set-state", trace_event_set_state, FALSE)
);

/// Command trait for Deserialize and find back Response.
trait Command: Serialize {
    type Res: DeserializeOwned;
    fn back(self) -> Self::Res;
}

macro_rules! generate_command_impl {
    ($name:ident, $res_type:ty) => {
        impl Command for $name {
            type Res = $res_type;

            fn back(self) -> Self::Res {
                Default::default()
            }
        }
    };
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
generate_command_impl!(qmp_capabilities, Empty);

/// quit
///
/// This command will cause the StratoVirt process to exit gracefully. While every
/// attempt is made to send the QMP response before terminating, this is not
/// guaranteed. When using this interface, a premature EOF would not be
/// unexpected.
///
/// # Examples
///
/// ```text
/// -> { "execute": "quit" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct quit {}
generate_command_impl!(quit, Empty);

/// stop
///
/// Stop all guest VCPU execution.
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
generate_command_impl!(stop, Empty);

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
generate_command_impl!(cont, Empty);

/// system_powerdown
///
/// Requests that a guest perform a powerdown operation.
///
/// # Examples
///
/// ```test
/// -> { "execute": "system_powerdown" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct system_powerdown {}
generate_command_impl!(system_powerdown, Empty);

/// system_reset
///
/// Reset guest VCPU execution.
///
/// # Examples
///
/// ```text
/// -> { "execute": "system_reset" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct system_reset {}
generate_command_impl!(system_reset, Empty);

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
///      "arguments": { "id": "net-0", "driver": "virtio-net-mmio", "addr": "0x0" } }
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
    #[serde(rename = "chardev")]
    pub chardev: Option<String>,
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
    pub sysfsdev: Option<String>,
    #[serde(rename = "queue-size")]
    pub queue_size: Option<u16>,
    pub port: Option<String>,
    pub backend: Option<String>,
    pub path: Option<String>,
    pub cameradev: Option<String>,
    pub hostbus: Option<String>,
    pub hostaddr: Option<String>,
    pub hostport: Option<String>,
    pub vendorid: Option<String>,
    pub productid: Option<String>,
    pub isobufs: Option<String>,
    pub isobsize: Option<String>,
    #[serde(rename = "cpu-id")]
    pub cpu_id: Option<u8>,
}

pub type DeviceAddArgument = device_add;
generate_command_impl!(device_add, Empty);

/// update_region
///
/// # Arguments
///
/// * `update_type` - update type: add or delete.
/// * `region_type` - the type of the region: io, ram_device, rom_device.
/// * `offset` - the offset of the father region.
/// * `size` - the size of the region.
/// * `priority` - the priority of the region.
/// * `romd` - read only mode.
/// * `ioeventfd` - is there an ioeventfd.
/// * `ioeventfd_data` - the matching data for ioeventfd.
/// * `ioeventfd_size` - the size of matching data.
///
/// Additional arguments depend on the type.
///
/// # Examples
///
/// ```text
/// -> { "execute": "update_region",
///      "arguments": { "update_type": "add", "region_type": "io_region",
///                     "offset": 0, "size": 4096, "priority": 99 } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct update_region {
    #[serde(rename = "update_type")]
    pub update_type: String,
    #[serde(rename = "region_type")]
    pub region_type: String,
    #[serde(rename = "offset")]
    pub offset: u64,
    #[serde(rename = "size")]
    pub size: u64,
    #[serde(rename = "priority")]
    pub priority: u64,
    #[serde(rename = "read_only_mode")]
    pub romd: Option<bool>,
    #[serde(rename = "ioeventfd")]
    pub ioeventfd: Option<bool>,
    #[serde(rename = "ioeventfd_data")]
    pub ioeventfd_data: Option<u64>,
    #[serde(rename = "ioeventfd_size")]
    pub ioeventfd_size: Option<u64>,
    #[serde(rename = "device_fd_path")]
    pub device_fd_path: Option<String>,
}

pub type UpdateRegionArgument = update_region;
generate_command_impl!(update_region, Empty);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOptions {
    pub driver: String,
    pub filename: String,
    #[serde(default)]
    pub aio: AioEngine,
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
///      "arguments": { "node-name": "drive-0",
///                     "file": { "driver": "file", "filename": "/path/to/block" },
///                     "cache": { "direct": true }, "read-only": false } }
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
    #[serde(rename = "detect-zeroes")]
    pub detect_zeroes: Option<String>,
    pub driver: Option<String>,
    pub backing: Option<String>,
    pub discard: Option<String>,
    pub id: Option<String>,
    pub options: Option<String>,
    #[serde(rename = "throttling.iops-total")]
    pub iops: Option<u64>,
    #[serde(rename = "l2-cache-size")]
    pub l2_cache_size: Option<String>,
    #[serde(rename = "refcount-cache-size")]
    pub refcount_cache_size: Option<String>,
}

pub type BlockDevAddArgument = blockdev_add;
generate_command_impl!(blockdev_add, Empty);

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
///      "arguments": { "id": "net-0", "ifname": "tap0", "fds": 123 } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct netdev_add {
    pub id: String,
    #[serde(rename = "ifname")]
    pub if_name: Option<String>,
    pub fd: Option<String>,
    pub fds: Option<String>,
    pub dnssearch: Option<String>,
    #[serde(rename = "type")]
    pub net_type: Option<String>,
    pub vhost: Option<bool>,
    pub vhostfd: Option<String>,
    pub vhostfds: Option<String>,
    pub downscript: Option<String>,
    pub script: Option<String>,
    pub queues: Option<u16>,
    pub chardev: Option<String>,
}

pub type NetDevAddArgument = netdev_add;
generate_command_impl!(netdev_add, Empty);

/// cameradev_add
///
/// # Arguments
///
/// * `id` - the device's ID, must be unique.
/// * `path` - the backend camera file, eg. /dev/video0.
/// * `driver` - the backend type, eg. v4l2.
///
/// # Examples
///
/// ```text
/// -> { "execute": "cameradev_add",
///      "arguments": { "id": "cam0", "driver": "v4l2", "path": "/dev/video0" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct cameradev_add {
    pub id: String,
    pub path: Option<String>,
    pub driver: String,
}

pub type CameraDevAddArgument = cameradev_add;
generate_command_impl!(cameradev_add, Empty);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddrDataOptions {
    pub path: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddrOptions {
    #[serde(rename = "type")]
    pub addr_type: String,
    #[serde(rename = "data")]
    pub addr_data: AddrDataOptions,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendDataOptions {
    pub addr: AddrOptions,
    pub server: bool,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendOptions {
    #[serde(rename = "type")]
    pub backend_type: String,
    #[serde(rename = "data")]
    pub backend_data: BackendDataOptions,
}

/// chardev-add
///
/// # Arguments
///
/// * `id` - the character device's ID, must be unique.
/// * `backend` - the chardev backend info.
///
/// Additional arguments depend on the type.
///
/// # Examples
///
/// ```text
/// -> { "execute": "chardev-add",
///      "arguments": { "id": "chardev_id", "backend": { "type": "socket", "data": {
///          "addr": { "type": "unix", "data": { "path": "/path/to/socket" } },
///          "server": false } } } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct chardev_add {
    pub id: String,
    pub backend: BackendOptions,
}

pub type CharDevAddArgument = chardev_add;
generate_command_impl!(chardev_add, Empty);

/// chardev-remove
///
/// Remove a chardev backend.
///
/// # Arguments
///
/// * `id` - The ID of the character device.
///
/// # Errors
///
/// If `id` is not a valid chardev backend, DeviceNotFound.
///
/// # Examples
///
/// ```text
/// -> { "execute": "chardev-remove", "arguments": { "id": "chardev_id" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct chardev_remove {
    pub id: String,
}
generate_command_impl!(chardev_remove, Empty);

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
/// -> { "execute": "device_del", "arguments": { "id": "net-0" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct device_del {
    pub id: String,
}
generate_command_impl!(device_del, Empty);

/// blockdev-del
///
/// Remove a block device.
///
/// # Arguments
///
/// * `node_name` - The name of the device node to remove.
///
/// # Errors
///
/// If `node_name` is not a valid device, DeviceNotFound.
///
/// # Examples
///
/// ```text
/// -> { "execute": "blockdev-del", "arguments": { "node-name": "node0" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct blockdev_del {
    #[serde(rename = "node-name")]
    pub node_name: String,
}
generate_command_impl!(blockdev_del, Empty);

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
/// If `id` is not a valid network backend, DeviceNotFound.
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
generate_command_impl!(netdev_del, Empty);

/// cameradev_del
///
/// Remove a camera backend.
///
/// # Arguments
///
/// * `id` - The name of the camera backend to remove.
///
/// # Errors
///
/// If `id` is not a valid camera backend, DeviceNotFound.
///
/// # Examples
///
/// ```text
/// -> { "execute": "cameradev_del", "arguments": { "id": "cam0" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct cameradev_del {
    pub id: String,
}
generate_command_impl!(cameradev_del, Empty);

/// query-hotpluggable-cpus
///
/// Query which CPU types could be plugged.
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
/// <- { "return": [
///      {
///         "type": host-x-cpu", "vcpus-count": 1,
///         "props": {"core-id": 0, "socket-id": 1, "thread-id": 0 }
///      },
///      {
///         "qom-path": "/machine/unattached/device[0]",
///         "type": "host-x-cpu", "vcpus-count": 1,
///         "props": { "core-id": 0, "socket-id": 0, "thread-id": 0 }
///      } ] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_hotpluggable_cpus {}
generate_command_impl!(query_hotpluggable_cpus, Vec<HotpluggableCPU>);

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
    #[cfg(target_arch = "x86_64")]
    #[serde(rename = "die_id", default, skip_serializing_if = "Option::is_none")]
    pub die_id: Option<isize>,
    #[cfg(target_arch = "aarch64")]
    #[serde(
        rename = "cluster_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cluster_id: Option<isize>,
    #[serde(rename = "thread-id", default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<isize>,
    #[serde(rename = "core-id", default, skip_serializing_if = "Option::is_none")]
    pub core_id: Option<isize>,
}

/// query-cpus
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
///          } ] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_cpus {}
generate_command_impl!(query_cpus, Vec<CpuInfo>);

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
/// <- { "return": { "running": true, "singlestep": false, "status": "running" } }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_status {}
generate_command_impl!(query_status, StatusInfo);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    #[serde(rename = "singlestep")]
    pub singlestep: bool,
    #[serde(rename = "running")]
    pub running: bool,
    #[serde(rename = "status")]
    pub status: RunState,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum RunState {
    #[serde(rename = "debug")]
    #[default]
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

/// migrate
///
/// Migrates the current running guest to another VM or file.
///
/// # Arguments
///
/// * `uri` - the Uniform Resource Identifier of the destination VM or file.
///
/// # Examples
///
/// ```text
/// -> { "execute": "migrate", "arguments": { "uri": "tcp:0:4446" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct migrate {
    #[serde(rename = "uri")]
    pub uri: String,
}
generate_command_impl!(migrate, Empty);

/// query-migrate
///
/// Returns information about current migration.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-migrate" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_migrate {}
generate_command_impl!(query_migrate, MigrationInfo);

/// migrate_cancel
///
/// Cancel migrate the current VM.
///
/// # Examples
///
/// ```text
/// -> { "execute": "migrate_cancel" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct cancel_migrate {}
generate_command_impl!(cancel_migrate, MigrationInfo);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationInfo {
    #[serde(rename = "status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// getfd
///
/// Receive a file descriptor via SCM rights and assign it a name.
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
generate_command_impl!(getfd, Empty);

/// query-balloon
///
/// Query the actual size of memory of VM.
///
/// # Returns
///
/// `BalloonInfo` includs the actual size of memory.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-balloon" }
/// <- { "return": { "actual": 8589934592 } }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_balloon {}
generate_command_impl!(query_balloon, BalloonInfo);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BalloonInfo {
    pub actual: u64,
}

/// query-vnc
///
/// Information about current VNC server.
///
/// # Examples
///
/// For pc machine type started with -vnc ip:port(for example: 0.0.0.0:0):
/// ```text
/// -> { "execute": "query-vnc" }
/// <- { "return": {
///         "enabled": true,
///         "host": "0.0.0.0",
///         "service": "50401",
///         "auth": "None",
///         "family": "ipv4",
///         "clients": [
///             "host": "127.0.0.1",
///             "service": "50401",
///             "family": "ipv4",
///         ] } }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_vnc {}
generate_command_impl!(query_vnc, VncInfo);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct VncInfo {
    #[serde(rename = "enabled")]
    pub enabled: bool,
    #[serde(rename = "host")]
    pub host: String,
    #[serde(rename = "service")]
    pub service: String,
    #[serde(rename = "auth")]
    pub auth: String,
    #[serde(rename = "family")]
    pub family: String,
    #[serde(rename = "clients")]
    pub clients: Vec<VncClientInfo>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct VncClientInfo {
    #[serde(rename = "host")]
    pub host: String,
    #[serde(rename = "service")]
    pub service: String,
    #[serde(rename = "family")]
    pub family: String,
}

/// query-display-image
///
/// Information about image of stratovirt.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-display-image" }
/// <- { "return": {
///         "fileDir": /tmp/stratovirt-images,
///         "isSuccess": true, } }
/// ``
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_display_image {}
generate_command_impl!(query_display_image, GpuInfo);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    #[serde(rename = "isSuccess")]
    pub isSuccess: bool,
    #[serde(rename = "fileDir")]
    pub fileDir: String,
}

/// balloon
///
/// Advice VM to change memory size with the argument `value`.
///
/// # Arguments
///
/// * `value` - Memoey size.
///
/// # Notes
///
/// This is only an advice instead of command to VM, therefore, the VM changes
/// its memory according to `value` and its condation.
///
/// # Examples
///
/// ```text
/// -> { "execute": "balloon", "arguments": { "value": 589934492 } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct balloon {
    #[serde(rename = "value")]
    pub value: u64,
}
generate_command_impl!(balloon, Empty);

/// query-version
///
/// Query version of StratoVirt.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-version" }
/// <- { "return": {
///         "version": { "qemu": { "minor": 1, "micro": 0, "major": 5 },
///         "package": "StratoVirt-2.3.0" },
///         "capabilities": [] } }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_version {}
generate_command_impl!(query_version, Version);

/// query-commands
///
/// Query all qmp commands of StratoVirt.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-commands" }
/// <- { "return": [ { "name": "qmp_capabilities" }, { "name": "quit" }, { "name": "stop" },
///        { "name": "cont" }, { "name": "system_powerdown" }, { "name": "system_reset" },
///        { "name": "device_add" }, { "name": "device_del" }, { "name": "chardev_add" },
///        { "name": "chardev_remove" }, { "name": "netdev_add" }, { "name": "netdev_del" },
///        { "name" : "cameradev_add" }, { "name": "cameradev_del" },
///        { "name": "query-hotpluggable-cpus" }, { "name": "query-cpus" } ] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_commands {}
generate_command_impl!(query_commands, Vec<Cmd>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Cmd {
    pub name: String,
}

/// query-target
///
/// Query the target platform where the StratoVirt is running.
///
/// # Examples
///
/// ```text
/// # for X86 platform.
/// -> { "execute": "query-target" }
/// <- { "return": { "arch": "x86_64" } }
///
/// # for Aarch64 platform.
/// -> { "execute": "query-target" }
/// <- { "return": { "arch": "aarch64" } }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_target {}
generate_command_impl!(query_target, Target);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub arch: String,
}

/// query-machines
///
/// Query machine information.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-machines" }
/// <- { "return": [ { "cpu-max": 255, "deprecated": false, "hotpluggable-cpus": true,
///            "name": "none", "numa-mem-supported": false },
///        { "cpu-max": 255, "deprecated": false, "hotpluggable-cpus": true,
///            "name": "microvm", "numa-mem-supported": false },
///        { "cpu-max": 255, "deprecated": false, "hotpluggable-cpus": true,
///            "name": "standardvm", "numa-mem-supported": false } ] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_machines {}
generate_command_impl!(query_machines, Vec<MachineInfo>);

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

/// query-events
///
/// Query all events of StratoVirt.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-events" }
/// <- { "return": [ { "name": "Shutdown" }, { "name": "Reset" },
///        { "name": "Stop" }, { "name": "Resume" }, { "name": "DeviceDeleted" },
///        { "name": "BalloonChanged" } ] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Events {
    pub name: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_events {}
generate_command_impl!(query_events, Vec<Events>);

/// query-kvm
///
/// Query if KVM is enabled.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-kvm" }
/// <- { "return": { "enabled": true, "present": true } }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_kvm {}
generate_command_impl!(query_kvm, KvmInfo);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KvmInfo {
    pub enabled: bool,
    pub present: bool,
}

/// qom-list-types
///
/// This command will return a list of types given search parameters.
///
/// # Examples
///
/// ```text
/// -> { "execute": "qom-list-types" }
/// <- { "return": [ { "name": "ioh3420", "parent": "pcie-root-port-base" },
///        { "name": "pcie-root-port", "parent": "pcie-root-port-base" },
///        { "name": "pcie-pci-bridge", "parent": "base-pci-bridge" },
///        { "name": "pci-bridge", "parent": "base-pci-bridge" } ] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct list_type {}
generate_command_impl!(list_type, Vec<TypeLists>);

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

/// device-list-properties
///
/// List properties associated with a device.
///
/// # Examples
///
/// ```text
/// -> { "execute": "device-list-properties", "arguments": { "typename": "virtio-blk-pci" } }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct device_list_properties {
    pub typename: String,
}
generate_command_impl!(device_list_properties, Vec<DeviceProps>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProps {
    pub name: String,
    #[serde(rename = "type")]
    pub prop_type: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct block_commit {}
generate_command_impl!(block_commit, Vec<DeviceProps>);

/// query-tpm-models
///
/// Query tpm models of StratoVirt.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-tpm-models" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_tpm_models {}
generate_command_impl!(query_tpm_models, Vec<String>);

/// query-tpm-types
///
/// Query target of StratoVirt.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-tpm-types" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_tpm_types {}
generate_command_impl!(query_tpm_types, Vec<String>);

/// query-command-line-options
///
/// Query command line options.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-command-line-options" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_command_line_options {}
generate_command_impl!(query_command_line_options, Vec<CmdLine>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CmdParameter {
    pub name: String,
    pub help: String,
    #[serde(rename = "type")]
    pub parameter_type: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CmdLine {
    pub parameters: Vec<CmdParameter>,
    pub option: String,
}

/// query-migrate-capabilities
///
/// Query capabilities of migration.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-migrate-capabilities" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_migrate_capabilities {}
generate_command_impl!(query_migrate_capabilities, Vec<MigrateCapabilities>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MigrateCapabilities {
    pub state: bool,
    pub capability: String,
}

/// query-qmp-schema
///
/// Query target of StratoVirt.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-qmp-schema" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_qmp_schema {}
generate_command_impl!(query_qmp_schema, Empty);

/// query-sev-capabilities
///
/// Query capabilities of sev.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-sev-capabilities" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_sev_capabilities {}
generate_command_impl!(query_sev_capabilities, Empty);

/// qom-list
///
/// List all Qom.
///
/// # Examples
///
/// ```text
/// -> { "execute": "qom-list" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct qom_list {}
generate_command_impl!(qom_list, Vec<PropList>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PropList {
    pub name: String,
    #[serde(rename = "type")]
    pub prop_type: String,
}

/// query-chardev
///
/// Query char devices.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-chardev" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_chardev {}
generate_command_impl!(query_chardev, Vec<ChardevInfo>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ChardevInfo {
    #[serde(rename = "frontend-open")]
    pub open: bool,
    pub filename: String,
    pub label: String,
}

/// qom-get
///
/// Get qom properties.
///
/// # Examples
///
/// ```text
/// -> { "execute": "qom-get" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct qom_get {}
generate_command_impl!(qom_get, bool);

/// query-block
///
/// Query blocks of StratoVirt.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-block" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_block {}
generate_command_impl!(query_block, Vec<Cmd>);

/// query-named-block-nodes
///
/// Query named block node.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-named-block-nodes" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_named_block_nodes {}
generate_command_impl!(query_named_block_nodes, Vec<Cmd>);

/// query-blockstats
///
/// Query status of blocks.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-blockstats" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_blockstats {}
generate_command_impl!(query_blockstats, Vec<Cmd>);

/// query-block-jobs
///
/// Query jobs of blocks.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-block-jobs" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_block_jobs {}
generate_command_impl!(query_block_jobs, Vec<Cmd>);

/// query-gic-capabilities
///
/// Query capabilities of gic.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-gic-capabilities" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_gic_capabilities {}
generate_command_impl!(query_gic_capabilities, Vec<GicCap>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GicCap {
    emulated: bool,
    version: u32,
    kernel: bool,
}

/// query-iothreads
///
/// Query information of iothreads.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-iothreads" }
/// <- { "return": [] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct query_iothreads {}
generate_command_impl!(query_iothreads, Vec<IothreadInfo>);

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

/// input_event
///
/// # Arguments
///
/// * `key` - the input type such as 'keyboard' or 'pointer'.
/// * `value` - the input value.
///
/// # Examples
///
/// ```text
/// -> { "execute": "input_event",
///      "arguments": { "key": "pointer", "value": "100,200,1" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct input_event {
    pub key: String,
    pub value: String,
}
generate_command_impl!(input_event, Vec<input_event>);

/// human-monitor-command
///
/// # Arguments
///
/// * `command_line` - the command line will be executed.
///
/// # Examples
///
/// ```text
/// -> { "execute": "human-monitor-command",
///      "arguments": { "command-line": "drive_add dummy
///          file=/path/to/file,format=raw,if=none,id=drive-id" } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct human_monitor_command {
    #[serde(rename = "command-line")]
    pub command_line: String,
}
pub type HumanMonitorCmdArgument = human_monitor_command;

/// blockdev-snapshot-internal-sync
///
/// Create disk internal snapshot.
///
/// # Arguments
///
/// * `device` - the valid block device.
/// * `name` - the snapshot name.
///
/// # Examples
///
/// ```text
/// -> { "execute": "blockdev-snapshot-internal-sync",
///      "arguments": { "device": "disk0", "name": "snapshot1" } }
/// <- { "return": {} }
/// ```
///
/// blockdev-snapshot-delete-internal-sync
///
/// Delete disk internal snapshot.
///
/// # Arguments
///
/// * `device` - the valid block device.
/// * `name` - the snapshot name.
///
/// # Examples
///
/// ```text
/// -> { "execute": "blockdev-snapshot-delete-internal-sync",
///      "arguments": { "device": "disk0", "name": "snapshot1" } }
/// <- { "return": {
///                    "id": "1",
///                    "name": "snapshot0",
///                    "vm-state-size": 0,
///                    "date-sec": 1000012,
///                    "date-nsec": 10,
///                    "vm-clock-sec": 100,
///                    "vm-clock-nsec": 20,
///                    "icount": 220414
///    } }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct blockdev_snapshot_internal {
    pub device: String,
    pub name: String,
}
pub type BlockdevSnapshotInternalArgument = blockdev_snapshot_internal;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "vm-state-size")]
    pub vm_state_size: u64,
    #[serde(rename = "date-sec")]
    pub date_sec: u32,
    #[serde(rename = "date-nsec")]
    pub date_nsec: u32,
    #[serde(rename = "vm-clock-nsec")]
    pub vm_clock_nsec: u64,
    #[serde(rename = "icount")]
    pub icount: u64,
}

/// query-mem
///
/// Query memory address space flat.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-mem" }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_mem {}
generate_command_impl!(query_mem, Empty);

/// query-vcpu-reg
///
/// Query vcpu register value.
///
/// # Arguments
///
/// * `addr` - the register addr will be query.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-vcpu-reg",
///      "arguments": { "addr": "603000000013df1a", "vcpu": 0 } }
/// <- { "return": "348531C5" }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_vcpu_reg {
    #[serde(rename = "addr")]
    pub addr: String,
    #[serde(rename = "vcpu")]
    pub vcpu: usize,
}
pub type QueryVcpuRegArgument = query_vcpu_reg;

/// query-mem-gpa
///
/// Query the value of the guest physical address.
///
/// # Examples
///
/// ```text
/// -> { "execute": "query-mem-gpa", "arguments": { "gpa": "13c4d1d00" } }
/// <- { "return": "B9000001" }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct query_mem_gpa {
    #[serde(rename = "gpa")]
    pub gpa: String,
}
pub type QueryMemGpaArgument = query_mem_gpa;

macro_rules! define_qmp_event_enum {
    ($($event:ident($name:expr, $data_type:ty $(, $serde_default:ident)?)),*) => {
        /// A enum to store all event struct
        #[derive(Debug, Clone, Serialize, Deserialize, EnumIter, EnumVariantNames, EnumString)]
        #[serde(tag = "event")]
        pub enum QmpEvent {
            $(
                #[serde(rename = $name)]
                #[strum(serialize = $name)]
                $event {
                    $(#[serde($serde_default)])?
                    data: $data_type,
                    timestamp: TimeStamp,
                },
            )*
        }
    };
}

// QMP event enum definition example: event("name", data, ..)
define_qmp_event_enum!(
    Shutdown("SHUTDOWN", Shutdown),
    Reset("RESET", Reset),
    Stop("STOP", Stop, default),
    Resume("RESUME", Resume, default),
    Powerdown("POWERDOWN", Powerdown, default),
    CpuResize("CPU_RESIZE", CpuResize, default),
    DeviceDeleted("DEVICE_DELETED", DeviceDeleted),
    BalloonChanged("BALLOON_CHANGED", BalloonInfo)
);

/// Shutdown
///
/// Emitted when the virtual machine has shut down, indicating that StratoVirt is
/// about to exit.
///
/// # Notes
///
/// If the command-line option "-no-shutdown" has been specified, StratoVirt
/// will not exit, and a STOP event will eventually follow the SHUTDOWN event.
///
/// # Examples
///
/// ```text
/// <- { "event": "SHUTDOWN",
///      "data": { "guest": true, "reason": "guest-shutdown" },
///      "timestamp": { "seconds": 1265044230, "microseconds": 450486 } }
/// ```
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
/// Emitted when the virtual machine is reset.
///
/// # Examples
///
/// ```text
/// <- { "event": "RESET",
///      "data": { "guest": false },
///      "timestamp": { "seconds": 1265044230, "microseconds": 450486 } }
/// ```
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
/// Emitted when the virtual machine is stopped.
///
/// # Examples
///
/// ```text
/// <- { "event": "STOP",
///      "data": {},
///      "timestamp": { "seconds": 1265044230, "microseconds": 450486 } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Stop {}

/// Resume
///
/// Emitted when the virtual machine resumes execution.
///
/// # Examples
///
/// ```text
/// <- { "event": "RESUME",
///      "data": {},
///      "timestamp": { "seconds": 1265044230, "microseconds": 450486 } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Resume {}

/// Powerdown
///
/// Emitted when the virtual machine powerdown execution.
///
/// # Examples
///
/// ```text
/// <- { "event": "POWERDOWN",
///      "data": {},
///      "timestamp": { "seconds": 1265044230, "microseconds": 450486 } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Powerdown {}

/// CpuResize
///
/// Emitted when the virtual machine cpu hot(un)plug execution.
///
/// # Examples
///
/// ```text
/// <- { "event": "CPU_RESIZE",
///      "data": {},
///      "timestamp": { "seconds": 1265044230, "microseconds": 450486 } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CpuResize {}

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

/// trace-event-get-state
///
/// # Arguments
///
/// * `name` - event name pattern
///
/// # Examples
///
/// ```text
/// -> { "execute": "trace-event-get-state",
///      "arguments": { "name": "event_name" } }
/// <- { "return": [ { "name": "event_name", "state": "disabled" } ] }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct trace_event_get_state {
    #[serde(rename = "name")]
    pub pattern: String,
}
pub type TraceEventGetArgument = trace_event_get_state;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TraceEventInfo {
    pub name: String,
    pub state: bool,
}

/// trace-event-set-state
///
/// # Arguments
///
/// * `name` - event name pattern
/// * `enable` - whether to enable tracing
///
/// # Examples
///
/// ```text
/// -> { "execute": "trace-event-set-state",
///      "arguments": { "name": "event_name",
///                     "enable": true } }
/// <- { "return": {} }
/// ```
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct trace_event_set_state {
    #[serde(rename = "name")]
    pub pattern: String,
    #[serde(rename = "enable")]
    pub enable: bool,
}
pub type TraceEventSetArgument = trace_event_set_state;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qmp_event_msg() {
        let event_json =
            r#"{"event":"STOP","data":{},"timestamp":{"seconds":1575531524,"microseconds":91519}}"#;
        let qmp_event: QmpEvent = serde_json::from_str(&event_json).unwrap();
        match qmp_event {
            QmpEvent::Stop {
                data: _,
                timestamp: _,
            } => {
                assert!(true);
            }
            _ => assert!(false),
        }
    }

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

        // qmp: system_reset.
        let json_msg = r#"
        {
            "execute": "system_reset"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"ok"#;
        assert!(err_msg == ret_msg);

        // unexpected arguments for system_reset.
        let json_msg = r#"
        {
            "execute": "system_reset" ,
            "arguments": "isdf"
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let ret_msg = r#"invalid type: string "isdf", expected struct system_reset"#;
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

    #[test]
    fn test_qmp_netdev_add() {
        // Normal netdev_add test.
        let json_msg = r#"
        {
            "execute": "netdev_add",
            "arguments": {
                "id": "net0",
                "ifname": "tap0",
                "fd": "11",
                "fds": "fd-net00:fd-net01",
                "dnssearch": "test",
                "type": "vhost-user",
                "vhost": true,
                "vhostfd": "21",
                "vhostfds": "vhostfd-net00:vhostfd-net01",
                "downscript": "/etc/ifdown.sh",
                "script": "/etc/ifup.sh",
                "queues": 16,
                "chardev": "char_dev_name"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"ok"#;
        assert!(err_msg.contains(part_msg));

        // Abnormal netdev_add test with invalid vhost type.
        let json_msg = r#"
        {
            "execute": "netdev_add",
            "arguments": {
                "vhost": "invalid_type"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"expected a boolean"#;
        assert!(err_msg.contains(part_msg));

        // Abnormal netdev_add test with invalid queues type.
        let json_msg = r#"
        {
            "execute": "netdev_add",
            "arguments": {
                "queues": "invalid_type"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"expected u16"#;
        assert!(err_msg.contains(part_msg));
    }

    #[test]
    fn test_qmp_input_event() {
        // key event
        let json_msg = r#"
        {
            "execute": "input_event" ,
            "arguments": {
                "key": "keyboard",
                "value": "2,1"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"ok"#;
        assert!(err_msg.contains(part_msg));
        // pointer event
        let json_msg = r#"
        {
            "execute": "input_event" ,
            "arguments": {
                "key": "pointer",
                "value": "4,5,1"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"ok"#;
        assert!(err_msg.contains(part_msg));
    }

    #[test]
    fn test_qmp_human_monitor_command() {
        // Normal test.
        let json_msg = r#"
        {
            "execute": "human-monitor-command" ,
            "arguments": {
                "command-line": "drive_add dummy file=/path/to/file,format=raw,if=none,id=drive-id"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"ok"#;
        assert!(err_msg.contains(part_msg));

        // Abnormal test with invalid arguments.
        let json_msg = r#"
        {
            "execute": "human-monitor-command" ,
            "arguments": {
                "invalid_key": "invalid_value"
            }
        }
        "#;
        let err_msg = match serde_json::from_str::<QmpCommand>(json_msg) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.to_string(),
        };
        let part_msg = r#"unknown field `invalid_key`, expected `command-line`"#;
        assert!(err_msg.contains(part_msg));
    }
}
