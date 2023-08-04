# StratoVirt QMP Reference Manual

## Introduction

StratoVirt controls VM's lifecycle and external api interface with [QMP](https://wiki.qemu.org/Documentation/QMP)
 in the current version.

## QMP Creation

When running StratoVirt, you must create QMP in cmdline arguments as a management interface.

StratoVirt supports UnixSocket-type QMP, you can set it by:

```shell
# cmdline
-qmp unix:/path/to/api/socket,server,nowait
```
Where, the information about 'server' and 'nowait' can be found in [section 2.12 Chardev](#212-chardev)

On top of that, monitor can be used to create QMP connection as well.
The following commands can be used to create a monitor.

Three properties can be set for monitor.

* id: unique device id.
* chardev: char device of monitor.
* mode: the model of monitor. NB: currently only "control" is supported.


```shell
# cmdline
-chardev socket,path=/path/to/monitor/sock,id=chardev_id,server,nowait
-mon chardev=chardev_id,id=monitor_id,mode=control
```

## QMP Connection

After StratoVirt started, you can connect to StratoVirt's QMP and manage it by QMP.

Several steps to connect QMP are showed as following:

```shell
# Start with UnixSocket
$ ncat -U /path/to/api/socket
```

Once connection is built, you will receive a `greeting` message from StratoVirt.

```json
{"QMP":{"version":{"StratoVirt":{"micro":1,"minor":0,"major":0},"package":""},"capabilities":[]}}
```

Now you can input QMP command to control StratoVirt.

## Block device backend management

### blockdev-add

Add a block backend.

#### Arguments

* `node-name` : the name of the block driver node, must be unique.
* `file` : the backend file information.
* `cache` : if use direct io.
* `read-only` : if readonly.
* `driver` : the block image format. Possible values are `raw` or `qcow2`. If not set, default is `raw`.

#### Notes

*Micro VM*

* `node-name` in `blockdev-add` should be same as `id` in `device_add`.

* For `addr`, it start at `0x0` mapping in guest with `vda` on x86_64 platform, and start at `0x1`
 mapping in guest with `vdb` on aarch64 platform.

 * For `driver`, only `raw` is supported.

#### Example

```json
<- {"execute": "blockdev-add", "arguments": {"node-name": "drive-0", "file": {"driver": "file", "filename": "/path/to/block"}, "cache": {"direct": true}, "read-only": false}}
-> {"return": {}}
```

### blockdev-del

Remove a block backend.

#### Arguments

* `node-name` : the name of the block driver node.

#### Example

```json
<- {"execute": "blockdev-del", "arguments": {"node-name": "drive-0"}}
-> {"return": {}}
```

## Net device backend management

### netdev_add

Add a network backend.

#### Arguments

* `id` : the device's ID, must be unique.
* `ifname` : the backend tap dev name.
* `fd` : the opened tap fd.
* `fds` : the opened tap fds.
* `queues` : the num of queues for multi-queue.
* `vhost` : whether to run as a vhost-net device.
* `vhostfd` : the vhost-net device fd.
* `vhostfds` : the vhost-net device fds.
* `chardev` : the chardev name for vhost-user net.

#### Notes

*Micro VM*

* `id` in `netdev_add` should be same as `id` in `device_add`.

* For `addr`, it start at `0x0` mapping in guest with `eth0`.

* It does not support multi-queue.

#### Example

```json
<- {"execute":"netdev_add", "arguments":{"id":"net-0", "ifname":"tap0"}}
-> {"return": {}}
```

### netdev_del

Remove a network backend.

#### Arguments

* `id` : the device's ID.

#### Example

```json
<- {"execute": "netdev_del", "arguments": {"id": "net-0"}}
-> {"return": {}}
```

## Camera device backend management

### cameradev_add

Add a camera backend.

#### Arguments

* `id` : the device's ID, must be unique.
* `driver` : the backend camera type, eg. v4l2 or demo.
* `path` : the backend camera file's path, eg. /dev/video0

#### Notes

* MicroVM is not supported.

#### Example

```json
<- {"execute":"cameradev_add", "arguments":{"id":"cam-0", "driver": "v4l2", "path":"/dev/video0"}}
-> {"return": {}}
```

### cameradev_del

Remove a camera backend.

#### Arguments

* `id` : the device's ID.

#### Notes

* MicroVM is not supported.

#### Example

```json
<- {"execute": "cameradev_del", "arguments": {"id": "cam-0"}}
-> {"return": {}}
```

## Character device backend management

Currently, It only supports Standard VM.

### chardev-add

Add a character device backend.

#### Arguments

* `id` : the character device's ID, must be unique.
* `backend` : the chardev backend info.

#### Notes

*Standard VM*

* `id` in `chardev-add` should be same as `id` in `netdev_add`.

#### Example

```json
<- {"execute":"chardev-add", "arguments": {"id": "chardev_id", "backend": {"type": "socket", "data": {"addr": {"type": "unix", "data": {"path": "/path/to/socket"}}, "server": false}}}}
-> {"return": {}}
```

### chardev-remove

Remove a character device backend.

#### Arguments

* `id` : the character device's ID.

#### Example

```json
<- {"execute": "chardev-remove", "arguments": {"id": "chardev_id"}}
-> {"return": {}}
```

## Hot plug management

StratoVirt supports hot-plug virtio-blk and virtio-net devices with QMP. Standard VM supports hot-plug vfio and vhost-user net devices.

### device_add

Add a device.

#### Arguments

* `id` : the device's ID, must be unique.
* `driver` : the name of the device's driver.
* `addr` : the address device insert into.
* `host` : the PCI device info in the system that contains domain, bus number, slot number and function number.
* `bus` : the bus device insert into. Only for Standard VM.
* `mac` : the mac of the net device.
* `netdev` : the backend of the net device.
* `drive` : the backend of the block device.
* `serial` : the serial of the block device.

#### Notes

*Standard VM*

* Currently, the device can only be hot-plugged to the pcie-root-port device. Therefore, you need to configure the root port on the cmdline before starting the VM.

* Guest kernel config: CONFIG_HOTPLUG_PCI_PCIE=y

* You are not advised to hot plug/unplug devices during VM startup, shutdown or suspension, or when the VM is under high pressure. In this case, the driver in the VM may not respond to requests, causing VM exceptions.

#### Example

```json
<- {"execute":"device_add", "arguments":{"id":"net-0", "driver":"virtio-net-mmio", "addr":"0x0"}}
-> {"return": {}}
```

### device_del

Remove a device from a guest.

#### Arguments

* `id` : the device's ID.

#### Notes

* The device is actually removed when you receive the DEVICE_DELETED event

#### Example

```json
<- {"execute": "device_del", "arguments": {"id": "net-0"}}
-> {"event":"DEVICE_DELETED","data":{"device":"net-0","path":"net-0"},"timestamp":{"seconds":1614310541,"microseconds":554250}}
-> {"return": {}}
```

## Lifecycle Management

With QMP, you can control VM's lifecycle by command `stop`, `cont`, `quit` and check VM state by
 `query-status`.

### stop

Stop all guest VCPUs execution.

#### Example

```json
<- {"execute":"stop"}
-> {"event":"STOP","data":{},"timestamp":{"seconds":1583908726,"microseconds":162739}}
-> {"return":{}}
```

### cont

Resume all guest VCPUs execution.

#### Example

```json
<- {"execute":"cont"}
-> {"event":"RESUME","data":{},"timestamp":{"seconds":1583908853,"microseconds":411394}}
-> {"return":{}}
```

### system_reset

Reset all guest VCPUs execution.

#### Example

```json
<- {"execute":"system_reset"}
-> {"return":{}}
-> {"event":"RESET","data":{"guest":true},"timestamp":{"seconds":1677381086,"microseconds":432033}}
```

### system_powerdown

Requests that a guest perform a powerdown operation.

### Example

```json
<- {"execute":"system_powerdown"}
-> {"return":{}}
-> {"event":"POWERDOWN","data":{},"timestamp":{"seconds":1677850193,"microseconds":617907}}
```

### quit

This command will cause StratoVirt process to exit gracefully.

#### Example

```json
<- {"execute":"quit"}
-> {"return":{}}
-> {"event":"SHUTDOWN","data":{"guest":false,"reason":"host-qmp-quit"},"timestamp":{"ds":1590563776,"microseconds":519808}}
```

### query-status

Query the running status of all VCPUs.

#### Example

```json
<- { "execute": "query-status" }
-> { "return": { "running": true,"singlestep": false,"status": "running" } }
```

### getfd

Receive a file descriptor via SCM rights and assign it a name.

#### Example

```json
<- { "execute": "getfd", "arguments": { "fdname": "fd1" } }
-> { "return": {} }
```

## balloon

With QMP command you can set target memory size of guest and get memory size of guest.

### balloon

Set target memory size of guest.

#### Arguments

* `value` : the memory size.

#### Example

```json
<- { "execute": "balloon", "arguments": { "value": 2147483648 } }
-> {"return":{}}
```

### query-balloon

Get memory size of guest.

#### Example

```json
<- { "execute": "query-balloon" }
-> {"return":{"actual":2147483648}}
```

## Migration

### migrate

Take a snapshot of the VM into the specified directory.

#### Arguments

* `uri` : template path.

#### Example

```json
<- {"execute":"migrate", "arguments":{"uri":"file:path/to/template"}}
-> {"return":{}}
```

### query-migrate

Get snapshot state.

#### Notes

Now there are 5 states during snapshot:

- `None`: Resource is not prepared all.
- `Setup`: Resource is setup, ready to do snapshot.
- `Active`: In snapshot.
- `Completed`: Snapshot succeed.
- `Failed`: Snapshot failed.

#### Example

```json
<- {"execute":"query-migrate"}
-> {"return":{"status":"completed"}}
```

## Event Notification

When some events happen, connected client will receive QMP events.

Now StratoVirt supports four events: `SHUTDOWN`, `STOP`, `RESUME`, `DEVICE_DELETED`.

## Flow control

QMP use `leak bucket` to control QMP command flow. Now QMP server accept 100 commands per second.
