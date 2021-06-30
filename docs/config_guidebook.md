# StratoVirt Guidebook

## 1. General Setting

StratoVirt can only be launched via cmdline arguments.

### 1.1 Machine Config

General configuration of machine, including
* type: The machine type of machine, StratoVirt only support MicroVm yet.
* dump-guest-core: Including guest memory in coredump file or not, default value is true.
* mem-share: Guest memory is sharable with other processes or not.

This feature is closed by default. There are two ways to open it:

```shell
# cmdline
-machine [type=]name[,dump-guest-core=on|off][,mem-share=on|off]
```

### 1.2 Cpu Number

StratoVirt supports to set the number of VCPUs(**nr_vcpus**).

This allows you to set the maximum number of VCPUs that VM will support. The maximum value is 254 and the minimum value that makes sense is 1.

By default, after booted, VM will online all CPUs you set.

```shell
# cmdline
-smp [cpus=]n
```

### 1.3 Memory Size

StratoVirt supports to set the size of VM's memory in cmdline.

This allows you to set the size of memory that VM will support.
You can choose `M` or `G` as unit (default unit is `Byte`).

Default VM memory size is 256M. The supported VM memory size is among [256M, 512G].

```shell
# cmdline
-m [size=]megs
-m 805306368
-m 256M
-m 1G
```

### 1.4 Backend file of memory

StratoVirt supports to set the backend file of VM's memory.

This allows you to give a path to backend-file, which can be either a directory or a file.
The path has to be absolute path.

```shell
# cmdline
-mem-path /path/to/file
-mem-path /path/to/dir
```

### 1.4.1 hugepages

Memory backend file can be used to let guest use hugetlbfs on host.
The following steps show how to use hugepages:

```shell
# mount hugetlbfs on a directory on host
$ mount -t hugetlbfs hugetlbfs /path/to/hugepages

# set the count of hugepages
$ sysctl vm.nr_hugepages=1024

# check hugepage size and count on host
$ cat /proc/meminfo

# run StratoVirt with backend-file
... -mem-path /path/to/hugepages ...
```

### 1.5 Kernel and Kernel Parameters

StratoVirt supports to launch PE or bzImage (only x86_64) format linux kernel 4.19 and can also set kernel
 parameters for VM.

This allows you to give a path to linux kernel, the path can be either absolute path or relative path.

And the given kernel parameters will be actually analyzed by boot loader.

``` shell
# cmdline
-kernel /path/to/kernel \
-append console=ttyS0 rebook=k panic=1 pci=off tsc=reliable ipv6.disable=1
```

### 1.6 Initrd Configuration

StratoVirt supports to launch VM by a initrd (boot loader initialized RAM disk) as well.

If the path to initrd image is configured, it will be loaded to ram by boot loader.

If you want to use initrd as rootfs, `root=/dev/ram` and `rdinit=/bin/sh` must be added in Kernel Parameters.

```shell
# cmdline
-initrd /path/to/initrd
```

## 2. Device Configuration

StratoVirt supports to deploy one kind of legacy device and four kinds of virtio-mmio devices.

The max number of devices is 16 on x86_64 platform and 32 on aarch64 platform.

### 2.1 iothread

Iothread is used by devices to improve io performance. StratoVirt will spawn some extra threads du to `iothread` configuration, 
and these threads can be used by devices exclusively improving performance.

There is only one argument for iothread:

* id: identify io thread, can used in device configuration.

```shell
# cmdline
-iothread id=iothread1 -iothread id=iothread2
```

### 2.2 Virtio-blk

Virtio block device is a virtual block device, which process read and write requests in virtio queue from guest.

Seven properties are supported for virtio block device.

* drive_id: unique device-id in StratoVirt
* path_on_host: the path of block device in host
* serial_num: serial number of virtio block (optional)
* read_only: whether virtio block device is read-only or not
* direct: open block device with `O_DIRECT` mode or not
* iothread: indicate which iothread will be used, if not specified the main thread will be used
* iops: used to limit IO operations for block device

If you want to boot VM with a virtio block device as rootfs, you should add `root=DEVICE_NAME_IN_GUESTOS`
 in Kernel Parameters. `DEVICE_NAME_IN_GUESTOS` will from `vda` to `vdz` in order.

```shell
# virtio mmio block device.
-drive id=drive_id,file=path_on_host,serial=serial_num,readonly=off,direct=off
-device virtio-blk-device,drive=drive_id[,iothread=iothread1,iops=200]
# virtio pci block device.
-drive id=drive_id,file=path_on_host,serial=serial_num,readonly=off,direct=off
-device virtio-blk-pci,drive=drive_id,bus=pcie.0,addr=0x3.0x0[,iothread=iothread1,iops=200]

```

### 2.3 Virtio-net

Virtio-net is a virtual Ethernet card in VM. It can enable the network capability of VM.

Four properties are supported for virtio net device.

* netid: unique device-id in StratoVirt
* host_dev_name: name of tap device in host
* mac: set mac address in VM (optional)
* iothread: indicate which iothread will be used, if not specified the main thread will be used. 
It only affects on virito-net, not vhost-net.

```shell
# virtio mmio net device
-netdev id=host_dev_name[,mac=12:34:56:78:9A:BC]
-device virtio-net-device,netdev=host_dev_name,id=netid[,iothread=iothread1]
# virtio pci net device
-netdev id=host_dev_name[,mac=12:34:56:78:9A:BC]
-device virtio-net-pci,netdev=host_dev_name,id=netid,bus=pcie.0,addr=0x2.0x0[,iothread=iothread1]
```

StratoVirt also supports vhost-net to get a higher performance in network.

It can be set by given `vhost` property.

```shell
# virtio mmio net device
-netdev id=host_dev_name,vhost=on[,mac=12:34:56:78:9A:BC]
-device virtio-net-device,netdev=host_dev_name,id=netid[,iothread=iothread1]
# virtio pci net device
-netdev id=host_dev_name,vhost=on[,mac=12:34:56:78:9A:BC]
-device virtio-net-pci,netdev=host_dev_name,id=netid,bus=pcie.0,addr=0x2.0x0[,iothread=iothread1]
```

*How to set a tap device?*

```shell
# In host
$ brctl addbr qbr0
$ ip tuntap add tap0 mode tap
$ brctl addif qbr0 tap0
$ ifconfig qbr0 up; ifconfig tap0 up
$ ifconfig qbr0 1.1.1.1

# Run StratoVirt
... -netdev id=net-0,netdev=tap0 ...

# In guest
$ ip link set eth0 up
$ ip addr add 1.1.1.2/24 dev eth0

# Now network is reachable
$ ping 1.1.1.1
```

### 2.4 Virtio-console

Virtio console is a general-purpose serial device for data transfer between the guest and host.
Character devices at /dev/hvc0 to /dev/hvc7 in guest will be created once setting it.
In host, it will be presented as a UnixSocket.

Two properties can be set for virtio console device.

* console_id: unique device-id in StratoVirt
* socket_path: the path of virtio console socket in the host

```shell
# shell
-chardev id=console_id,path=socket_path
```

### 2.5 Virtio-vsock

Virtio vsock is a host/guest communication device like virtio console, but it has higher performance.

If you want use it, need:

* Host kernel config: CONFIG_VHOST_VSOCK=m
* Guest kernel config: CONFIG_VIRTIO_VSOCKETS=y

And `modprobe vhost_vsock` in the host.

 Two properties can be set for virtio vsock device.

* vsock_id: unique device-id in StratoVirt
* guest_cid: a unique Context-ID in host to each guest, it should satisfy `3<=guest_cid<u32:MAX`

```shell
# virtio mmio device.
-device vhost-vsock-device,id=vsock_id,guest-cid=3

# virtio pci device.
-device vhost-vsock-pci,id=vsock_id,guest-cid=3,bus=pcie.0,addr=0x1.0x0
```

*You can only set one virtio vsock device for one VM.*

*You can also use [`nc-vsock`](https://github.com/stefanha/nc-vsock) to test virtio-vsock.*

```shell
# In guest
$ nc-vsock -l port_num

# In host
$ nc-vsock guest_cid port_num
```

### 2.6 Serial

Serial is a legacy device for VM, it is a communication interface which bridges the guest and host.

Commonly, we use serial as ttyS0 to output console message in StratoVirt.

In StratoVirt, we can set *one* serial and bind it with host's stdio.

There is only one argument for serial device:

* stdio: bind serial with stdio

```shell
# cmdline
-serial stdio
```

### 2.7 Virtio_Balloon
Balloon is a virtio device, it offers a flex memory mechanism for VM.

Only one property is supported for virtio-balloon.
* deflate_on_oom: whether to deflate balloon when there is no enough memory in guest.
This feature can prevent OOM occur in guest.

```shell
# virtio mmio balloon device
-device virtio-balloon-device,deflate-on-oom=true
# virtio pci balloon device
-device virtio-balloon-pci,bus=pcie.0,addr=0x4.0x0,deflate-on-oom=true
```

### 2.8 Virtio-rng
Virtio rng is a paravirtualized random number generator device, it provides a hardware rng device to the guest.

If you want use it, need:

* Guest kernel config: CONFIG_HW_RANDOM=y CONFIG_HW_RANDOM_VIA=y CONFIG_HW_RANDOM_VIRTIO=y

Only two property is supported for virtio-rng.
* random_file: the path of character device generates with random number in host
* bytes_per_sec: the number of bytes that the character device generates with a random number per second,
it should satisfy `64<=bytes_per_sec<1000000000`

```shell
# cmdline
-rng random_file=/path/to/random_file[,bytes_per_sec=1000000]
```

### 2.9 PCIe root port
A PCI Express Port on a Root Complex that maps a portion of a Hierarchy through an associated virtual PCI-PCI
Bridge.

Four parameters are supported for pcie root port.
* port: port number of root port.
* bus: bus number of root port.
* addr: including slot number and function number.
* id: the name of secondary bus.

```shell
-device pcie-root-port,port=0x1,addr=0x1.0x2,bus=pcie.0,id=pcie.1
```

### 2.10 PFlash
PFlash is a virtualized flash device, it provides code storage and data storage for EDK2 during standard boot.

Usually, two PFlash devices are added to the main board. The first PFlash device is used to store binary code for EDK2 firmware, so this device is usually read-only. The second device is used to store configuration information related to standard boot, so this device is usually readable and writable.

Three properties can be set for PFlash device.

* file: the path of PFlash device in host
* readonly: whether PFlash device is read-only or not. Default option is false. Note that the PFlash device which stores binary code should be read-only, the PFlash device which stores boot information should be readable and writable
* unit: unique device-id for PFlash devices. It should satisfy `0<=unit<=1`. Note that the unit of the PFlash device which stores binary code should be 0, the unit of the PFlash device which stores boot information should be 1

```shell
# cmdline
-pflash file=/path/to/code_storage_file,unit=0[,readonly=true]
-pflash file=/path/to/data_storage_file,unit=1
```

## 3. StratoVirt Management

StratoVirt controls VM's lifecycle and external api interface with [QMP](https://wiki.qemu.org/Documentation/QMP)
 in current version.

### 3.1 qmp Creation

When running StratoVirt, you must create qmp in cmdline arguments as a management interface.

StratoVirt supports UnixSocket-type qmp, you can set it by:

```shell
# cmdline
-qmp unix:/path/to/api/socket
```

### 3.2 qmp Connection

After StratoVirt started, you can connect to StratoVirt's qmp and manage it by QMP.

Several steps to connect qmp are showed as following:

```shell
# Start with UnixSocket
$ ncat -U /path/to/api/socket
```

Once connection is built, you will receive a `greeting` message from StratoVirt.

```json
{"QMP":{"version":{"StratoVirt":{"micro":1,"minor":0,"major":0},"package":""},"capabilities":[]}}
```

Now you can input QMP command to control StratoVirt.

### 3.3 Lifecycle Management

With QMP, you can control VM's lifecycle by command `stop`, `cont`, `quit` and check VM state by
 `query-status`.

#### 3.3.1 Command `stop`

Stop all guest VCPUs execution.

```json
<- {"execute":"stop"}
-> {"event":"STOP","data":{},"timestamp":{"seconds":1583908726,"microseconds":162739}}
-> {"return":{}}
```

#### 3.3.2 Command `cont`

Resume all guest VCPUs execution.

```json
<- {"execute":"cont"}
-> {"event":"RESUME","data":{},"timestamp":{"seconds":1583908853,"microseconds":411394}}
-> {"return":{}}
```

#### 3.3.3 Command `quit`

This command will cause StratoVirt process to exit gracefully.

```json
<- {"execute":"quit"}
-> {"return":{}}
-> {"event":"SHUTDOWN","data":{"guest":false,"reason":"host-qmp-quit"},"timestamp":{"ds":1590563776,"microseconds":519808}}
```

#### 3.3.4 Command `query-status`

Query the running status of all VCPUs.

```json
<- { "execute": "query-status" }
-> { "return": { "running": true,"singlestep": false,"status": "running" } }
```

#### 3.3.5 Command `getfd`

Receive a file descriptor via SCM rights and assign it a name.

```json
<- { "execute": "getfd", "arguments": { "fdname": "fd1" } }
-> { "return": {} }
```

### 3.4 Device Hot-replace

StratoVirt supports hot-replacing virtio-blk and virtio-net devices with QMP.

#### 3.4.1 Hot-replace Virtio-blk

```json
<- {"execute": "blockdev-add", "arguments": {"node-name": "drive-0", "file": {"driver": "file", "filename": "/path/to/block"}, "cache": {"direct": true}, "read-only": false}}
-> {"return": {}}
<- {"execute": "device_add", "arguments": {"id": "drive-0", "driver": "virtio-blk-mmio", "addr": "0x1"}}
-> {"return": {}}
```

**`node-name` in `blockdev-add` should be same as `id` in `device_add`.**

For `addr`, it start at `0x0` mapping in guest with `vda` on x86_64 platform, and start at `0x1`
 mapping in guest with `vdb` on aarch64 platform.

You can also remove the replaceable block device by:

```json
<- {"execute": "device_del", "arguments": {"id": "drive-0"}}
-> {"event": "DEVICE_DELETED", "data":{"device": "drive-0", "path": "/path/to/block"}}
-> {"return": {}}
```

#### 3.4.2 Hot-replace Virtio-net

```json
<- {"execute":"netdev_add", "arguments":{"id":"net-0", "ifname":"tap0"}}
-> {"return": {}}
<- {"execute":"device_add", "arguments":{"id":"net-0", "driver":"virtio-net-mmio", "addr":"0x0"}}
-> {"return": {}}
```

**`id` in `netdev_add` should be same as `id` in `device_add`.**

For `addr`, it start at `0x0` mapping in guest with `eth0`.

You can also remove the replaceable net device by:

```json
<- {"execute": "device_del", "arguments": {"id": "net-0"}}
-> {"event":"DEVICE_DELETED","data":{"device":"net-0","path":"net-0"},"timestamp":{"seconds":1614310541,"microseconds":554250}}
-> {"return": {}}
```

### 3.5 Balloon

With QMP command you can set target memory size of guest and get memory size of guest.
#### 3.5.1 command 'balloon'
Set target memory size of guest.
```json
<- { "execute": "balloon", "arguments": { "value": 2147483648 } }
-> {"return":{}}
```
#### 3.5.2 command 'query-balloon'
Get memory size of guest.
```json
<- { "execute": "query-balloon" }
-> {"return":{"actual":2147483648}}
```

### 3.6 Event Notification

When some events happen, connected client will receive QMP events.

Now StratoVirt supports four events: `SHUTDOWN`, `STOP`, `RESUME`, `DEVICE_DELETED`.

### 3.7 Flow control

QMP use `leak bucket` to control QMP command flow. Now QMP server accept 100 commands per second.

## 4. Other Features

### 4.1 Daemonize

StratoVirt supports to run as a daemon.

```shell
# cmdline
-daemonize
```

**When run StratoVirt as a daemon, you are not allowed to bind serial with stdio or output log to stdio.**

And you can also restore StratoVirt's **pid number** to a file by:

```shell
# cmdline
-pidfile /path/to/pidfile
```

### 4.2 Seccomp

StratoVirt use [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html) to limit the syscalls
in StratoVirt process by default. StratoVirt use only 40 syscalls in x86_64 (39 syscalls in aarch64) after running.  
It will make a slight influence on performance to StratoVirt. If you want to disable seccomp, you can
run StratoVirt with `-disable-seccomp`.

```shell
# cmdline
-disable-seccomp
```

### 4.3 Logging

StratoVirt supports to output log to stderr and log file.

You can enable StratoVirt's logging by:

```shell
# Output log to stderr
-D
# Output log to log file
-D /path/to/log/file
```

StratoVirt's log-level depends on env `STRATOVIRT_LOG_LEVEL`.
StratoVirt supports five log-levels: `trace`, `debug`, `info`, `warn`, `error`. The default level is `error`.
