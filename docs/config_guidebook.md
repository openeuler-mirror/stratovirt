# StratoVirt Guidebook

## 1. General Setting

StratoVirt can only be launched via cmdline arguments.

### 1.1 Machine Config

General configuration of machine, including
* type: The type of machine, three types of machine are available: "none", "microvm",
"q35"(x86_64 platform) and "virt" (aarch64 platform).
* dump-guest-core: Including guest memory in coredump file or not, default value is true.
* mem-share: Guest memory is sharable with other processes or not.
* accel: accelerate module, supported value `kvm`. (optional). If not set, default is KVM.
* usb: whether use usb. supported value `off`. (optional). If not set, default is off.

NB: machine type "none" is used to get the capabilities of stratovirt.

```shell
# cmdline
-machine [type=]name[,dump-guest-core=on|off,mem-share=on|off]
```

### 1.2 Cpu Number

StratoVirt supports to set the number of VCPUs(**nr_vcpus**).

This allows you to set the maximum number of VCPUs that VM will support. The maximum value is 254 and the minimum value that makes sense is 1.

By default, after booted, VM will online all CPUs you set.
Four properties are supported for `smp`.
* cpus: the number of VCPUs.
* maxcpus: the number of max VCPUs.
* sockets: the number of socket. (optional). If not set, its value depends on the value of `maxcpus`. On the arm machine, if you start a microvm, the value of socket must be one so far.
* dies: the number of dies. (optional). If not set, default is one.
* clusters: the number of clusters. (optional). If not set, default is one.
* cores: the number of core. (optional). If not set, its value depends on the value of `maxcpus`.
* threads: the number of thread. (optional). If not set, its value depends on the value of `maxcpus`.

NB: the arguments of cpu topology is used to interconnect with libvirt.

If it is configured, sockets * dies * clusters * cores * threads must be equal to maxcpus, and maxcpus should be larger than or equal to cpus.


```shell
# cmdline
-smp [cpus=]n[,maxcpus=,sockets=,dies=,clusters=,cores=,threads=]
```

### 1.3 Memory

#### 1.3.1 Memory Size

StratoVirt supports to set the size of VM's memory in cmdline.

This allows you to set the size of memory that VM will support.
You can choose `G` as unit (default unit is `M`).

Default VM memory size is 256M. The supported VM memory size is among [256M, 512G].

```shell
# cmdline
-m [size=]megs
-m 256m
-m 256
-m 1G
```

#### 1.3.2 Memory Prealloc
Memory prealloc is supported by StratoVirt, users can use the following cmdline to configure
memory prealloc.

```shell
-mem-prealloc
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

### 1.5 NUMA node
The optional NUMA node element gives the opportunity to create a virtual machine with non-uniform memory accesses.
The application of NUMA node is that one region of memory can be set as fast memory, another can be set as slow memory.

Each NUMA node is given a list of command lines option, there will be described in detail below. 
1. -object memory-backend-ram,size=2G,id=mem0,[policy=bind,host-nodes=0]
   It describes the size and id of each memory zone, the policy of binding to host memory node.
   you should choose `G` or `M` as unit for each memory zone. The host-nodes id must exist on host OS.
   The optional policies are default, preferred, bind and interleave.
2. -numa node,cpus=0-1,memdev=mem0
   It describes id and cpu set of the NUMA node, and the id belongs to which memory zone.
3. -numa dist,src=0,dst=0,val=10
   It describes the distance between source and destination. The default of source to source is 10,
   source to destination is 20. And if you choose not to set these parameters, the VM will set the default values.
   
The following command shows how to set NUMA node:

```shell
# The number of cpu must be set to be the same as numa node cpu.
-smp 8

# The memory size must be set to be the same as numa node mem.
-m 4G

-object memory-backend-ram,size=2G,id=mem0,[host-nodes=0-1,policy=bind]
-object memory-backend-ram,size=2G,id=mem1,[host-nodes=0-1,policy=bind]
-numa node,nodeid=0,cpus=0-1:4-5,memdev=mem0
-numa node,nodeid=1,cpus=2-3:6-7,memdev=mem1
[-numa dist,src=0,dst=0,val=10]
[-numa dist,src=0,dst=1,val=20]
[-numa dist,src=1,dst=0,val=20]
[-numa dist,src=1,dst=1,val=10]
```

### 1.6 Kernel and Kernel Parameters

StratoVirt supports to launch PE or bzImage (only x86_64) format linux kernel 4.19 and can also set kernel
 parameters for VM.

This allows you to give a path to linux kernel, the path can be either absolute path or relative path.

And the given kernel parameters will be actually analyzed by boot loader.

``` shell
# cmdline
-kernel /path/to/kernel \
-append "console=ttyS0 rebook=k panic=1 pci=off tsc=reliable ipv6.disable=1"
```

### 1.7 Initrd Configuration

StratoVirt supports to launch VM by a initrd (boot loader initialized RAM disk) as well.

If the path to initrd image is configured, it will be loaded to ram by boot loader.

If you want to use initrd as rootfs, `root=/dev/ram` and `rdinit=/bin/sh` must be added in Kernel Parameters.

```shell
# cmdline
-initrd /path/to/initrd
```

### 1.8 Global config

Users can set the global configuration using the -global parameter.

One property can be set:

* pcie-root-port.fast-unplug: the fast unplug feature switch, only Kata is supported.

```shell
-global pcie-root-port.fast-unplug=1
```

### 1.9 Logging

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

### 1.10 Daemonize

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

## 2. Device Configuration

For machine type "microvm", only virtio-mmio and legacy devices are supported.
Maximum number of user creatable devices is 11 on x86_64 and 160 on aarch64.

For standard VM (machine type "q35" on x86_64, and "virt" on aarch64) , virtio-pci devices are supported instead of virtio-mmio
devices. As for now pci bridges are not implemented yet, there is currently only one
root bus named pcie.0. As a result, a total of 32 pci devices can be configured.

### 2.1 iothread

Iothread is used by devices to improve io performance. StratoVirt will spawn some extra threads due to `iothread` configuration,
and these threads can be used by devices exclusively improving performance.

There is only one argument for iothread:

* id: identify io thread, can used in device configuration.

```shell
# cmdline
-object iothread,id=iothread1 -object iothread,id=iothread2
```

### 2.2 Virtio-blk

Virtio block device is a virtual block device, which process read and write requests in virtio queue from guest.

Nine properties are supported for virtio block device.

* drive_id: unique device-id in StratoVirt.
* path_on_host: the path of block device in host.
* serial_num: serial number of virtio block. (optional)
* read_only: whether virtio block device is read-only. If not set, default is false.
* direct: open block device with `O_DIRECT` mode. If not set, default is true.
* iothread: indicate which iothread will be used, if not specified the main thread will be used. (optional)
* throttling.iops-total: used to limit IO operations for block device. (optional)
* if: drive type, for block drive, it should be `none`. If not set, default is `none` (optional)
* format: the format of block image, default value `raw`. NB: currently only `raw` is supported. (optional)
If not set, default is raw.
* num-queues: the optional num-queues attribute controls the number of queues to be used for block device. If not set,
the default block queue number is 1. The max queues number supported is no more than 32.
* bootindex: the boot order of block device. (optional) If not set, the priority is lowest.
The number ranges from 0 to 255, the smaller the number, the higher the priority.
It determines the order of bootable devices which firmware will use for booting the guest OS.

For virtio-blk-pci, two more properties are required.
* bus: name of bus which to attach.
* addr: including slot number and function number. The first number represents slot number
of device and the second one represents function number of it.

If you want to boot VM with a virtio block device as rootfs, you should add `root=DEVICE_NAME_IN_GUESTOS`
 in Kernel Parameters. `DEVICE_NAME_IN_GUESTOS` will from `vda` to `vdz` in order.

```shell
# virtio mmio block device.
-drive id=drive_id,file=path_on_host[,readonly=off,direct=off,throttling.iops-total=200]
-device virtio-blk-device,drive=drive_id,id=blkid[,iothread=iothread1,serial=serial_num]
# virtio pci block device.
-drive id=drive_id,file=path_on_host[,readonly=off,direct=off,throttling.iops-total=200]
-device virtio-blk-pci,drive=drive_id,bus=pcie.0,addr=0x3.0x0,id=blk-0[,multifunction=on,iothread=iothread1,serial=serial_num,num-queues=N,bootindex=1]
```

### 2.3 Virtio-net

Virtio-net is a virtual Ethernet card in VM. It can enable the network capability of VM.

Six properties are supported for netdev.
* tap/vhost-user: the type of net device. NB: currently only tap and vhost-user is supported.
* id: unique netdev id.
* ifname: name of tap device in host.
* fd: the file descriptor of opened tap device.
* fds: file descriptors of opened tap device.
* queues: the optional queues attribute controls the number of queues to be used for either multiple queue virtio-net or
  vhost-net device. The max queues number supported is no more than 16.
NB: to configure a tap device, use either `fd` or `ifname`, if both of them are given,
the tap device would be created according to `ifname`.

Eight properties are supported for virtio-net-device or virtio-net-pci.
* id: unique net device id.
* iothread: indicate which iothread will be used, if not specified the main thread will be used.
It has no effect when vhost is set.
* netdev: netdev of net device.
* vhost: whether to run as a vhost-net device.
* vhostfd: the file descriptor of opened tap device.
* vhostfds: file descriptors of opened tap device.
* mac: set mac address in VM (optional).
* mq: the optional mq attribute enable device multiple queue feature.

Two more properties are supported for virtio pci net device.
* bus: name of bus which to attach.
* addr: including slot number and function number. The first number represents slot number
of device and the second one represents function number of it. For virtio pci net device, it
is a single function device, the function number should be set to zero.

```shell
# virtio mmio net device
-netdev tap,id=netdevid,ifname=host_dev_name
-device virtio-net-device,netdev=netdevid,id=netid[,iothread=iothread1,mac=12:34:56:78:9A:BC]
# virtio pci net device
-netdev tap,id=netdevid,ifname=host_dev_name[,queues=N]
-device virtio-net-pci,netdev=netdevid,id=netid,bus=pcie.0,addr=0x2.0x0[,multifunction=on,iothread=iothread1,mac=12:34:56:78:9A:BC,mq=on]
```

StratoVirt also supports vhost-net to get a higher performance in network. It can be set by
giving `vhost` property, and one more property is supported for vhost-net device.

* vhostfd: fd for vhost-net device, it could be configured when `vhost=on`. If this argument is not
given when `vhost=on`, StratoVirt gets it by opening "/dev/vhost-net" automatically.

```shell
# virtio mmio net device
-netdev tap,id=netdevid,ifname=host_dev_name,vhost=on[,vhostfd=2]
-device virtio-net-device,netdev=netdevid,id=netid[,iothread=iothread1,mac=12:34:56:78:9A:BC]
# virtio pci net device
-netdev tap,id=netdevid,ifname=host_dev_name,vhost=on[,vhostfd=2,queues=N]
-device virtio-net-pci,netdev=netdevid,id=netid,bus=pcie.0,addr=0x2.0x0[,multifunction=on,iothread=iothread1,mac=12:34:56:78:9A:BC,mq=on]
```

StratoVirt also supports vhost-user net to get a higher performance by ovs-dpdk. Currently, only
virtio pci net device support vhost-user net. It should open sharing memory('-mem-share=on') and
hugepages('-mem-path ...' ) when using vhost-user net.

```shell
# virtio pci net device
-chardev socket,id=chardevid,path=socket_path
-netdev vhost-user,id=netdevid,chardev=chardevid[,queues=N]
-device virtio-net-pci,netdev=netdevid,id=netid,mac=12:34:56:78:9A:BC,bus=pci.0,addr=0x2.0x0[,mq=on]
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
... -netdev tap,id=netdevid,ifname=tap0 ...

# In guest
$ ip link set eth0 up
$ ip addr add 1.1.1.2/24 dev eth0

# Now network is reachable
$ ping 1.1.1.1
```

note: If you want to use multiple queues, create a tap device as follows:
```shell
# In host
$ brctl addbr qbr0
$ ip tuntap add tap1 mode tap multi_queue
$ brctl addif qbr0 tap1
$ ifconfig qbr0 up; ifconfig tap1 up
$ ifconfig qbr0 1.1.1.1
```

*How to create port by ovs-dpdk?*

```shell
# Start open vSwitch daemons
$ ovs-ctl start
# Initialize database
$ ovs-vsctl init
# Dpdk init
$ ovs-vsctl set Open_vSwitch . other_config:dpdk-init=true
# Set up dpdk lcore mask
$ ovs-vsctl set Open_vSwitch . other_config:dpdk-lcore-mask=0xf
# Set up hugepages for dpdk-socket-mem (2G)
$ ovs-vsctl set Open_vSwitch . other_config:dpdk-socket-mem=1024
# Set up PMD(Pull Mode Driver) cpu mask
$ ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=0xf
# Add bridge
$ ovs-vsctl add-br ovs_br -- set bridge ovs_br datapath_type=netdev
# Add port
$ ovs-vsctl add-port ovs_br port1 -- set Interface port1 type=dpdkvhostuser
$ ovs-vsctl add-port ovs_br port2 -- set Interface port2 type=dpdkvhostuser
# Set num of rxq/txq
$ ovs-vsctl set Interface port1 options:n_rxq=num,n_txq=num
$ ovs-vsctl set Interface port2 options:n_rxq=num,n_txq=num
```

### 2.4 Virtio-console

Virtio console is a general-purpose serial device for data transfer between the guest and host.
Character devices at /dev/hvc0 to /dev/hvc7 in guest will be created once setting it.
To set the virtio console, chardev for redirection will be required. See [section 2.12 Chardev](#212-chardev) for details.

Two properties can be set for virtconsole.
* id: unique device-id.
* chardev: char device of virtio console device.

For virtio-serial-pci, two more properties are required.
* bus: bus number of virtio console.
* addr: including slot number and function number. The first number represents slot number
of device and the second one represents function number of it.

```shell
# virtio mmio device
-device virtio-serial-device[,id=virtio-serial0]
-chardev socket,path=socket_path,id=virtioconsole1,server,nowait
-device virtconsole,chardev=virtioconsole1,id=console_id

# virtio pci device
-device virtio-serial-pci,bus=pcie.0,addr=0x1.0x0,id=virtio-serial0[,multifunction=on]
-chardev socket,path=socket_path,id=virtioconsole1,server,nowait
-device virtconsole,chardev=virtioconsole1,id=console_id
```
NB:
Currently, only one virtio console device is supported in standard machine.

### 2.5 Virtio-vsock

Virtio vsock is a host/guest communication device like virtio console, but it has higher performance.

If you want use it, need:

* Host kernel config: CONFIG_VHOST_VSOCK=m
* Guest kernel config: CONFIG_VIRTIO_VSOCKETS=y

And `modprobe vhost_vsock` in the host.

Three properties can be set for virtio vsock device.

* vsock_id: unique device-id in StratoVirt.
* guest_cid: a unique Context-ID in host to each guest, it should satisfy `3<=guest_cid<u32:MAX`.
* vhostfd: fd of vsock device. (optional).

For vhost-vsock-pci, two more properties are required.
* bus: name of bus which to attach.
* addr: including slot number and function number. the first number represents slot number
of device and the second one represents function number of it.

```shell
# virtio mmio device.
-device vhost-vsock-device,id=vsock_id,guest-cid=3

# virtio pci device.
-device vhost-vsock-pci,id=vsock_id,guest-cid=3,bus=pcie.0,addr=0x1.0x0[,multifunction=on]
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

In StratoVirt, there are two ways to set serial and bind it with host's character device.
NB: We can only set *one* serial.

To use the first method, chardev for redirection will be required. See [section 2.12 Chardev](#212-chardev) for details.
```shell
# add a chardev and redirect the serial port to chardev
-chardev backend,id=chardev_id[,path=path,server,nowait]
-serial chardev:chardev_id
```

Or you can simply use `-serial dev` to bind serial with character device.
```shell
# simplifed redirect methods
-serial stdio
-serial pty
-serial socket,path=socket_path,server,nowait
-serial file,path=file_path
```

### 2.7 Virtio-balloon
Balloon is a virtio device, it offers a flex memory mechanism for VM.

Only one property is supported for virtio-balloon.
* deflate_on_oom: whether to deflate balloon when there is no enough memory in guest.
This feature can prevent OOM occur in guest.

For virtio-balloon-pci, two more properties are required.
* bus: name of bus which to attach.
* addr: including slot number and function number. the first number represents slot number
of device and the second one represents function number of it.

```shell
# virtio mmio balloon device
-device virtio-balloon-device,deflate-on-oom=true
# virtio pci balloon device
-device virtio-balloon-pci,bus=pcie.0,addr=0x4.0x0,deflate-on-oom=true,id=balloon-0[,multifunction=on]
```

### 2.8 Virtio-rng
Virtio rng is a paravirtualized random number generator device, it provides a hardware rng device to the guest.

If you want to use it, need:

* Guest kernel config: CONFIG_HW_RANDOM=y CONFIG_HW_RANDOM_VIA=y CONFIG_HW_RANDOM_VIRTIO=y

Five properties are supported for virtio-rng.
* filename: the path of character device generates with random number in host.
* period: period of timer to limit the rate of char stream. unit: millisecond.
* max-bytes: the max bytes that the character device generates with a random number in the 'period' of time.

For virtio-rng-pci, two more properties are required.
* bus: name of bus which to attach.
* addr: including slot number and function number. the first number represents slot number
of device and the second one represents function number of it. As virtio pci rng device is a
single function device, the function number should be set to zero.

 NB:
 * The limited rate will be transformed to bytes/sec. For instance: if period=100, max-bytes=100; the final
 result is that the max number of bytes generated by rng device is 1000.
 * Limited rate should between 64(include) and 1000000000(not include). In other words:
 64 <= max-bytes/period < 1000000000.

```shell
# virtio mmio rng device
-object rng-random,id=objrng0,filename=/path/to/random_file
-device virtio-rng-device,rng=objrng0,max-bytes=1234,period=1000
# virtio pci rng device
-object rng-random,id=objrng0,filename=/path/to/random_file
-device virtio-rng-pci,rng=objrng0,max-bytes=1234,period=1000,bus=pcie.0,addr=0x1.0x0,id=rng-id[,multifunction=on]
```

### 2.9 PCIe root port
A PCI Express Port on a Root Complex that maps a portion of a Hierarchy through an associated virtual PCI-PCI
Bridge.

Four parameters are supported for pcie root port.
* port: port number of root port.
* bus: name of bus which to attach.
* addr: including slot number and function number.
* id: the name of secondary bus.
* chassis: the number of chassis. Interconnect with libvirt only.(optional).
* multifunction: whether to open multi function for pcie root port.(optional).
If not set, default value is false.

```shell
-device pcie-root-port,port=0x1,addr=0x1,bus=pcie.0,id=pcie.1[,multifunction=on]
```

**The slot number of the device attached to the root port must be 0**

### 2.10 PFlash
PFlash is a virtualized flash device, it provides code storage and data storage for EDK2 during standard boot.

Usually, two PFlash devices are added to the main board. The first PFlash device is used to store binary code for EDK2 firmware, so this device is usually read-only. The second device is used to store configuration information related to standard boot, so this device is usually readable and writable. You can check out the [boot](./boot.md) to learn how to get the EDK2 firmware files.

Four properties can be set for PFlash device.

* file: the path of PFlash device in host.
* readonly: whether PFlash device is read-only or not. Default option is false. Note that the PFlash device which stores binary code should be read-only, the PFlash device which stores boot information should be readable and writable.
* unit: unique device-id for PFlash devices. It should satisfy `0<=unit<=1`. Note that the unit of the PFlash device which stores binary code should be 0, the unit of the PFlash device which stores boot information should be 1.
* if: the type of drive, in this case it is 'pflash'.

```shell
# cmdline
-drive file=/path/to/code_storage_file,if=pflash,unit=0[,readonly=true]
-drive file=/path/to/data_storage_file,if=pflash,unit=1,
```

### 2.11 VFIO
The VFIO driver is an IOMMU/device agnostic framework for exposing direct access to userspace, in a secure,
IOMMU protected environment. Virtual machine often makes use of direct device access when configured for the highest
possible I/O performance.

Four properties are supported for VFIO device
* host: PCI device info in the system that contains domain, bus number, slot number and function number.
* id: VFIO device name.
* bus: bus number of VFIO device.
* addr: including slot number and function number.

```shell
-device vfio-pci,host=0000:1a:00.3,id=net,bus=pcie.0,addr=0x03.0x0[,multifunction=on]
```

Note: the kernel must contain physical device drivers, otherwise it cannot be loaded normally.

See [VFIO](./vfio.md) for more details.

### 2.12 Chardev
The type of chardev backend could be: stdio, pty, socket and file(output only).

Five properties can be set for chardev.

* id: unique chardev-id.
* backend: the type of redirect method.
* path: the path of backend in the host. This argument is only required for socket-type chardev and file-type chardev.
* server: run as a server. This argument is only required for socket-type chardev.
* nowait: do not wait for connection. This argument is only required for socket-type chardev.

```shell
# redirect methods
-chardev stdio,id=chardev_id
-chardev pty,id=chardev_id
-chardev socket,id=chardev_id,path=socket_path[,server,nowait]
-chardev file,id=chardev_id,path=file_path
```

## 3. Trace

Users can specify the configuration file which lists events to trace.

One property can be set:

* events: file lists events to trace.

```shell
-trace events=<file>
```

## 4. Seccomp

StratoVirt use [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html) to limit the syscalls
in StratoVirt process by default. It will make a slight influence on performance to StratoVirt.
* x86_64

| Number of Syscalls | GNU Toolchain | MUSL Toolchain |
| :----------------: | :-----------: | :------------: |
|      microvm       |      47       |       46       |
|        q35         |      53       |       54       |

* aarch64

| Number of Syscalls | GNU Toolchain | MUSL Toolchain |
| :----------------: | :-----------: | :------------: |
|      microvm       |      45       |       45       |
|        virt        |      51       |       50       |

If you want to disable seccomp, you can run StratoVirt with `-disable-seccomp`.
```shell
# cmdline
-disable-seccomp
```

## 5. Snapshot and Restore

StratoVirt supports to take a snapshot of a paused VM as VM template. This template can be used to warm start a new VM. Warm start skips the kernel boot stage and userspace initialization stage to boot VM in a very short time.

### 5.1 Restore from VM template

Restore from VM template with below command:
```shell
$ ./stratovirt \
    -machine microvm \
    -kernel path/to/vmlinux.bin \
    -append "console=ttyS0 pci=off reboot=k quiet panic=1 root=/dev/vda" \
    -drive file=path/to/rootfs,id=rootfs,readonly=off,direct=off \
    -device virtio-blk-device,drive=rootfs,id=rootfs \
    -qmp unix:path/to/socket,server,nowait \
    -serial stdio \
    -incoming file:path/to/template
```

* incoming: the path of the template.

See [Snapshot and Restore](./snapshot.md) for details.

## 6. Ozone
Ozone is a lightweight secure sandbox for StratoVirt, it provides secure environment for StratoVirt
by limiting resources of StratoVirt using 'namespace'. Please run ozone with root permission.

### 6.1 Usage
Ozone can be launched by the following commands:
```shell
$ ./ozone \
    -name stratovirt_ozone \
    -exec_file /path/to/stratovirt \
    -gid 100 \
    -uid 100 \
    -capability [CAP_*] \
    -netns /path/to/network_name_space \
    -source /path/to/source_files \
    -numa numa_node \
    -cgroup <controller1>=<value1>,<controller2>=<value2> \
    [-clean-resource] \
    -- \
    <arguments for launching stratovirt>
```

About the arguments:
* `name` : the name of ozone, it should be unique.
* `exec_file` : path to the StratoVirt binary file. NB: it should be a statically linked binary file.
* `uid` : the user id.
* `gid` : the group id.
* `capability` : set the ozone environment capabilities. If not set, forbid any capability.
* `netns` : path to a existed network namespace.
* `source` : path to the source file, such as `rootfs` and `vmlinux`.
* `clean-resource` : a flag to clean resource.
* `numa` : numa node, this argument must be configured if `cpuset.cpus` is set.
* `cgroup` : set cgroup controller value. supported controller: `cpuset.cpus` and `memory.limit_in_bytes`.
* `--` : these two dashes are used to splite args, the args followed are used to launched StratoVirt.

### 6.2 Example
As ozone uses a directory to mount as a root directory, after ozone is launched, the directory "/srv/zozne/{exec_file}/{name}" will be created. (Where, `exec_file` is the executable binary file, usually it is `stratovirt`, while `name` is the name of ozone, it is given by users, but the length of it should be no more than 255 bytes.) In order to run ozone normally, please make sure that the directory "/srv/zozne/{exec_file}/{name}" does not exists before launching ozone.

On top of that, the path-related arguments are different. They are all in the current(`./`) directory.

For net name space, it can be created by the following command with name "mynet":
```shell
$ sudo ip netns add mynet
```
After creating, there is a file named `mynet` in `/var/run/netns`.

The following example illustrates how to config a ozone under netns `mynet`, running on cpu "4-5" with memory limitation 1000000 bytes.

```shell
$ ./ozone \
    -name stratovirt_ozone \
    -exec_file /path/to/stratovirt \
    -gid 100 \
    -uid 100 \
    -capability CAP_CHOWN \
    -netns /var/run/netns/mynet \
    -source /path/to/vmlinux.bin /path/to/rootfs \
    -numa 0 \
    -cgroup cpuset.cpus=4-5 memory.limit_in_bytes=1000000 \
    -- \
    -kernel ./vmlinux.bin \
    -append console=ttyS0 root=/dev/vda reboot=k panic=1 rw \
    -drive file=./rootfs,id=rootfs,readonly=off \
    -device virtio-blk-device,drive=rootfs,id=rootfs \
    -qmp unix:./stratovirt.socket,server,nowait \
    -serial stdio
```

Once the process of StratoVirt exits, the following command can be used to clean the environment.
```shell
$ ./ozone \
    -name stratovirt_ozone \
    -exec_file /path/to/stratovirt \
    -gid 100 \
    -uid 100 \
    -netns /path/to/network_name_space \
    -source /path/to/vmlinux.bin /path/to/rootfs \
    -clean-resource
```

## 7. Libvirt
Libvirt launches StratoVirt by creating cmdlines. But some of these commands
such as: cpu, overcommit, uuid, no-user-config, nodefaults, sandbox, msg, rtc, no-shutdown,
nographic, realtime, display, usb, mem-prealloc and boot, are not supported by StratoVirt.
To launch StratoVirt from libvirt successfully, StratoVirt needs to put these arguments into
white list. However, these cmdlines never function.

Apart from the above commands, some arguments are playing the same roles. Like 'format'
and 'bootindex' for virtio-blk; 'chassis' for pcie-root-port; 'sockets',
'cores' and 'threads' for smp; 'accel' and 'usb' for machine; "format" for pflash device.
