# Snapshot and Restore

StratoVirt supports to take a snapshot of a paused VM as VM template. This template can be used to warm start a new VM. Warm start skips the kernel boot stage and userspace initialization stage to boot VM in a very short time.

## Create VM template

First, we create a StratoVirt VM:
```shell
$ ./stratovirt \
    -machine microvm \
    -kernel path/to/vmlinux.bin \
    -append "console=ttyS0 pci=off reboot=k quiet panic=1 root=/dev/vda" \
    -drive file=path/to/rootfs,id=rootfs,readonly=off,direct=off \
    -device virtio-blk-device,drive=rootfs,id=rootfs \
    -qmp unix:path/to/socket,server,nowait \
    -serial stdio
```

After the VM boot up, pause the VM with QMP:
```shell
$ ncat -U path/to/socket
{"QMP":{"version":{"StratoVirt":{"micro":1,"minor":0,"major":0},"package":""},"capabilities":[]}}
{"execute":"stop"}
{"event":"STOP","data":{},"timestamp":{"seconds":1583908726,"microseconds":162739}}
{"return":{}}
```

When VM is in paused state, is's safe to take a snapshot of the VM into the specified directory with QMP.
```shell
$ ncat -U path/to/socket
{"QMP":{"version":{"StratoVirt":{"micro":1,"minor":0,"major":0},"package":""},"capabilities":[]}}
{"execute":"migrate", "arguments":{"uri":"file:path/to/template"}}
{"return":{}}
```

Two files will be created in given directory on the system.
```shell
$ ls path/to/template
memory  state
```
File `state` contains the device state data of VM devices. File `memory` contains guest memory data of VM memory. The file size is explained by the size of VM guest memory.

## Restore from VM template

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

The device configuration must be the same with template VM. Its cpu number, guest memory size, device number and type can be changed. For drive file, only support previous file or its backups. After that, the VM is created from template successfully.

## Snapshot state check

Use QMP command `query-migrate` to check snapshot state:
```shell
$ ncat -U path/to/socket
{"QMP":{"version":{"StratoVirt":{"micro":1,"minor":0,"major":0},"package":""},"capabilities":[]}}
{"execute":"query-migrate"}
{"return":{"status":"completed"}}
```

Now there are 5 states during snapshot:
- `None`: Resource is not prepared all.
- `Setup`: Resource is setup, ready to do snapshot.
- `Active`: In snapshot.
- `Completed`: Snapshot succeed.
- `Failed`: Snapshot failed.

## Limitations

Snapshot-restore support machine type:
- `microvm`
- `q35` (on x86_64 platform)
- `virt` (on aarch64 platform)

Some devices and feature don't support to be snapshot yet:
- `vhost-net`
- `vfio` devices
- `balloon`
- `hugepage`,`mem-shared`,`backend file of memory`
- `pmu`
- `sve`
- `gic-version=2`

Some device attributes can't be changed:
- `virtio-net`: mac
- `virtio-blk`: file(only ordinary file or copy file), serial_num
- `device`: bus, addr
- `smp`
- `m`

For machine type `microvm`, if use `hot-replace` before snapshot, add newly replaced device to restore command.
