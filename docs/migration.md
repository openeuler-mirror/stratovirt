# Live migration

## Introduction

Virtual machine live migration is the key feature provided by StratoVirt. It needs to execute virtual machine migration
when any of the following happens:
- Server overload: when a source server is overloaded, a set of the VMs from this server is migrated to an underloaded
   server using VM migration technique.
- Server maintenance: if there is a need for server maintenance, VMs from the source server are migrated to another server.
- Server fault: whenever there is server fault, VMs are migrated from the faulty server to the target server.

## Transports

The migration stream can be passed over any transport as following:
- TCP mode migration: using tcp sockets to do the migration.
- UNIX mode migration: using unix sockets to do the migration.

Note: UNIX mode only supports migrate two VMs on the same host OS. TCP mode supports migrate both on the same or
   different host OS.

## Migration

Launch the source VM:
```shell
./stratovirt \
    -machine q35 \
    -kernel ./vmlinux.bin \
    -append "console=ttyS0 pci=off reboot=k quiet panic=1 root=/dev/vda" \
    -drive file=path/to/rootfs,id=rootfs,readonly=off,direct=off \
    -device virtio-blk-pci,drive=rootfs,id=rootfs,bus=pcie.0,addr=0 \
    -qmp unix:path/to/socket1,server,nowait \
    -serial stdio \
```

Launch the destination VM:
```shell
./stratovirt \
    -machine q35 \
    -kernel ./vmlinux.bin \
    -append "console=ttyS0 pci=off reboot=k quiet panic=1 root=/dev/vda" \
    -drive file=path/to/rootfs,id=rootfs,readonly=off,direct=off \
    -device virtio-blk-pci,drive=rootfs,id=rootfs,bus=pcie.0,addr=0 \
    -qmp unix:path/to/socket2,server,nowait \
    -serial stdio \
    -incoming tcp:192.168.0.1:4446 \
```

Note:
- The destination VM command line parameter needs to be consistent with the source VM.
- If it is necessary to change the data transmission from tcp network protocol to unix socket,
  the parameter `-incoming tcp:192.168.0.1:4446` needs to be replaced with `-incoming unix:/tmp/stratovirt-migrate.socket`.
- Unix socket protocol only supports migrate two VMs on the same host OS.

Start to send migration for the source VM:
```shell
$ ncat -U path/to/socket1
<- {"QMP":{"version":{"StratoVirt":{"micro":1,"minor":0,"major":0},"package":""},"capabilities":[]}}
-> {"execute":"migrate", "arguments":{"uri":"tcp:192.168.0.1:4446"}}
<- {"return":{}}
```

Note:
- If using unix socket protocol to migrate vm, you need to modify QMP command of `"uri":"tcp:192.168.0.1:4446"` to
  `"uri":"unix:/tmp/stratovirt-migrate.socket"`.

When finish executing the command line, the live migration is start. in a moment, the source VM should be successfully
migrated to the destination VM.

## Cancel Migration

If you want to cancel the live migration, executing the following command:
```shell
$ ncat -U path/to/socket1
<- {"QMP":{"version":{"StratoVirt":{"micro":1,"minor":0,"major":0},"package":""},"capabilities":[]}}
-> {"execute":"migrate_cancel"}
<- {"return":{}}
```

## Query migration state

Use QMP command `query-migrate` to check migration state:
```shell
$ ncat -U path/to/socket
<- {"QMP":{"version":{"StratoVirt":{"micro":1,"minor":0,"major":0},"package":""},"capabilities":[]}}
-> {"execute":"query-migrate"}
<- {"return":{"status":"completed"}}
```

Now there are 5 states during migration:
- `None`: Resource is not prepared all.
- `Setup`: Resource is setup, ready to migration.
- `Active`: In migration.
- `Completed`: Migration completed.
- `Failed`: Migration failed.
- `Canceled`: Migration canceled.

## Limitations

Migration supports machine type:
- `q35` (on x86_64 platform)
- `virt` (on aarch64 platform)

Some devices and feature don't support to be migration yet:
- `vhost-net`
- `vhost-user-net`
- `vfio` devices
- `balloon`
- `mem-shared`,`backend file of memory`
- `pmu`
- `sve`
- `gic-version=2`

Some device attributes can't be changed:
- `virtio-net`: mac
- `virtio-blk`: file(only ordinary file or copy file), serial_num
- `device`: bus, addr
- `smp`
- `m`

If hot plug device before migrate source vm, add newly replaced device command should be add to destination vm.

Before live migration:
- source and destination host CPU needs to be the same architecture.
- the VMs image needs to be shared by source and destination.
- live migration may fail if the VM is performing lifecycle operations, such as reboot, shutdown.
- the command to startup the VM needs to be consistent on source and destination host.

During live migration:
- source and destination networks cannot be disconnected.
- it is banned to operate VM lifecycle, includes using the QMP command and executing in the VM.
- live migration time is affected by network performance, total memory of VM and applications.

After live migration:
- it needs to wait for the source VM to release resources before fetching back the live migration operation.
