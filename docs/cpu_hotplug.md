# CPU hotplug and hotunplug

StratoVirt support to hot(un)plug CPU to a running VM. This feature supports dynamic adjustment of CPU resources of VM. Currently, only standard VM with x86_64 architecture is supported, and NUMA architecture is not supported.

## Create VM

First, we create a StratoVirt VM.

```shell
$ ./stratovirt \
    -machine q35 \
    -smp [cpus=]<n>,maxcpus=<max_cpus> \
    -m 512 \
    -kernel path/to/kernel \
    -append "console=ttyS0 root=/dev/vda reboot=k panic=1" \
    -drive file=path/to/OVMF_CODE.fd,if=pflash,unit=0,readonly=true \
    -device pcie-root-port,port=0x0,addr=0x1.0x0,bus=pcie.0,id=pcie.1 \
    -drive file=path/to/rootfs,id=rootfs,readonly=true \
    -device virtio-blk-pci,drive=rootfs,bus=pcie.1,addr=0x0.0x0,id=blk-0 \
    -qmp unix:path/to/api/socket,server,nowait \
    -serial stdio
```

- `cpus`: Set the number of CPUs to 'n' (default: 1). The number of `cpus` will all online after VM booted, and can't be hotunplugged.  
- `maxcpus`: Set the number of total CPUs, including online and offline CPUs. The number of offline CPUs is also the number of CPUs that support hotplug. The number of `maxcpus` should not less than `cpus`.

## Hotplug CPU

After the VM boot up, hotplug CPU with QMP:

```shell
$ ncat -U path/to/api/socket
{"QMP":{"version":{"qemu":{"micro":1,"minor":0,"major":5},"package":"StratoVirt-2.3.0"},"capabilities":[]}}
-> {"execute": "device_add","arguments": { "id": "device-id", "driver": "generic-x86-cpu", "cpu-id": cpuid }}
<- {"return":{}}
<- {"event":"CPU_RESIZE","data":{},"timestamp":{"seconds":seconds, "microseconds":microseconds}}
```

- `id`: The ID of the CPU device, which should be a globally unique string.  
- `cpu-id`: The number of the CPU, which can be an integer in the range of [`cpus`, `maxcpus`)

## Hotunplug CPU

hotunplug CPU with QMP:

```shell
$ ncat -U path/to/api/socket
{"QMP":{"version":{"qemu":{"micro":1,"minor":0,"major":5},"package":"StratoVirt-2.3.0"},"capabilities":[]}}
-> {"execute": "device_del", "arguments": { "id": "device-id"}}
<- {"return":{}}
<- {"event":"CPU_RESIZE","data":{},"timestamp":{"seconds":seconds, "microseconds":microseconds}}
```

## Limitations

CPU hot(un)plug support machine type:
- `q35` (on x86_64 platform)

Some devices and feature don't support to be CPU hotplug yet:
- `numa`
