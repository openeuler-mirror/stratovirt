# CPU热插拔

StratoVirt支持对一个运行中的虚机进行CPU的热插入和热拔出。该功能可以动态调整虚机的CPU资源。目前，该功能只支持x86_64的标准虚机，并且不包含NUMA架构。

## 创建虚机

首先，创建一台虚机。

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

- `cpus`：设置虚机的启动CPU数量为'n'(默认: 1)。 `cpus`参数所设置的CPU会在虚机启动后全部上线运行，并且这些CPU不支持热拔出。  
- `maxcpus`：设置虚机的总CPU数量, 包含了在线和离线的CPU, 离线CPU的数量也就是支持热插拔的CPU, `maxcpus`的数量不能小于`cpus`。

## 热插入CPU

虚机启动后，通过QMP热插入CPU

```shell
$ ncat -U /path/to/api/socket
{"QMP":{"version":{"qemu":{"micro":1,"minor":0,"major":5},"package":"StratoVirt-2.3.0"},"capabilities":[]}}
-> {"execute": "device_add","arguments": { "id": "device-id", "driver": "generic-x86-cpu", "cpu-id": cpuid }}
<- {"return":{}}
<- {"event":"CPU_RESIZE","data":{},"timestamp":{"seconds":seconds, "microseconds":microseconds}}
```

- `id`: CPU设备的ID, 该ID应该为全局唯一的字符串。  
- `cpu-id`: CPU的编号，编号的取值范围是[`cpus`, `maxcpus`)内的整数。

## 热拔出CPU

通过QMP热拔出CPU：

```shell
$ ncat -U /path/to/api/socket
{"QMP":{"version":{"qemu":{"micro":1,"minor":0,"major":5},"package":"StratoVirt-2.3.0"},"capabilities":[]}}
-> {"execute": "device_del", "arguments": { "id": "device-id"}}
<- {"return":{}}
<- {"event":"CPU_RESIZE","data":{},"timestamp":{"seconds":seconds, "microseconds":microseconds}}
```

## 限制

CPU热插拔支持的虚机类型:
- `q35` (on x86_64 platform)

CPU热插拔不支持的设备和特性:
- `numa`
