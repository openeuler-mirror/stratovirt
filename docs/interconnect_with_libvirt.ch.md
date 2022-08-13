#  libvirt
Libvirt是StratoVirt的管理软件，它是通过创建命令行来运行StratoVirt和发送QMP命令来管理StratoVirt。目前，支持五个virsh命令来管理StratoVirt:
`virsh create`, `virsh destroy`, `virsh suspend`, `virsh resume` 和 `virsh console`.


## 配置
通过下列方式来配置StratoVirt:

- 内存:

```
<memory unit='GiB'>8</memory>
or
<memory unit='MiB'>8192</memory>
```

- CPU:

CPU拓扑还没有支持，请仅配置VCPU的个数。
```
<vcpu>4</vcpu>
```
- 架构:

`arch`的可选值为: `aarch64` 和 `x86_64`。在X86平台, 支持的机型是 `q35`；在aarch64平台, 支持的机型是 `virt`.
```
<os>
	<type arch='x86_64' machine='q35'>hvm</type>
</os>
```

- 内核和命令行:

`/path/to/standard_vm_kernel` 是标准虚拟机内核的路径.
```
<kernel>/path/to/standard_vm_kernel</kernel>
<cmdline>console=ttyS0 root=/dev/vda reboot=k panic=1 rw</cmdline>
```

- 特性:

由于在标准虚拟机中使用acpi，因此必须配置acpi特性。
```
<features>
    <acpi/>
</features>
```
对于aarch64平台，由于使用了gicv3，因此 `gic` 也应该被加入到特性中。
```
<features>
    <acpi/>
    <gic version='3'/>
</features>
```

- 模拟器:

为了给libvirt设置模拟器， `/path/to/StratoVirt_binary_file` 是StratoVirt二进制的文件路径。
```
<devices>
    <emulator>/path/to/StratoVirt_binary_file</emulator>
</devices>
```

- balloon设备
```
<controller type='pci' index='4' model='pcie-root-port' />
<memballoon model='virtio'>
    <alias name='balloon0'/>
    <address type='pci' domain='0x000' bus='0x04' slot='0x00' function='0x00'/>
</memballoon>
```

- pflash设备

可以通过以下的配置加入pflash设备。
`/path/to/pflash` 是pflash设备文件路径。
```
<loader readonly='yes' type='pflash'>/path/to/pflash</loader>
<nvram template='/path/to/OVMF_VARS'>/path/to/OVMF_VARS</nvram>
```

- io线程个数

```
<iothreads>1</iothreads>
```

- 磁盘设备:

```
<controller type='pci' index='1' model='pcie-root-port' />
<disk type='file' device='disk'>
    <driver name='qemu'  type='raw' iothread='1'/>
    <source file='/path/to/rootfs'/>
    <target dev='hda' bus='virtio'/>
    <iotune>
        <total_iops_sec>1000</total_iops_sec>
    </iotune>
    <address type='pci' domain='0x000' bus='0x01' slot='0x00' function='0x00'/>
</disk>
```

- 网卡设备

```
<controller type='pci' index='2' model='pcie-root-port' />
<interface type='ethernet'>
    <mac address='de:ad:be:ef:00:01'/>
    <source bridge='qbr0'/>
    <target dev='tap0'/>
    <model type='virtio'/>
    <address type='pci' domain='0x000' bus='0x02' slot='0x00' function='0x00'/>
</interface>
```

- 串口设备

为了使用 `virsh console` 命令，virtio串口设备可以通过使用重定向 `pty` 配置。
```
<controller type='pci' index='3' model='pcie-root-port' />
<controller type='virtio-serial' index='0'>
    <alias name='virt-serial0'/>
    <address type='pci' domain='0x000' bus='0x03' slot='0x00' function='0x00'/>
</controller>
<console type='pty'>
    <target type='virtio' port='0'/>
    <alias name='console0'/>
</console>
```

- vhost-vsock设备

```
<controller type='pci' index='6' model='pcie-root-port' />
<vsock model='virtio'>
    <cid auto='no' address='3'/>
    <address type='pci' domain='0x000' bus='0x00' slot='0x06' function='0x00'/>
</vsock>
```

- 随机数设备

```
<controller type='pci' index='5' model='pcie-root-port' />
<rng model='virtio'>
    <rate period='1000' bytes='1234'/>
    <backend model='random'>/path/to/random_file</backend>
    <address type='pci' domain='0x000' bus='0x05' slot='0x00' function='0x00'/>
</rng>
```

- 直通设备

```
<controller type='pci' index='7' model='pcie-root-port' />
<hostdev mode='subsystem' type='pci' managed='yes'>
<driver name='vfio'/>
<source>
    <address domain='0x0000' bus='0x03' slot='0x00' function='0x0'/>
</source>
</hostdev>
```