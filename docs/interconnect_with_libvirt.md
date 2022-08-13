#  libvirt
Libvirt is one of manager for StratoVirt, it manages StratoVirt by creating cmdlines to launch StratoVirt
and giving commands via QMP. Currently, five virsh commands are supported to manage StratoVirt:
`virsh create`, `virsh destroy`, `virsh suspend`, `virsh resume` and `virsh console`.


## Configuration
StratoVirt can be configured by following ways:

- memory:

```
<memory unit='GiB'>8</memory>
or
<memory unit='MiB'>8192</memory>
```

- CPU:

CPU topology is not supported, please configure the number of VCPUs only.
```
<vcpu>4</vcpu>
```
- Architecture:

Optional value of `arch` are: `aarch64` and `x86_64`. On X86 platform, supported machine is `q35`; on aarch64 platform, supported machine is `virt`.
```
<os>
	<type arch='x86_64' machine='q35'>hvm</type>
</os>
```

- Kernel and cmdline:

`/path/to/standard_vm_kernel` is the path of standard vm kernel.
```
<kernel>/path/to/standard_vm_kernel</kernel>
<cmdline>console=ttyS0 root=/dev/vda reboot=k panic=1 rw</cmdline>
```

- feature:

As the acpi is used in Standard VM, therefore the acpi feature must be configured.
```
<features>
    <acpi/>
</features>
```
For aarch64 platform, as gicv3 is used the `gic` should also be added to feature.
```
<features>
    <acpi/>
    <gic version='3'/>
</features>
```

- emulator:

Set emulator for libvirt, `/path/to/StratoVirt_binary_file` is the path to StratoVirt binary file.
```
<devices>
    <emulator>/path/to/StratoVirt_binary_file</emulator>
</devices>
```

- balloon
```
<controller type='pci' index='4' model='pcie-root-port' />
<memballoon model='virtio'>
    <alias name='balloon0'/>
    <address type='pci' domain='0x000' bus='0x04' slot='0x00' function='0x00'/>
</memballoon>
```

- pflash

Pflash can be added by the following config.
`/path/to/pflash` is the path of pflash file.
```
<loader readonly='yes' type='pflash'>/path/to/pflash</loader>
<nvram template='/path/to/OVMF_VARS'>/path/to/OVMF_VARS</nvram>
```

- iothread

```
<iothreads>1</iothreads>
```

- block:

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

- net

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

- console

To use `virsh console` command, the virtio console with redirect `pty` should be configured.
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

- vhost-vsock

```
<controller type='pci' index='6' model='pcie-root-port' />
<vsock model='virtio'>
    <cid auto='no' address='3'/>
    <address type='pci' domain='0x000' bus='0x00' slot='0x06' function='0x00'/>
</vsock>
```

- rng

```
<controller type='pci' index='5' model='pcie-root-port' />
<rng model='virtio'>
    <rate period='1000' bytes='1234'/>
    <backend model='random'>/path/to/random_file</backend>
    <address type='pci' domain='0x000' bus='0x05' slot='0x00' function='0x00'/>
</rng>
```

- vfio

```
<controller type='pci' index='7' model='pcie-root-port' />
<hostdev mode='subsystem' type='pci' managed='yes'>
<driver name='vfio'/>
<source>
    <address domain='0x0000' bus='0x03' slot='0x00' function='0x0'/>
</source>
</hostdev>
```