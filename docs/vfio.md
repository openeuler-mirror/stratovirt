# VFIO User Manual

## Introduction

The VFIO driver is an IOMMU/device agnostic framework for exposing direct access to userspace, in a secure,
IOMMU protected environment. Virtual machine often makes use of direct device access when configured for the highest
possible I/O performance.

## Preparation

In order to successfully use VFIO device, it is mandatory that hardware supports virtualization and IOMMU groups.
Execute the following command on your host OS to check whether the IOMMU has been turned on.
```shell
# dmesg | grep iommu
```
If the IOMMU is turned on, the terminal display as follows:
```shell
iommu: Default domain type: Translated
hibmc-drm 0000:0a:00.0: Adding to iommu group 0
ehci-pci 0000:7a:01.0: Adding to iommu group 1
ehci-pci 0000:ba:01.0: Adding to iommu group 2
ohci-pci 0000:7a:00.0: Adding to iommu group 3
ohci-pci 0000:ba:00.0: Adding to iommu group 4
xhci_hcd 0000:7a:02.0: Adding to iommu group 5
...
```
Assume user wants to access PCI device 0000:1a:00.3.
The device is attached to PCI bus, therefore user will make use of vfio-pci to manage the group:
```shell
# modprobe vfio-pci
```

## Bind VFIO device

Binding this device to the vfio-pci driver, it will create the VFIO group character devices for this group.
```shell
# echo 0000:1a:00.3 > /sys/bus/pci/devices/0000:1a:00.3/driver/unbind
# echo `lspci -ns 0000:1a:00.3 | awk -F':| ' '{print $5" "$6}'` > /sys/bus/pci/drivers/vfio-pci/new_id
```

## Command line

Four properties are supported for VFIO device
* host: PCI device info in the system that contains domain, bus number, slot number and function number.
* id: VFIO device name.
* bus: bus number of VFIO device.
* addr: including slot number and function number.
```shell
-device vfio-pci,host=0000:1a:00.3,id=net,bus=pcie.0,addr=0x03.0x0[,multifunction=on]
```
Note: the kernel must contain physical device drivers, otherwise it cannot be loaded normally.
Note: avoid using balloon devices and vfio devices together.

## Hot plug management

StratoVirt standard VM supports hot-plug VFIO devices with QMP.
Refer to qmp.md for specific command line parameters.

### Example

hot plug VFIO device:
```json
-> {"execute":"device_add", "arguments":{"id":"vfio-0", "driver":"vfio-pci", "bus": "pcie.1", "addr":"0x0", "host": "0000:1a:00.3"}}
<- {"return": {}}
```
hot unplug VFIO device:
```json
-> {"execute": "device_del", "arguments": {"id": "vfio-0"}}
<- {"event":"DEVICE_DELETED","data":{"device":"vfio-0","path":"vfio-0"},"timestamp":{"seconds":1614310541,"microseconds":554250}}
<- {"return": {}}
```

## Unbind VFIO device

If it is necessary to unbind VFIO device directly, you can execute the following command.
Note: assume uses hinic driver
```shell
# echo 0000:03:00.0 > /sys/bus/pci/drivers/vfio-pci/unbind
# echo 0000:03:00.0 > /sys/bus/pci/drivers/hinic/bind
```
