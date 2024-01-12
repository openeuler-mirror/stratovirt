# StratoVirt Boot

StratoVirt provides two kinds of machine, which are microvm and standard VM. The
boot process of these two machines are as follows.

## pre-parameter setting

```shell
arch=`uname -m`
if [ ${arch} = "x86_64" ]; then
    con=ttyS0
    machine="q35"
elif [ ${arch} = "aarch64" ]; then
    con=ttyAMA0
    machine="virt"
else
    echo "${arch} architecture not supported."
    exit 1
fi
```

## microvm boot process

### 1. Build kernel

The microvm machine type of StratoVirt supports PE or bzImage format kernel images
on x86_64 platforms, and supports PE format kernel images on aarch64 platforms.
Kernel image can be built with following steps:

1. Firstly, get the openEuler kernel source code with:

   ```shell
   $ git clone -b kernel-5.10 --depth=1 https://gitee.com/openeuler/kernel
   $ cd kernel
   ```

   If you use our openEuler 21.03, you can also acquire kernel source with yum:

   ```shell
   $ sudo yum install kernel-source
   $ cd /usr/src/linux-5.10.0-0.0.0.7.oe1.$(uname -m)/
   ```

2. Configure your linux kernel. You can use [our recommended microvm config](./kernel_config/micro_vm)
and copy it to `kernel` path as `.config`. You can also modify config options by:

   ```shell
   $ make menuconfig
   ```

3. Build and transform kernel image to PE format.

   ```shell
   $ make -j$(nproc) vmlinux && objcopy -O binary vmlinux vmlinux.bin
   ```

4. If you want to compile bzImage format kernel in x86_64.
   ```shell
   $ make -j$(nproc) bzImage
   ```

### 2. Build rootfs

Rootfs image is a file system image. An EXT4-format image with `/sbin/init` can
be mounted at boot time in StratoVirt. You can check [Appendix](#2Appendix).

### 3. Boot command line sample

```shell
/usr/bin/stratovirt \
    -machine microvm \
    -kernel /path/to/kernel \
    -smp 1 \
    -m 1024m \
    -append "console=${con} pci=off reboot=k quiet panic=1 root=/dev/vda" \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off,direct=off \
    -device virtio-blk-device,drive=rootfs,id=rootfs \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio
```

## Standard VM boot process

Standard VMs can boot in two modes. The first mode is kernel + rootfs.The other
is to use the raw image that has been preinstalled with the guest OS.

The preceding two boot modes both require standard boot firmware. So we first
describe how to obtain the standard boot firmware.

### 1. Get firmware for standard boot

Standard boot needs firmware. Stratovirt only supports booting from UEFI (Unified
Extensible Firmware Interface) on x86_64 and aarch64 platform.

EDK II is an open-source project that implements UEFI specification. We use EDK II
as the firmware to boot VM, and therefore we have to get the corresponding EDK II binary.

There are two ways to get the EDK II binary, either by installing directly by yum
or compiling from source code. The specific steps are as follows. Notes that EDK II
binary contains two files, one for executable code storage and the other for boot
data storage.

#### 1.1 Directly install EDK II

On x86_64 platform, run

```shell
$ sudo yum install -y edk2-ovmf
```

On aarch64 platform, run

```shell
$ sudo yum install -y edk2-aarch64
```

After installing edk2, on x86_64 platform, `OVMF_CODE.fd` and `OVMF_VARS.fd` are
located in `/usr/share/edk2/ovmf` directory. On aarch64 platform, `QEMU_EFI-pflash.raw`
and `vars-template-pflash.raw` are located in `/usr/share/edk2/aarch64` directory.

#### 1.2 Compile from source code

```shell
# Install necessary packages to compile edk2.
yum install git nasm acpica-tools -y

# Clone edk2 source code.
git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout edk2-stable202102
git submodule update --init

# Compile edk2, and get the firmware used to run StratoVirt.
arch=`uname -m`
if [ ${arch} = "x86_64" ]; then
    echo "ACTIVE_PLATFORM = OvmfPkg/OvmfPkgX64.dsc" >> Conf/target.txt
    echo "TARGET_ARCH = X64" >> Conf/target.txt
elif [ ${arch} = "aarch64" ]; then
    echo "ACTIVE_PLATFORM = ArmVirtPkg/ArmVirtQemu.dsc" >> Conf/target.txt
    echo "TARGET_ARCH = AARCH64" >> Conf/target.txt
else
    echo "${arch} architecture not supported."
    exit 1
fi

echo "TOOL_CHAIN_TAG = GCC5" >> Conf/target.txt
echo "BUILD_RULE_CONF = Conf/build_rule.txt" >> Conf/target.txt
echo "TARGET = RELEASE" >> Conf/target.txt

make -C BaseTools
. ./edksetup.sh
build


if [ ${arch} = "x86_64" ]; then
    cp ./Build/OvmfX64/RELEASE_GCC5/FV/OVMF_CODE.fd /home/
    cp ./Build/OvmfX64/RELEASE_GCC5/FV/OVMF_VARS.fd /home/
elif [ ${arch} = "aarch64" ]; then
    dd if=/dev/zero of=/home/STRATOVIRT_EFI.raw bs=1M count=64
    dd of=/home/STRATOVIRT_EFI.raw if=./Build/ArmVirtQemu-AARCH64/RELEASE_GCC5/FV/QEMU_EFI.fd conv=notrunc
    dd if=/dev/zero of=/home/STRATOVIRT_VAR.raw bs=1M count=64
fi
```

After compiling edk2, on x86_64 platform, `OVMF_CODE.fd` and `OVMF_VARS.fd` locate
underneath `/home` directory. On aarch64 platform, `STRATOVIRT_EFI.raw` and
`STRATOVIRT_VAR.raw` locates underneath `/home` directory.

### 2. Boot with kernel and rootfs
#### 2.1 Build kernel

The standard_ machine in StratoVirt supports bzImage format kernel image
on x86_64 platform; and supports PE format kernel image on aarch64 platform.
Kernel image can be built with:

1. Firstly, get the openEuler kernel source code with:

   ```shell
   $ git clone -b kernel-5.10 --depth=1 https://gitee.com/openeuler/kernel
   $ cd kernel
   ```

2. Configure your linux kernel. You should use [our recommended standard_vm config]
(./kernel_config/standard_vm) and copy it to `kernel` path as `.config`.

3. Build kernel image

   ```shell
   # on aarch64 platform, transform kernel image to PE format.
   $ make -j$(nproc) vmlinux && objcopy -O binary vmlinux vmlinux.bin

   # on x86_64 platform, get bzImage format kernel image.
   $ make -j$(nproc) bzImage
   ```
In addition to manually building the kernel image, you can also download the
[kernel image](https://repo.openeuler.org/openEuler-21.09/stratovirt_img/x86_64/std-vmlinuxz)
from the openEuler official website.

#### 2.2 Build rootfs

The building of rootfs for standard VM is exactly the same with microvm. You can
check [Appendix](#2Appendix) for more detailed information.


### 3. Boot with raw image
#### 3.1 Get raw image

You can download the installed [qcow2 image](https://repo.openeuler.org/openEuler-21.03/virtual_machine_img/x86_64/openEuler-21.03-x86_64.qcow2.xz)
from the OpenEuler official website.

After downloading the file, run the qemu-img command to convert the file. Next,
take the qcow2 image of openeuler-21.03 as an example to give the specific commands:

```shell
$ xz -d openEuler-21.03-x86_64.qcow2.xz
$ qemu-img convert -f qcow2 -O raw openEuler-21.03-x86_64.qcow2 openEuler-21.03-x86_64.raw
```

Now the available raw image is obtained.

### 4. Boot with kernel directly

It can directly boot from kernel. In this mode, UEFI and ACPI will not be used. And VM will skip the UEFI, directly start the kernel to reduce boot up time.

Run the following commands to direct boot VM from kernel:

```shell
/usr/bin/stratovirt \
    -machine virt \
    -kernel /path/to/kernel \
    -smp 1 \
    -m 2G \
    -append "console=${con} reboot=k panic=1 root=/dev/vda rw" \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off,direct=off \
    -device virtio-blk-pci,drive=rootfs,id=blk1,bus=pcie.0,addr=0x2 \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio
```

Note: This mode currently only supports arm architecture.

### 5. Boot command line sample

Note that standard need two PFlash devices which will use two firmware files from
EDK II binary. If you don't need to store boot information, data storage file can
be omitted whose unit is 1. But code storage file with unit 0 is necessary.

Run the following commands to boot with the kernel and rootfs:

```shell
/usr/bin/stratovirt \
    -machine ${machine} \
    -kernel /path/to/kernel \
    -smp 1 \
    -m 2G \
    -append "console=${con} reboot=k panic=1 root=/dev/vda rw" \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off,direct=off \
    -device virtio-blk-pci,drive=rootfs,id=blk1,bus=pcie.0,addr=0x2 \
    -drive file=/path/to/OVMF_CODE.fd,if=pflash,unit=0,readonly=true \
    -drive file=/path/to/OVMF_VARS.fd,if=pflash,unit=1 \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio
```

The command for booting with the raw image is as follows:

```shell
/usr/bin/stratovirt \
    -machine ${machine} \
    -smp 1 \
    -m 2G \
    -drive file=/path/to/raw_image,id=raw_image,readonly=off,direct=off \
    -device virtio-blk-pci,drive=raw_image,id=blk1,bus=pcie.0,addr=0x2 \
    -drive file=/path/to/OVMF_CODE.fd,if=pflash,unit=0,readonly=true \
    -drive file=/path/to/OVMF_VARS.fd,if=pflash,unit=1 \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio
```

## Appendix

Below is a simple way to make a EXT4 rootfs image:

1. Prepare a properly-sized file(e.g. 1G):

   ```shell
   $ dd if=/dev/zero of=./rootfs.ext4 bs=1G count=20
   ```

2. Create an empty EXT4 file system on this file:

   ```shell
   $ mkfs.ext4 ./rootfs.ext4
   ```

3. Mount the file image:

   ```shell
   $ mkdir -p /mnt/rootfs
   $ sudo mount ./rootfs.ext4 /mnt/rootfs && cd /mnt/rootfs
   ```

4. Get the [latest alpine-minirootfs](http://dl-cdn.alpinelinux.org/alpine):

   ```shell
   $ arch=`uname -m`
   $ wget http://dl-cdn.alpinelinux.org/alpine/v3.13/releases/$arch/alpine-minirootfs-3.13.0-$arch.tar.gz -O alpine-minirootfs.tar.gz
   $ tar -zxvf alpine-minirootfs.tar.gz
   $ rm alpine-minirootfs.tar.gz
   ```

   Make a simple `/sbin/init` for EXT4 file image.

   ```shell
   $ rm sbin/init && touch sbin/init && cat > sbin/init <<EOF
   #! /bin/sh
   mount -t devtmpfs dev /dev
   mount -t proc proc /proc
   mount -t sysfs sysfs /sys
   ip link set up dev lo

   exec /sbin/getty -n -l /bin/sh 115200 /dev/ttyS0
   poweroff -f
   EOF

   $ sudo chmod +x sbin/init
   ```

   **Notice: alpine is an example. You can use any open rootfs filesystem with init/systemd as rootfs image.**

5. Unmount rootfs image:

    ```shell
    $ cd ~ && umount /mnt/rootfs
    ```

## Links

- [EDK II wiki](https://github.com/tianocore/tianocore.github.io/wiki/EDK-II)
- [OVMF wiki](https://github.com/tianocore/tianocore.github.io/wiki/OVMF)

