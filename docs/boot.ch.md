# StratoVirt 启动准备

StratoVirt提供了轻量虚拟机和标准虚拟机两种机型。两种机型的启动过程如下。

## 前置参数设置

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

## 轻量虚拟机启动过程

### 1. 构建内核镜像

StratoVirt的轻量虚拟机机型在x86_64平台上支持PE格式或是bzImage格式的内核镜像，在
aarch64平台上支持PE格式的内核镜像。通过以下步骤来构建内核镜像：

1. 首先，获取openEuler内核源码:

   ```shell
   $ git clone -b kernel-5.10 --depth=1 https://gitee.com/openeuler/kernel
   $ cd kernel
   ```
   如果你安装我们openEuler的21.03版本，也可以通过使用yum源的方式来获取内核源码：

   ```shell
   $ sudo yum install kernel-source
   $ cd /usr/src/linux-5.10.0-0.0.0.7.oe1.$(uname -m)/
   ```

2. 配置linux内核信息。你可以使用 [我们提供的轻量虚拟机内核配置文件](./kernel_config/micro_vm)
并且将配置文件重命名为`.config`拷贝至`kernel`路径下。 当然你也可以通过命令修改内
核编译选项:

   ```shell
   $ make menuconfig
   ```

3. 构建并将内核镜像转换为PE格式。

   ```shell
   $ make -j$(nproc) vmlinux && objcopy -O binary vmlinux vmlinux.bin
   ```

4. 如果你想要在x86_64平台编译bzImage格式内核镜像。
   ```shell
   $ make -j$(nproc) bzImage
   ```

### 2. 构建rootfs镜像

Rootfs镜像是一种文件系统镜像。在StratoVirt启动时可以挂载带有`/sbin/init`的EXT4格
式镜像。你可以查看[附录](#2附录)。

### 3. 启动命令样例

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

## 标准虚拟机启动过程

标准虚拟机有两种启动方式，第一种使用kernel+rootfs；另一种是使用预先安装好guest 操
作系统的raw格式镜像。

接下来讲解如何通过以上所述的两种方式启动标准虚拟机。以上两种启动方式均需使用标准启动
固件，为此首先讲解如何获取标准启动固件。

### 1. 获取标准启动固件

标准启动需要启动固件。Stratovirt仅支持在x86_64和aarch64平台上从UEFI（统一可扩展
固件接口）启动。

EDK2是一个实现了UEFI规范的开源项目。我们使用EDK2作为固件启动虚拟机，因此我们必须
获得相应的EDK2二进制文件.

有两种方法可以获取EDK2二进制文件，通过yum源直接安装或从源代码编译。具体步骤如下。
请注意，EDK2二进制文件包含两个文件，一个用于存储可执行代码，另一个用于存储引导数据。

#### 1.1 直接安装EDK2

在x86_64平台, 运行

```shell
$ sudo yum install -y edk2-ovmf
```

在aarch64平台, 运行

```shell
$ sudo yum install -y edk2-aarch64
```

安装edk2之后，在x86_64平台, `OVMF_CODE.fd` 和 `OVMF_VARS.fd` 文件存在于
`/usr/share/edk2/ovmf` 目录下。 在aarch64平台， `QEMU_EFI-pflash.raw` 和
`vars-template-pflash.raw` 文件会存在于`/usr/share/edk2/aarch64` 目录下。

#### 1.2 从源代码编译

```shell
# 安装必要依赖包用于编译edk2。
yum install git nasm acpica-tools -y

# 克隆 edk2 源代码.
git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout edk2-stable202102
git submodule update --init

# 编译 edk2, 并获取固件文件用于启动StratoVirt。
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

编译edk2之后，在x86_64平台， `OVMF_CODE.fd` 和 `OVMF_VARS.fd` 文件会位于 `/home`
目录下。在aarch64平台， `STRATOVIRT_EFI.raw` 和 `STRATOVIRT_VAR.raw` 文件会位于
`/home` 目录下.

### 2. 以 kernel + rootfs 方式启动标准虚拟机

#### 2.1 构建内核镜像

StratoVirt的标准虚拟机机型支持x86_64平台的bzImage格式内核镜像和aarch64平台的PE格
式内核镜像。内核镜像构建如下：

1. 获取openEuler内核源码:

   ```shell
   $ git clone -b kernel-5.10 --depth=1 https://gitee.com/openeuler/kernel
   $ cd kernel
   ```

2. 配置linux内核信息。你可以使用我们提供的标准虚拟机 [内核配置文件](./kernel_config/standard_vm)
 并且将配置文件重命名为`.config`拷贝至`kernel`路径下。

3. 构建内核镜像

   ```shell
   # 在aarch64平台，将内核镜像转换为PE格式。
   $ make -j$(nproc) vmlinux && objcopy -O binary vmlinux vmlinux.bin

   # 在x86_64平台，将内核镜像转换为bzImage格式.
   $ make -j$(nproc) bzImage
   ```

除了手动构建内核镜像的方式以外，也可以直接从 openEuler 官网下载对应的
[内核镜像](https://repo.openeuler.org/openEuler-21.09/stratovirt_img/x86_64/std-vmlinuxz)。

#### 2.2 构建rootfs镜像

为标准虚拟机构建rootfs镜像实际上与轻量虚拟机相同。你可以通过[附录](#2附录)查看更多
的详细信息。

### 3. 以 raw 格式镜像启动标准虚拟机

#### 3.1 获取 raw 格式镜像

你可以从 openEuler 官网下载已经安装好的 [qcow2 镜像](https://repo.openeuler.org/openEuler-21.03/virtual_machine_img/x86_64/openEuler-21.03-x86_64.qcow2.xz)。

下载之后，可以利用 qemu-img 命令进行转换。接下来以 openEuler-21.03 版本的 qcow2
镜像为例给出具体命令：

```shell
$ xz -d openEuler-21.03-x86_64.qcow2.xz
$ qemu-img convert -f qcow2 -O raw openEuler-21.03-x86_64.qcow2 openEuler-21.03-x86_64.raw
```

至此就获得了可以使用的 raw 格式镜像。

### 4. 以 direct kernel boot 方式启动标准虚拟机

为virt虚机主板提供直接从kernel启动的模式。在该模式下，不需要UEFI和APCI表，
虚拟机将跳过UEFI启动阶段，直接从kernel启动，从而加快启动速度。

启动命令行如下：

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

说明：当前只支持ARM架构下virt虚机主板快速启动标准虚拟机。

### 5. 启动命令行样例

请注意，标准虚拟机需要两个PFlash设备，它们将使用来自与EDK2二进制的两个固件文件。
如果你不需要保持启动信息，单元序列为1的数据存储文件可以被省略。但是单元序号为0的
代码存储文件是必须的。

首先给出 kernel + rootfs 的启动命令，具体如下：

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

最后给出 raw 格式镜像的启动命令，具体如下:

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

## 附录

以下是一种制作EXT4格式rootfs镜像的方法：

1. 准备一个合适大小的文件（例如 1G）：

   ```shell
   $ dd if=/dev/zero of=./rootfs.ext4 bs=1G count=20
   ```

2. 在这个文件上创建一个空的EXT4格式的文件系统：

   ```shell
   $ mkfs.ext4 ./rootfs.ext4
   ```

3. 挂载文件系统镜像:

   ```shell
   $ mkdir -p /mnt/rootfs
   $ sudo mount ./rootfs.ext4 /mnt/rootfs && cd /mnt/rootfs
   ```

4. 获取 [最新的alpine-minirootfs](http://dl-cdn.alpinelinux.org/alpine) ：

   ```shell
   $ arch=`uname -m`
   $ wget http://dl-cdn.alpinelinux.org/alpine/v3.13/releases/$arch/alpine-minirootfs-3.13.0-$arch.tar.gz -O alpine-minirootfs.tar.gz
   $ tar -zxvf alpine-minirootfs.tar.gz
   $ rm alpine-minirootfs.tar.gz
   ```

   为EXT4格式文件系统镜像制作一个简单的 `/sbin/init` 。

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

   **注意: alpine仅是一个例子。你可以使用任何开源的拥有init/systemd的rootfs文件系统来制作rootfs镜像。**


5. 卸载rootfs镜像：

    ```shell
    $ cd ~ && umount /mnt/rootfs
    ```

## 链接

- [EDK2的wiki](https://github.com/tianocore/tianocore.github.io/wiki/EDK-II)
- [OVMF的wiki](https://github.com/tianocore/tianocore.github.io/wiki/OVMF)

