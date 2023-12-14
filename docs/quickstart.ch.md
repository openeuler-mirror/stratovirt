# 开始使用StratoVirt

## 1. 准备工作

* 主机操作系统

   StratoVirt可以运行在x86_64和aarch64平台。

   最重要的是StratoVirt是基于Linux内核的虚拟机（KVM）构建的，因此在运行的平台上需要保证有KVM内核模块的存在。

* 权限

    需要保证对`/dev/kvm`有读写的权限。 如果没有，可以通过以下方式获取权限:

    ```shell
    $ sudo setfacl -m u:${USER}:rw /dev/kvm
    ```

## 2. 获取StratoVirt

StratoVirt在openEuler 20.09及之后的版本都有提供。 可以通过yum命令直接进行安装。

```shell
$ sudo yum install stratovirt
```

安装完成后可以找到StratoVirt二进制的路径: `/usr/bin/stratovirt`.

如果需要自己构建StratoVirt二进制, 可以参考[构建指导](./build_guide.ch.md).

## 3. 运行StratoVirt

通过StratoVirt二进制（无论是通过yum安装获取或是通过源码构建获取），可以启动Linux客户机。
StratoVirt当前提供了两种虚拟机：微虚拟机和标准虚拟机（x86_64平台q35主板和aarch平台的virt主板）。
作为快速入门，以下展示启动微虚拟机。
首先，需要PE格式的Linux内核二进制和ext4文件系统镜像（作为rootfs）。
* `x86_64` 启动资源: [内核二进制](https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/x86_64/vmlinux.bin)
and [rootfs镜像](https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/x86_64/openEuler-22.03-LTS-stratovirt-x86_64.img.xz).
* `aarch64` 启动资源: [内核二进制](https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/aarch64/vmlinux.bin)
and [rootfs镜像](https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/aarch64/openEuler-22.03-LTS-stratovirt-aarch64.img.xz).

也可以通过以下的shell脚本获取内核二进制和rootfs镜像:

```shell
arch=`uname -m`
dest_kernel="vmlinux.bin"
dest_rootfs="rootfs.ext4"
image_bucket_url="https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img"

if [ ${arch} = "x86_64" ] || [ ${arch} = "aarch64" ]; then
    kernel="${image_bucket_url}/${arch}/vmlinux.bin"
    rootfs="${image_bucket_url}/${arch}/openEuler-22.03-LTS-stratovirt-${arch}.img.xz"
else
    echo "Cannot run StratoVirt on ${arch} architecture!"
    exit 1
fi

echo "Downloading $kernel..."
wget ${kernel} -O ${dest_kernel} --no-check-certificate

echo "Downloading $rootfs..."
wget ${rootfs} -O ${dest_rootfs}.xz --no-check-certificate
xz -d ${dest_rootfs}.xz

echo "kernel file: ${dest_kernel} and rootfs image: ${dest_rootfs} download over."
```

启动StratoVirt客户机:

```shell
socket_path=`pwd`"/stratovirt.sock"
kernel_path=`pwd`"/vmlinux.bin"
rootfs_path=`pwd`"/rootfs.ext4"

# 保证QMP通信socket文件路径可以被创建。
rm -f ${socket_path}

# 通过StratoVirt启动轻量化机型的Linux客户机。
/usr/bin/stratovirt \
    -machine microvm \
    -kernel ${kernel_path} \
    -smp 1 \
    -m 1024 \
    -append "console=ttyS0 pci=off reboot=k quiet panic=1 root=/dev/vda" \
    -drive file=${rootfs_path},id=rootfs,readonly=off,direct=off \
    -device virtio-blk-device,drive=rootfs,id=rootfs \
    -qmp unix:${socket_path},server,nowait \
    -serial stdio
```

在标准输入输出串口上提示登入客户机。 如果使用我们提供的`openEuler-22.03-LTS-stratovirt.img`镜像，
可以使用用户名`root`和密码`openEuler12#$`进行登入。

如果想要停止客户机，可以通过在客户机内部输入`reboot`命令来实际关闭StratoVirt。
这是因为StratoVirt没有在微虚拟机类型中实现电源管理。

如果需要了解更多关于运行StratoVirt信息，请参考[配置指导](./config_guidebook.md).