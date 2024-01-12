# 如何使用BusyBox制作initrdfs

## 1. 下载Busybox源码，然后解压

``` shell
wget https://busybox.net/downloads/busybox-1.36.1.tar.bz2
tar -xjf busybox-1.36.1.tar.bz2
```

## 2. 编译BusyBox

``` shell
make defconfig
make menuconfig
```

**注意**：选中构建静态库二进制， 在没有依赖库的情况下可以构建二进制。

```text
Settings  --->
    [*] Build static binary (no shared libs)
```

## 3. 安装BusyBox

将已编译的BusyBox安装到默认路径: `_install`.

``` shell
make install
```

## 4. 配置BusyBox

```shell
cd _install
mkdir proc sys dev etc etc/init.d
touch etc/init.d/rcS

cat >etc/init.d/rcS<<EOF
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
/sbin/mdev -s
EOF

chmod +x etc/init.d/rcS
```

## 5. 制作initrd镜像

```shell
cd _install
find . | cpio -o --format=newc > /tmp/StratoVirt-initrd
```

## 6. 使用initrd运行StratoVirt

```shell
$ ./stratovirt \
    -machine microvm \
    -kernel /path/to/kernel \
    -append "console=ttyS0 reboot=k panic=1 root=/dev/ram rdinit=/bin/sh" \
    -initrd /tmp/StratoVirt-initrd \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio
```

