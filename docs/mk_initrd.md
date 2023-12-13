# How to make a initrdfs use BusyBox

## 1. Download BusyBox, then decompression

``` shell
wget https://busybox.net/downloads/busybox-1.36.1.tar.bz2
tar -xjf busybox-1.36.1.tar.bz2
```

## 2. Compile BusyBox

``` shell
make defconfig
make menuconfig
```

**Notice**：Check Build static binary, can build binary without dependence library.

```text
Settings  --->
    [*] Build static binary (no shared libs)
```

## 3. Install BusyBox

Install the compiled BusyBox to default path: `_install`.

``` shell
make install
```

## 4. Config BusyBox

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

## 5. Make initrd image

```shell
cd _install
find . | cpio -o --format=newc > /tmp/StratoVirt-initrd
```

## 6. Run StratoVirt with initrd

```shell
$ ./stratovirt \
    -machine microvm \
    -kernel /path/to/kernel \
    -append "console=ttyS0 reboot=k panic=1 root=/dev/ram rdinit=/bin/sh" \
    -initrd /tmp/StratoVirt-initrd \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio
```

