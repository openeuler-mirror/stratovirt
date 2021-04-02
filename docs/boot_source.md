# Build StratoVirt Boot Souce

## 1. Build kernel

The StratoVirt in current version supports PE or bzImage (only x86_64) format kernel images on
both x86_64 and aarch64 platforms. Kernel image can be built with:

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

2. Configure your linux kernel. You can use [our recommended config](./kernel_config) and
copy it to `kernel` path as `.config`. You can also modify config options by:

   ```shell
   $ make menuconfig
   ```

3. Build and transform kernel image to PE format.

   ```shell
   $ make -j vmlinux && objcopy -O binary vmlinux vmlinux.bin
   ```

5. If you want compile bzImage format kernel in x86_64.
   ```shell
   $ make -j bzImage
   ```

## 2. Make rootfs

Rootfs image is a file system image.  An EXT4-format image with `/sbin/init` can be mounted at
 boot time in StratoVirt. Below is a simple way to make a EXT4 rootfs image:

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
   $ wget http://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/$arch/alpine-minirootfs-3.13.0-$arch.tar.gz -O alpine-minirootfs.tar.gz
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

5.  Unmount rootfs image:

    ```shell
    $ cd ~ && umount /mnt/rootfs
    ```
