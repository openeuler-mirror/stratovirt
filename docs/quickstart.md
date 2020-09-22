# Getting Started with StratoVirt

## 1. Prepare

* Host os

    StratoVirt supports host os Linux 4.19 in both x86_64 and aarch64 platform.

    KVM mod should be supported in your host Linux kernel.

* Authority

    You should have read/write access to `/dev/kvm`. If not, you can get your access by:

    ```shell
    $ sudo setfacl -m u:${USER}:rw /dev/kvm
    ```
## 2. Build StratoVirt from source

### 2.1 Check rust environment

To build StratoVirt, make sure that Rust language environment and Cargo have already installed.
 The version of rustc is suggested up to 1.42.

```shell
$ rustc -version
rustc 1.42.0
```

If you want to deploy rust environment, the following link will help you:

<https://www.rust-lang.org/tools/install>

### 2.2 Build with musl-libc

With musl-libc, StratoVirt is linked statically and having no library dependencies. It's the
 default target to build StratoVirt.

```shell
# Add musl rust tool-chain, if installed, skip
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-musl

# Build StratoVirt
$ cargo build --release --target ${arch}-unknown-linux-musl
```

Now you can find StratoVirt binary in `target/${arch}-unknown-linux-musl/release/stratovirt`.

### 2.3 Build with glibc

StratoVirt can also build using glibc toolchains. By this way, StratoVirt is linked dynamically.

```shell
# Add gnu rust tool-chain, if installed, skip
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-gnu

# Build StratoVirt
$ cargo build --release --target ${arch}-unknown-linux-gnu
```

Now you can find StratoVirt binary in `target/${arch}-unknown-linux-gnu/release/stratovirt`.

## 3. Get Kernel and rootfs Image

### 3.1 Build kernel

The current version StratoVirt supports only PE-format kernel images in both x86_64 and aarch64
platforms, which can be built with:

1. Firstly, get the openEuler kernel source code:

   ```shell
   $ git clone https://gitee.com/openeuler/kernel
   $ cd kernel
   ```

2. Check out the kernel version to kernel-4.19:

   ```shell
   $ git checkout kernel-4.19
   ```

3. Configure your linux kernel build. You can use [our recommended config](./kernel_config) and
copy it to `kernel` path as `.config`. You can interactive config by:

   ```shell
   $ make menuconfig
   ```

4. Build and transform kernel image to PE format.

   ```shell
   $ make -j vmlinux && objcopy -O binary vmlinux vmlinux.bin
   ```

### 3.2 Make rootfs

Rootfs image is a file system image.  An EXT4-format image with an `init` can be mounted at
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
   $ sudo mount ./rootfs.ext4 /mnt/rootfs && cd /mnt/rootfs
   ```

4. Get the [latest alpine-minirootfs](http://dl-cdn.alpinelinux.org/alpine) for your platform(e.g.
 aarch64 3.12.0):

   ```shell
   $ wget http://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-minirootfs-3.12.0-aarch64.tar.gz
   $ tar -zxvf alpine-minirootfs-3.12.0-aarch64.tar.gz
   $ rm alpine-minirootfs-3.12.0-aarch64.tar.gz
   ```

5. Make a simple `/sbin/init` for EXT4 file image.

   ```shell
   $ cat > sbin/init <<EOF
   #! /bin/sh
   mount -t devtmpfs dev /dev
   mount -t proc proc /proc
   mount -t sysfs sysfs /sys
   ip link set up dev lo

   exec /sbin/getty -n -l /bin/sh 115200 /dev/ttyS0
   poweroff -f
   EOF

   sudo chmod +x sbin/init
   ```

6.  Unmount rootfs image:

    ```shell
    $ umount /mnt/rootfs
    ```

## 4. Running StratoVirt

With kernel and rootfs image, we can boot up a guest Linux machine by StratoVirt.

### 4.1 Running with cmdline

The minimum configuration for StratoVirt is:

* A PE format Linux kernel
* Make rootfs image as virtio-blk device and add this device to kernel parameters
* Api-channel to control StratoVirt
* If you want to login with ttyS0, you may need a serial and add ttyS0 to kernel parameters

You can deploy them with cmdline arguments:

```shell
# Make sure api-channel can be created.
$ rm -f /path/to/socket

# Start StratoVirt
$ ./stratovirt \
    -kernel /path/to/vmlinux.bin \
    -append console=ttyS0 pci=off reboot=k panic=1 root=/dev/vda \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off \
    -api-channel unix:/path/to/socket \
    -serial stdio
```

### 4.2 Running with json

StratoVirt can also boot from a json configuration file like [default.json](./default.json).

```shell
# Json configuration file
$ cat default.json
{
  "boot-source": {
    "kernel_image_path": "/path/to/vmlinux.bin",
    "boot_args": "console=ttyS0 root=/dev/vda" reboot=k panic=1
  },
  "machine-config": {
    "vcpu_count": 1,
    "mem_size": 268435456
  },
  "drive": [
    {
      "drive_id": "rootfs",
      "path_on_host": "/path/to/rootfs,
      "direct": false,
      "read_only": false
    }
  ],
  "serial": {
    "stdio": true
  }
}

# Start StratoVirt
$ ./stratovirt \
    -config ./default.json \
    -api-channel unix:/path/to/socket
```

Now StratoVirt can boot a guest Linux machine.

You can also run StratoVirt with initrdfs, read [initrd_guide](./mk_initrd.md).

If you want to know more information on running StratoVirt, go to the [StratoVirt-Guidebook](./StratoVirt-Guidebook.md).
