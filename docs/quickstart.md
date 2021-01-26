# Getting Started with StratoVirt

## 1. Prepare

* Host os

   You can run StratoVirt on both x86_64 and aarch64 platforms.

   And on top of that, the StratoVirt is based on KVM, so please make sure you have KVM module on your platform.

* Authority

    You should have read/write permissions to `/dev/kvm`. If not, you can get your permissions by:

    ```shell
    $ sudo setfacl -m u:${USER}:rw /dev/kvm
    ```
## 2. Build StratoVirt from source

### 2.1 Check rust environment

To build StratoVirt, make sure that Rust language environment and Cargo have already been installed.
 The recommended version of rustc is 1.42 or later.

```shell
$ rustc -version
rustc 1.42.0
```

If you want to deploy rust environment, the following link will help you:

<https://www.rust-lang.org/tools/install>

### 2.2 Build with musl-libc

With musl-libc, StratoVirt is linked statically and has no library dependencies. It's the
 default target to build StratoVirt.

```shell
# Add musl rust tool-chain, if installed, skip
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-musl

# Build StratoVirt
$ cargo build --release --target ${arch}-unknown-linux-musl
```

Now you can find StratoVirt binary file in `target/${arch}-unknown-linux-musl/release/stratovirt`.

### 2.3 Build with glibc

StratoVirt can also be built using glibc toolchains. By this way, StratoVirt is linked dynamically.

```shell
# Add gnu rust tool-chain, if installed, skip
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-gnu

# Build StratoVirt
$ cargo build --release --target ${arch}-unknown-linux-gnu
```

Now you can find StratoVirt binary file in `target/${arch}-unknown-linux-gnu/release/stratovirt`.

## 3. Prepare kernel and rootfs image

### 3.1 Build kernel

The StratoVirt in current version supports PE or bzImage (only x86_64) format kernel images on
both x86_64 and aarch64 platforms, which can be built with:

1. Firstly, get the openEuler kernel source code:

   ```shell
   $ git clone -b kernel-4.19 --depth=1 https://gitee.com/openeuler/kernel
   $ cd kernel
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

### 3.2 Make rootfs

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

4. Get the [latest alpine-minirootfs](http://dl-cdn.alpinelinux.org/alpine) for your platform(e.g.
 aarch64 3.12.0):

   ```shell
   $ wget http://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-minirootfs-3.12.0-aarch64.tar.gz
   $ tar -zxvf alpine-minirootfs-3.12.0-aarch64.tar.gz
   $ rm alpine-minirootfs-3.12.0-aarch64.tar.gz
   ```

5. Make a simple `/sbin/init` for EXT4 file image.

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

6.  Unmount rootfs image:

    ```shell
    $ cd ~ && umount /mnt/rootfs
    ```

## 4. Run StratoVirt

With kernel and rootfs image, we can boot a guest linux machine by StratoVirt.

### 4.1 Run with cmdline

The minimum configuration for StratoVirt is:

* A PE or bzImage (only x86_64) format linux kernel
* A rootfs image as virtio-blk device, which has to be added to kernel parameters
* Api-channel to control StratoVirt
* If you want to login with ttyS0, you may need a serial and add ttyS0 to kernel parameters

You can deploy StratoVirt with cmdline arguments:

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

StratoVirt can also boot from a json configuration file like provided [sample default.json](./default.json).

```shell
# Json configuration file
$ cat default.json
{
  "boot-source": {
    "kernel_image_path": "/path/to/kernel",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off tsc=reliable ipv6.disable=1 root=/dev/vda"
  },
  "machine-config": {
    "vcpu_count": 1,
    "mem_size": 268435456
  },
  "drive": [
    {
      "drive_id": "rootfs",
      "path_on_host": "/path/to/rootfs/image",
      "direct": false,
      "read_only": false
    }
  ],
  "balloon": {
    "deflate_on_oom": true
  },
  "serial": {
    "stdio": true
  }
}

# Start StratoVirt
$ ./stratovirt \
    -config ./default.json \
    -api-channel unix:/path/to/socket
```

You can also run StratoVirt with initrdfs, read [initrd_guide](./mk_initrd.md).

### 4.3 Close the VM

ACPI(Advanced Configuration and Power Interface) has not been implemented yet in StratoVirt. Power manament, such as `shutdown` 
or `reboot` behavior, is not allowed. So it is not feasible to use `shutdown` or `poweroff` command to close the VM.
Instead, use `reboot` command in the guest or `quit` command with QMP to close the VM.

If you want to know more information on running StratoVirt, go to the [Configuration Guidebook](./config_guidebook.md).
