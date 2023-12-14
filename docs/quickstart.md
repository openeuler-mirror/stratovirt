# Getting Started with StratoVirt

## 1. Prepare

* Host os

   You can run StratoVirt on both x86_64 and aarch64 platforms.

   And on top of that, the StratoVirt is based on KVM, so please make sure you
have KVM module on your platform.

* Authority

    You should have read/write permissions to `/dev/kvm`. If not, you can get your permissions by:

    ```shell
    $ sudo setfacl -m u:${USER}:rw /dev/kvm
    ```

## 2. Get the StratoVirt Binary

StratoVirt is offerred by openEuler 20.09 or later. You can install by yum directly.

```shell
$ sudo yum install stratovirt
```

Now you can find StratoVirt binary with path: `/usr/bin/stratovirt`.

If you'd like to build StratoVirt yourself, you should check out the [build_guide](./build_guide.md).

## 3. Run StratoVirt

With StratoVirt binary (either installed with yum, or built from source), we can
boot a guest linux machine. Now StratoVirt provides two kinds of machine, which
are microvm and standard_vm("q35" on x86_64 platform and "virt" on aarch64 platform).
As a quick start, we show how to start a VM with microvm.

First, you will need an PE format Linux kernel binary, and an ext4 file system image (as rootfs).
* `x86_64` boot source: [kernel](https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/x86_64/vmlinux.bin)
and [rootfs](https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/x86_64/openEuler-22.03-LTS-stratovirt-x86_64.img.xz).
* `aarch64` boot source: [kernel](https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/aarch64/vmlinux.bin)
and [rootfs](https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/aarch64/openEuler-22.03-LTS-stratovirt-aarch64.img.xz).

Or get the kernel and rootfs with shell:

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

Start guest linux machine with StratoVirt:

```shell
socket_path=`pwd`"/stratovirt.sock"
kernel_path=`pwd`"/vmlinux.bin"
rootfs_path=`pwd`"/rootfs.ext4"

# Make sure QMP can be created.
rm -f ${socket_path}

# Start linux VM with machine type "microvm" by StratoVirt.
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

You should now see a serial in stdio prompting you to log into the guest machine.
If you used our `openEuler-22.03-LTS-stratovirt.img` image, you can login as
`root`, using the password `openEuler12#$`.

If you want to quit the guest machine, using a `reboot` command inside the guest
will actually shutdown StratoVirt. This is due to that StratoVirt didn't implement
guest power management in microvm type.

If you want to know more information on running StratoVirt, go to the [Configuration Guidebook](./config_guidebook.md).
