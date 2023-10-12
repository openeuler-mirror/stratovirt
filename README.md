# StratoVirt
StratoVirt is an enterprise-level virtualization platform for cloud data centers
in the computing industry. It implements a set of architecture that supports
three scenarios: virtual machines, containers, and serverless computing.

StratoVirt has competitive advantages in light weight and low noise, software
and hardware coordination, and Rust language-level security.

StratoVirt reserves interfaces and design to support more features, now can support
standard and lightweight virtualization together,
as well as the ability to extend support for new heterogeneous devices.

## How to start

### Preparation
Before building StratoVirt, make sure that Rust language and Cargo have already
been installed. If not, you can find installation guidance via following link:

https://www.rust-lang.org/tools/install

And it will get smaller memory overhead if you prepare musl toolchain for rust.

### Build StratoVirt
To build StratoVirt, clone the project and build it first:
```sh
$ git clone https://gitee.com/openeuler/stratovirt.git
$ cd stratovirt
$ make build
```
Now you can find StratoVirt binary in `target/release/stratovirt`.

### Run a VM with StratoVirt
To run StratoVirt quickly, requires
* A PE or bzImage (only x86_64) format Linux kernel
* An EXT4 filesystem, raw format rootfs disk image

You can get kernel and rootfs image from the following link:

https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/

For standard VM, firmware file of EDK2 which follows UEFI is required.

```shell
# If the socket of qmp exists, remove it first.

# Start microvm
$ ./target/release/stratovirt \
    -machine microvm \
    -kernel /path/to/kernel \
    -append "console=ttyS0 root=/dev/vda reboot=k panic=1" \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off \
    -device virtio-blk-device,drive=rootfs,id=rootfs \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio

# Start standard VM on x86_64
$ ./target/release/stratovirt \
    -machine q35 \
    -kernel /path/to/kernel \
    -append "console=ttyS0 root=/dev/vda reboot=k panic=1" \
    -drive file=/path/to/firmware,if=pflash,unit=0,readonly=true \
    -device pcie-root-port,port=0x0,addr=0x1.0x0,bus=pcie.0,id=pcie.1 \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off \
    -device virtio-blk-pci,drive=rootfs,bus=pcie.1,addr=0x0.0x0,id=blk-0 \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio
```

The detailed guidance of making rootfs, compiling kernel and building StratoVirt
can be found in [StratoVirt QuickStart](./docs/quickstart.md).

StratoVirt supports much more features, the detailed guidance can be found in
[Configuration Guidebook](docs/config_guidebook.md).

## Design

To get more details about StratoVirt's core architecture design, refer to
[StratoVirt design](./docs/design.md).

## How to contribute
We welcome new contributors! And we are happy to provide guidance and help for
new contributors. StratoVirt follows Rust formatting conventions, which can be
found at:

https://github.com/rust-dev-tools/fmt-rfcs/tree/master/guide
https://github.com/rust-lang/rust-clippy

You can get more information about StratoVirt at:

https://gitee.com/openeuler/stratovirt/wikis

If you find a bug or have some ideas, please send an email to the
[virt mailing list](https://mailweb.openeuler.org/postorius/lists/virt.openeuler.org/)
or submit an [issue](https://gitee.com/openeuler/stratovirt/issues).

## Licensing
StratoVirt is licensed under the Mulan PSL v2.
