# StratoVirt

StratoVirt is an enterprise-class virtualization platform oriented to cloud data centers. It offers a unified architecture that fits into the three scenarios: VMs, containers, and serverless computing.
StratoVirt has competitive advantages in key technologies such as lightweight low overhead, hardware-software collaboration, and Rust language-level security.

StratoVirt provides reserved interfaces and design flexibility to enable additional features. It supports both standard and lightweight virtualization, while maintaining extensibility for emerging heterogeneous devices.

## How to Start

### Environment Setup

Before compiling StratoVirt, ensure that the Rust language environment and Cargo software have been installed. If they are not installed, install them by referring to the following link:
https://www.rust-lang.org/tools/install

### Software Compilation

To compile StratoVirt, you need to clone the code project and then run the compilation command as follows:

```sh
$ git clone https://gitcode.com/openeuler/stratovirt.git
$ cd stratovirt
$ make build
```

You can find the generated binary file in the `target/release/stratovirt` directory.

### Starting the VM Using StratoVirt

To quickly get started with StratoVirt, you need to prepare:

* Linux kernel image in PE or bzImage format (x86_64 only)
* ext4 file system and rootfs image in RAW format
* UEFI-compliant EDK2 firmware file

You can obtain the prepared Linux kernel image and rootfs image from the following link: https://repo.openeuler.org/openEuler-22.03-LTS/stratovirt_img/

For more details, see [stratovirt_boot](./docs/boot.ch.md).

```shell
# Preset parameters
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

# Start the microVM. If the socket file of -qmp already exists, delete it first.
$ ./target/release/stratovirt \
    -machine microvm \
    -kernel /path/to/kernel \
    -append "console=${con} root=/dev/vda reboot=k panic=1" \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off \
    -device virtio-blk-device,drive=rootfs,id=rootfs \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio

# Start the standard model. If the socket file of -qmp already exists, delete it first.
$ ./target/release/stratovirt \
    -machine ${machine} \
    -kernel /path/to/kernel \
    -append "console=${con} root=/dev/vda reboot=k panic=1" \
    -drive file=/path/to/firmware,if=pflash,unit=0,readonly=true \
    -device pcie-root-port,port=0x0,addr=0x1.0x0,bus=pcie.0,id=pcie.1 \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off \
    -device virtio-blk-pci,drive=rootfs,bus=pcie.1,addr=0x0.0x0,id=blk-0 \
    -qmp unix:/path/to/socket,server,nowait \
    -serial stdio
```

## More Information

For details about how to create a rootfs image, compile a kernel image, and compile StratoVirt, see [stratovirt_quickstart](./docs/quickstart.ch.md).

For details about how to configure more features supported by StratoVirt, see [configuration_guidebook](docs/config_guidebook.md).

For details about the core architecture design of StratoVirt, see [stratovirt_design](./docs/design.ch.md).

## How to Contribute

We welcome new contributors and are very pleased to provide guidance and help for new contributors.
StratoVirt complies with the Rust programming specifications. For details, visit:

https://github.com/rust-dev-tools/fmt-rfcs/tree/master/guide

https://github.com/rust-lang/rust-clippy

For more information about StratoVirt, visit:

https://gitcode.com/openeuler/stratovirt/wiki

If you encounter a bug or have ideas to share, feel free to email the [virt mailing list](https://mailweb.openeuler.org/postorius/lists/virt.openeuler.org/) or submit an [issue](https://gitcode.com/openeuler/stratovirt/issues).

## License

StratoVirt is licensed under the Mulan PSL v2.
