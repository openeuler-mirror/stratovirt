# StratoVirt
StratoVirt is an opensource VMM(Virtual Machine Manager) which aims to perform
next generation virtualization.

Based on Rust programming language, StratoVirt is lightweight, efficient and safe.
StratoVirt reduces memory resource consumption and improves VM startup speed while
retains isolation capability and security capability of traditional virtualization.

StratoVirt supports communicating with external systems using OCI compatible Interface, 
and can be applied to microservices or serverless scenarios.

StratoVirt reserves interface and design for importing more features, even standard virtualization.

## How to start

### Preparation
Before building StratoVirt, make sure that Rust language and Cargo have already
been installed. If not, you can find installation guidance from the following link:

https://www.rust-lang.org/tools/install

### Build StratoVirt
To build StratoVirt, clone the project and build it first:
```sh
$ git clone https://gitee.com/openeuler/stratovirt.git
$ cd stratovirt
$ cargo build --release
```
Now you can find StratoVirt binary in `target/release/stratovirt`.

### Run a VM with StratoVirt
To run StratoVirt quickly, requires
* A PE format Linux kernel
* An EXT4-format rootfs image

```shell
# If the socket of api-channel exists, remove if first.
$ ./target/release/stratovirt \
    -kernel /path/to/kernel \
    -append console=ttyS0 root=/dev/vda reboot=k panic=1 \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off \
    -api-channel unix:/path/to/socket \
    -serial stdio
```

The detailed guidance of making rootfs, compiling kernel and building StratoVirt can be found
in [StratoVirt QuickStart](./docs/quickstart.md).

StratoVirt supports much more features, the detailed guidance can be found in [Configuration Guidebook](docs/config_guidebook.md).

## Design

To get more details about StratoVirt's core architecture design, refer to [StratoVirt design](./docs/design.md).

## How to contribute
We welcome new contributors! And we are happy to provide guidance and help for new contributors.
StratoVirt follows Rust formatting conventions, which can be found at:

https://github.com/rust-dev-tools/fmt-rfcs/tree/master/guide
https://github.com/rust-lang/rust-clippy

You can get more information about StratoVirt at:

https://gitee.com/openeuler/stratovirt/wikis

## Licensing
StratoVirt is licensed under the Mulan PSL v2.
