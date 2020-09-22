# StratoVirt

StratoVirt is an opensource VMM(Virtual Machine Manager) which aims to perform
next generation virtualization.StratoVirt is based on Rust programming
language.StratoVirt is lightweight, efficient and safe.It also has features like
Full Sence Support and Modules Flexible Splitting.

StratoVirt is based on Rust language, which ensures the high performance in 
safety and efficiency.

StratoVirt supports live-time remote control with qmp commands.

In the future, StratoVirt would be capable of virtualizing normal machines
with specific hardware emulators.

## How to start

### Preparation
Before building StratoVirt, make sure that Rust language and Cargo have already
been installed, if not, you can install Rust and cargo from following links:

https://www.rust-lang.org/tools/install

### Build StratoVirt
To build StratoVirt, go to the project's directory and make use of Cargo:
```sh
$ git clone https://gitee.com/src-openeuler/stratovirt.git
$ cd stratovirt
$ cargo build --release
```
Now you can find StratoVirt binary in `target/debug/stratovirt`

### Run a VM with StratoVirt
To run StratoVirt quickly, requires
* A PE format Linux kernel
* An EXT4-format rootfs image

```shell
$ ./target/release/stratovirt \
    -kernel /path/to/kernel \
    -append console=ttyS0 root=/dev/vda reboot=k panic=1 \
    -drive file=/path/to/rootfs,id=rootfs,readonly=off \
    -api-channel unix:/path/to/socket \
    -serial stdio
```

Running a VM with json configuration file is also supported,
please refer to [quickstart guide](./docs/quickstart.md) for more details.

## How to contribute
We welcome new contributors! If you want to join us, please
take a glance at the Rust formatting guidance first:

https://github.com/rust-dev-tools/fmt-rfcs/tree/master/guide

Use `cargo clippy` to check and improve your code, the installation guidance
and usage is as below:

https://github.com/rust-lang/rust-clippy

## Licensing
StratoVirt is licensed under the Mulan PSL v2.
