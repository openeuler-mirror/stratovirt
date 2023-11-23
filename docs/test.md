# StratoVirt test

StratoVirt supports two test modes: unit test and mod test. It should be noted that mod test is not fully supported on the x86_64 architecture now.

## Unit test

Unit tests are Rust functions that verify that the non-test code is functioning in the expected manner. We recommend performing unit test execution separately, run StratoVirt unit test as follows:

```shell
$ cargo test --workspace --exclude mod_test -- --nocapture --test-threads=1
```

## Mod test

StratoVirt mod test is an integrated testing method. During the test, the StratoVirt process will be started as the server and communicate through socket and QMP to test the StratoVirt module function.

Before running mod test, we need to compile `stratovirt` and `virtiofsd` first, and then export the environment variables `STRATOVIRT_BINARY` and `VIRTIOFSD_BINARY`.

Build StratoVirt:

```shell
$ cargo build --workspace --bins --release --target=aarch64-unknown-linux-gnu --all-features
```

Build virtiofsd:

```shell
$ git clone https://gitlab.com/virtio-fs/virtiofsd.git
$ cd virtiofsd
$ cargo build --release
```

Export the environment variables `STRATOVIRT_BINARY` and `VIRTIOFSD_BINARY`:

```shell
$ export STRATOVIRT_BINARY="/path/to/stratovirt"
$ export VIRTIOFSD_BINARY="/path/to/virtiofsd"
```

Run StratoVirt mod test as follows:

```shell
$ cargo test --all-features -p mod_test -- --nocapture --test-threads=1
```
