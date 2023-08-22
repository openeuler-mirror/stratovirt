
# Build StratoVirt from source

## 1. Check Rust environment

To build StratoVirt, make sure that Rust language environment and Cargo have already been installed.
The recommended version of rustc is 1.51.0 or later, otherwise compilation may be failed.

```shell
$ rustc --version
rustc 1.51.0
```

If you want to deploy rust environment, the following link will help you:

<https://www.rust-lang.org/tools/install>

## 2. Build with glibc

With glibc, StratoVirt is linked dynamically. It's the default target to build StratoVirt.

```shell
# Add gnu rust tool-chain, if installed, skip
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-gnu

# Build StratoVirt
$ cargo build --release --target ${arch}-unknown-linux-gnu
```

Now you can find StratoVirt binary file in `target/${arch}-unknown-linux-gnu/release/stratovirt`.

## 3. Build with musl-libc

StratoVirt can also be built using musl-libc toolchains. By this way, StratoVirt is linked statically
and has no library dependencies.

```shell
# Add musl rust tool-chain, if installed, skip
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-musl

# Build StratoVirt
$ cargo build --release --target ${arch}-unknown-linux-musl
```

Now you can find StratoVirt static binary file in `target/${arch}-unknown-linux-musl/release/stratovirt`.

## 4. Build with features

For different scenarios, StratoVirt provides feature conditional compilation options based on the cargo `feature`.

List of optional features:

- scream_alsa: enable virtual sound card with `ALSA` interface
- scream_pulseaudio: enable virtual sound card with `PulseAudio` interface
- usb_host: enable USB Host device
- usb_camera_v4l2: enable USB camera with `v4l2` backend

```shell
$ cargo build --release --features "scream_alsa"
```
