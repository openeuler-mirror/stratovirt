
# Build StratoVirt from source

## 1. Check Rust environment

To build StratoVirt, make sure that Rust language environment and Cargo have already been installed.
The recommended version of rustc is 1.64.0 or later, otherwise compilation may be failed.

```shell
$ rustc --version
rustc 1.64.0
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
$ cargo build --workspace --bins --release --target ${arch}-unknown-linux-gnu
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
$ cargo build --workspace --bins --release --target ${arch}-unknown-linux-musl
```

Now you can find StratoVirt static binary file in `target/${arch}-unknown-linux-musl/release/stratovirt`.

## 4. Build with features

For different scenarios, StratoVirt provides feature conditional compilation options based on the cargo `feature`.

List of optional features:

- scream_alsa: enable virtual sound card with `ALSA` interface
- scream_pulseaudio: enable virtual sound card with `PulseAudio` interface
- usb_host: enable USB Host device
- usb_camera_v4l2: enable USB camera with `v4l2` backend
- gtk: enable GTK display
- vnc: enable VNC display
- ramfb: enable ramfb display device
- virtio_gpu: enable virtio-gpu virtualized graphics card
- pvpanic: enable virtualized pvpanic pci device

```shell
$ cargo build --workspace --bins --release --features "scream_alsa"
```

## 5. Compiling of OpenHarmony OS version

Stratovirt now can run on OpenHarmony OS(OHOS). Stratovirt, OHOS version, is compiled on x64, and relies on RUST cross compilation toolchain and SDK offered by OHOS.

Before compiling, specify OHOS SDK path in environment variable OHOS_SDK. Some crates needed by StratoVirt now are not support OHOS platform, adapting is essential.

Here is a command demo:

```
RUSTFLAGS="-C link-arg=--target=aarch64-linux-ohos -C linker={OHOS_SDK}/llvm/bin/clang" cargo build --target aarch64-linux-ohos --features {FEATURES}"
```

# Build static StratoVirt in containers

## 1. Check docker environment

In order to build StratoVirt in containers, ensure that the docker software is installed. This can be checked with the following command:

```shell
$ docker -v
Docker version 18.09.0
```

If you want to deploy a docker environment, the following link can help you:

<https://docs.docker.com/get-docker/>

## 2. Run the build script

Run the script under tools/build_stratovirt_static directory to automatically run a docker container to build a statically linked StratoVirt.

```shell
$ cd tools/build_stratovirt_static
# Build StratoVirt with your custom_image_name
$ sh build_stratovirt_from_docker.sh custom_image_name
```

After the build is complete, you can find the statically linked binary StratoVirt in the path: `target/${arch}-unknown-linux-musl/release/stratovirt`.

