
# 通过源码构建StratoVirt

## 1. 检查Rust构建环境

为了构建StratoVirt，需保证已经安装了Rust语言环境和Cargo软件。
rustc的推荐版本为1.64.0及其之后的版本, 否则编译可能失败。

```shell
$ rustc --version
rustc 1.64.0
```

如果你想部署rust环境，下面的链接可以帮助你：

<https://www.rust-lang.org/tools/install>

## 2. 使用glibc构建

使用glibc构建则StratoVirt为动态链接二进制。它是StratoVirt的默认构建方式。

```shell
# 添加gnu工具链，如果已安装，请跳过
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-gnu

# 构建StratoVirt
$ cargo build --workspace --bins --release --target ${arch}-unknown-linux-gnu
```

现在你可找到StratoVirt二进制的路径在 `target/${arch}-unknown-linux-gnu/release/stratovirt`.

## 3. 使用musl-libc构建

StratoVirt也可以使用musl-libc工具链进行构建。通过这种方式，StratoVirt可以被静态链接，不依赖于任何的动态库。

```shell
# 添加musl工具链，如果已安装，请跳过
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-musl

# 构建StratoVirt
$ cargo build --workspace --bins --release --target ${arch}-unknown-linux-musl
```

现在你可找到StratoVirt静态链接二进制的路径在 `target/${arch}-unknown-linux-musl/release/stratovirt`.

## 4. 特性编译选项

对于不同的场景，StratoVirt提供基于cargo `feature`的特性条件编译选项。

可选特性清单如下:

- scream_alsa：使能虚拟声卡，使用`ALSA`后端
- scream_pulseaudio：使能虚拟声卡，使用`PulseAudio`后端
- usb_host：使能USB Host设备
- usb_camera_v4l2：使能USB摄像头，使用`v4l2`后端
- gtk：使能GTK显示
- vnc：使能VNC显示
- ramfb：使能ramfb显示设备
- virtio_gpu：使能virtio-gpu虚拟显卡

```shell
$ cargo build --release --features "scream_alsa"
```

## 5. OpenHarmony OS版本的编译

StratoVirt支持在Openharmony OS(OHOS)的运行。该版本的编译需要一台x64机器，并使用OHOS提供的RUST交叉编译工具链、以及SDK。

编译之前，需要把OHOS SDK的路径指定到环境变量OHOS_SDK中。另外，StratoVirt依赖的crate有部分不支持OHOS的编译，需要对其源码做相关修改。

编译命令示意如下：

```
RUSTFLAGS="-C link-arg=--target=aarch64-linux-ohos -C linker={OHOS_SDK}/llvm/bin/clang" cargo build --target aarch64-linux-ohos --features {FEATURES}"
```

# 通过容器构建StratoVirt静态链接二进制

## 1. 检查docker环境

为了通过容器构建StratoVirt，需保证已经安装了docker软件。可通过下面的命令检查：

```shell
$ docker -v
Docker version 18.09.0
```

如果你想部署docker环境，下面的链接可以帮助你：

<https://docs.docker.com/get-docker/>

## 2. 使用tools下提供的构建工具

运行tools/build_stratovirt_static下的脚本，自动拉起docker容器构建静态链接的StratoVirt。

```shell
$ cd tools/build_stratovirt_static
# 自定义一个镜像名称，构建StratoVirt静态链接二进制
$ sh build_stratovirt_from_docker.sh custom_image_name
```

构建完成后，可找到StratoVirt构建静态链接二进制的路径在 `target/${arch}-unknown-linux-musl/release/stratovirt`.

