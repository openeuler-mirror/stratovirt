
# 通过源码构建StratoVirt

## 1. 检查Rust构建环境

为了构建StratoVirt，需保证已经安装了Rust语言环境和Cargo软件。
rustc的推荐版本为1.51.0及其之后的版本, 否则编译可能失败。

```shell
$ rustc --version
rustc 1.51.0
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
$ cargo build --release --target ${arch}-unknown-linux-gnu
```

现在你可找到StratoVirt二进制的路径在 `target/${arch}-unknown-linux-gnu/release/stratovirt`.

## 3. 使用musl-libc构建

StratoVirt也可以使用musl-libc工具链进行构建。通过这种方式，StratoVirt可以被静态链接，不依赖于任何的动态库。

```shell
# 添加musl工具链，如果已安装，请跳过
$ arch=`uname -m`
$ rustup target add ${arch}-unknown-linux-musl

# 构建StratoVirt
$ cargo build --release --target ${arch}-unknown-linux-musl
```

现在你可找到StratoVirt静态链接二进制的路径在 `target/${arch}-unknown-linux-musl/release/stratovirt`.

## 4. 特性编译选项

对于不同的场景，StratoVirt提供基于cargo `feature`的特性条件编译选项。

可选特性清单如下:

- scream_alsa：使能虚拟声卡，使用`ALSA`后端
- scream_pulseaudio：使能虚拟声卡，使用`PulseAudio`后端

```shell
$ cargo build --release --features "scream_alsa"
```
