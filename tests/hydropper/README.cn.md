# Hydropper：
hydropper是一个基于pytest的轻量级测试框架，在其基础上封装了虚拟化的相关测试原子，用于stratovirt的黑盒测试。当前hydropper已经支持轻量级虚拟场景和标准化虚拟场景的一些测试用例，可以帮助开发人员发现和定位stratovirt的问题。

## 如何开始

### 环境准备
1. 请确保你的openEuler系统已经安装python3。

2. requirements.txt里面包含了hydropper的依赖包。

- pytest>5.0.0
- aexpect>1.5.0
- retrying

你可以通过下面的命令来安装这些包：
```sh
$ pip3 install -r requirements.txt
```

3. 请在你的openEuler系统上安装下列网络依赖包，以支持用例执行：

```sh
$ yum install nmap
$ yum install iperf3
$ yum install bridge-utils
```

4. 网络配置（可参考以下模板）：

```sh
brctl addbr strato_br0
ip link set strato_br0 up
ip address add 1.1.1.1 dev strato_br0
```

5. 构建测试镜像请参考 docs/IMAGE_BUILD.md。

### 参数配置
请在config目录下的config.ini里配置参数和对应路径，通常的用例都需要配置好kernel和rootfs：
```ini
[env.params]
...
VM_USERNAME = <usrname>
VM_PASSWORD = <passwd>
...
[stratovirt.params]
...
STRATOVIRT_VMLINUX = /path/to/kernel
STRATOVIRT_ROOTFS = /path/to/rootfs
...
```

请在config.ini中配置好IP_PREFIX和IP_3RD，这两项表示虚拟机IPv4地址的前24位，
最后8位会由hydropper来自动配置。请注意虚拟机需要和主机在同一网段。

```ini
[network.params]
# such as 'IP_PREFIX.xxx.xxx'
IP_PREFIX = 1.1
# such as 'xxx.xxx.IP_3RD.xxx'
IP_3RD = 1
```

### 运行测试用例
你可以在hydropper目录下通过以下的命令来执行用例：
```sh
# 执行所有用例
$ pytest

# 执行所有带有关键字microvm的用例
$ pytest -k microvm

# 执行test_microvm_cmdline中的全部用例
$ pytest testcases/microvm/functional/test_microvm_cmdline.py

# 执行test_microvm_without_daemonize用例
$ pytest testcases/microvm/functional/test_microvm_cmdline.py::test_microvm_without_daemonize
```

### 增加测试用例
在testcases目录下的microvm目录里来增加自定义的用例。你可以新增一个python文件或者是在已存在的python文件里新增一个新的函数，文件名和函数名都必须形如test_*：
```python
test_microvm_xxx.py
def test_microvm_xxx()
```

我们已经预置了一些虚拟机对象，用户可以通过生成它们的实例来对虚拟机测试：
```python
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.launch()
```

另外，Fixture也可以帮助我们来更好的编写用例，用户可以参照以下方式来使用Fixture：
```python
# 标记该函数为system用例
@pytest.mark.system
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.launch()
```

现在你可以使用pytest -m system来执行所有的“system”用例了。

用户可以使用basic_config()函数，来配置一些虚拟机的参数：
```python
# 设置虚拟机配置4个VCPU和4G内存
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.basic_config(vcpu_count=4, mem_size='4G')
    test_vm.launch()
```

### 日志

- pytest默认日志路径：/var/log/pytest.log
- stratovirt默认日志路径：/var/log/stratovirt
