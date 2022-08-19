# Hydropper：
Hydropper is a lightweight test framework based on pytest. It encapsulates virtualization-related test atoms and is used for stratovirt black-box tests.Hydropper has provided some testcases for lightweight virtualization and standard virtualization to help Developers find and locate Stratovirt problems.

## How to start


### Preparation
1. Ensure that python3 has been installed on your openEuler system.

2. The requirements.txt file contains the Python3 dependency package.

- pytest>5.0.0
- aexpect>1.5.0
- retrying

You can install these packages by running the following commands:
```sh
$ pip3 install -r requirements.txt
```

3. Network dependency package:
```sh
$ yum install nmap
$ yum install iperf3
$ yum install bridge-utils
```

4. Network configuration（template）

```sh
brctl addbr strato_br0
ip link set strato_br0 up
ip address add 1.1.1.1 dev strato_br0
```

5. For details about how to build a test image, see docs/IMAGE_BUILD.md.

### Parameter configuration
Set parameters and corresponding paths in the config/config.ini. Generally, the kernel and rootfs must be configured for test cases.
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

Configure IP_PREFIX and IP_3RD in the "config.ini" file,
which indicate the first 24 bits of the VM IPv4 address,
The last 8 bits are automatically configured by the hydropper.
Note that the VM and the host must be in the same network segment.

```ini
[network.params]
# such as 'IP_PREFIX.xxx.xxx'
IP_PREFIX = 1.1
# such as 'xxx.xxx.IP_3RD.xxx'
IP_3RD = 1
```

### Run testcases
You can run the following commands in the hydroper directory to execute cases:
```sh
# Run all cases
$ pytest

# Run all cases with the keyword microvm
$ pytest -k microvm

# Run all cases in test_microvm_cmdline.py
$ pytest testcases/microvm/functional/test_microvm_cmdline.py

# Run test_microvm_without_daemonize
$ pytest testcases/microvm/functional/test_microvm_cmdline.py::test_microvm_without_daemonize
```

### Add new testcases
Add customized cases to the microvm directory under testcases.You can add a python file or add a function to an existing python file.The file name and function name must be in the format of test_*.
```python
test_microvm_xxx.py
def test_microvm_xxx()
```

We have preset some virtual machine objects. You can test the virtual machine by generating their instances：
```python
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.launch()
```

In addition, Fixture is useful to write testcases.You can use Fixture in the following ways:
```python
# Mark the tag to system
@pytest.mark.system
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.launch()
```

Now you can use the pytest -m system command to run all the "system" cases.

You can use the basic_config() function to configure VM parameters：
```python
# Configure four vCPUs and 4 GB memory for the VM.
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.basic_config(vcpu_count=4, mem_size='4G')
    test_vm.launch()
```

### Log

- pytest default log path: /var/log/pytest.log
- stratovirt default log path: /var/log/stratovirt
