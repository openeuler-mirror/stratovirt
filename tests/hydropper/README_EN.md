# Hydropper

Hydropper is a lightweight testing framework based on pytest. It encapsulates virtualization-related atomic tests for black-box testing of StratoVirt. Currently, hydropper supports certain test cases in lightweight and standard virtualization scenarios, helping developers detect and locate StratoVirt issues.

## How to Start

### Environment Setup

1. Ensure that Python 3 has been installed on the openEuler system.
2. Ensure that the **requirements.txt** file contains the dependency packages of hydropper.
   - pytest>5.0.0
   - aexpect>1.5.0
   - retrying

    You can run the following command to install the packages:

    ```sh
    $ pip3 install -r requirements.txt
    ```

3. Install the following network dependency packages on the openEuler system to support test case execution:

    ```sh
    $ yum install nmap
    $ yum install iperf3
    $ yum install bridge-utils
    ```

4. Configure the network (by referring to the following template):

    ```sh
    brctl addbr strato_br0
    ip link set strato_br0 up
    ip address add 1.1.1.1 dev strato_br0
    ```

5. Build a test image by referring to docs/IMAGE_BUILD.md.

### Parameter Configuration

Configure the parameters and corresponding paths in the **config.ini** file in the **config** directory. The kernel and rootfs need to be configured for common test cases.

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

Configure **IP_PREFIX** and **IP_3RD** in the **config.ini** file. The two parameters indicate the first 24 bits of the IPv4 address of the VM.
The last eight bits are automatically configured by Hydropper. Ensure that the VM and the host are in the same network segment.

```ini
[network.params]
# such as 'IP_PREFIX.xxx.xxx'
IP_PREFIX = 1.1
# such as 'xxx.xxx.IP_3RD.xxx'
IP_3RD = 1
```

### Running Test Cases

You can run the following commands in the hydropper directory to execute test cases:

```sh
# Execute all test cases.
$ pytest

# Execute all test cases with the keyword microvm.
$ pytest -k microvm

# Execute all test cases in test_microvm_cmdline.
$ pytest testcases/microvm/functional/test_microvm_cmdline.py

# Execute the test_microvm_without_daemonize test case.
$ pytest testcases/microvm/functional/test_microvm_cmdline.py::test_microvm_without_daemonize
```

### Adding Test Cases

Custom test cases can be added to the **microvm** directory under the **testcases** directory. You can add a Python file or add a new function to an existing Python file. The file name and function name must be in the format of test_***.

```python
test_microvm_xxx.py
def test_microvm_xxx()
```

Some VM objects have been preset. You can generate instances of these objects to test the VMs.

```python
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.launch()
```

In addition, fixture can help you better compile test cases. You can use fixture as follows:

```python
# Mark the function as a system test case.
@pytest.mark.system
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.launch()
```

You can use pytest -m system to execute all system test cases.

You can use the basic_config() function to configure certain VM parameters.

```python
# Configure the VM with four vCPUs and 4 GB memory.
def test_microvm_xxx(microvm):
    test_vm = microvm
    test_vm.basic_config(vcpu_count=4, mem_size='4G')
    test_vm.launch()
```

### Logs

- Default pytest log path: /var/log/pytest.log
- Default StratoVirt log path: /var/log/stratovirt
