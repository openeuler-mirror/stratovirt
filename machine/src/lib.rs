// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
#[macro_use]
extern crate machine_manager;

pub mod errors {
    error_chain! {
        links {
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
            MicroVm(super::micro_vm::errors::Error, super::micro_vm::errors::ErrorKind);
            Virtio(virtio::errors::Error, virtio::errors::ErrorKind);
        }

        foreign_links {
            KvmIoctl(kvm_ioctls::Error);
        }

        errors {
            AddDevErr(dev: String) {
                display("Failed to add {} device.", dev)
            }
            CrtAddrSpaceErr(space_type: String) {
                display("Failed to create {} address space.", space_type)
            }
            LoadKernErr {
                display("Failed to load kernel.")
            }
            #[cfg(target_arch = "aarch64")]
            GenFdtErr {
                display("Failed to generate FDT.")
            }
            RegNotiferErr {
                display("Failed to register event notifier.")
            }
        }
    }
}

mod micro_vm;

pub use micro_vm::LightMachine;

use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use address_space::KvmIoListener;
use address_space::{create_host_mmaps, AddressSpace, KvmMemoryListener, Region};
use kvm_ioctls::{Kvm, VmFd};
use machine_manager::config::{
    BalloonConfig, ConsoleConfig, DriveConfig, MachineMemConfig, NetworkInterfaceConfig,
    SerialConfig, VmConfig, VsockConfig,
};
use machine_manager::event_loop::EventLoop;
use util::loop_context::{EventNotifier, NotifierCallback, NotifierOperation};
use util::seccomp::{BpfRule, SeccompOpt, SyscallFilter};
use virtio::balloon_allow_list;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use errors::{ErrorKind, Result, ResultExt};

pub trait MachineOps {
    /// Calculate the ranges of memory according to architecture.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - memory size of VM.
    ///
    /// # Returns
    ///
    /// A array of ranges, it's element represents (start_addr, size).
    /// On x86_64, there is a gap ranged from (4G - 768M) to 4G, which will be skipped.
    fn arch_ram_ranges(&self, mem_size: u64) -> Vec<(u64, u64)>;

    /// Init I/O & memory address space and mmap guest memory.
    ///
    /// # Arguments
    ///
    /// * `fds` - File descriptors obtained by opening KVM module and creating new VM.
    /// * `mem_config` - Memory setting.
    /// * `sys_io` - IO address space required for x86_64.
    /// * `sys_mem` - Memory address space.
    fn init_memory(
        &self,
        fds: (Kvm, &Arc<VmFd>),
        mem_config: &MachineMemConfig,
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
    ) -> Result<()> {
        let kvm_fd = fds.0;
        let vm_fd = fds.1;
        sys_mem
            .register_listener(Box::new(KvmMemoryListener::new(
                kvm_fd.get_nr_memslots() as u32,
                vm_fd.clone(),
            )))
            .chain_err(|| "Failed to register KVM listener for memory space.")?;
        #[cfg(target_arch = "x86_64")]
        sys_io
            .register_listener(Box::new(KvmIoListener::new(vm_fd.clone())))
            .chain_err(|| "Failed to register KVM listener for I/O space.")?;

        // Init guest-memory
        // Define ram-region ranges according to architectures
        let ram_ranges = self.arch_ram_ranges(mem_config.mem_size);
        let mem_mappings = create_host_mmaps(&ram_ranges, &mem_config)
            .chain_err(|| "Failed to mmap guest ram.")?;
        for mmap in mem_mappings.iter() {
            let base = mmap.start_address().raw_value();
            let size = mmap.size();
            sys_mem
                .root()
                .add_subregion(Region::init_ram_region(mmap.clone()), base)
                .chain_err(|| {
                    format!(
                        "Failed to register region in memory space: base={}, size={}",
                        base, size,
                    )
                })?;
        }

        Ok(())
    }

    /// Add RTC device.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - File descriptor of VM.
    #[cfg(target_arch = "aarch64")]
    fn add_rtc_device(&mut self, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Add serial device.
    ///
    /// # Arguments
    ///
    /// * `config` - Device configuration.
    /// * `vm_fd` - File descriptor of VM.
    fn add_serial_device(&mut self, config: &SerialConfig, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Add block device.
    ///
    /// # Arguments
    ///
    /// * `config` - Device configuration.
    fn add_block_device(&mut self, config: &DriveConfig) -> Result<()>;

    /// Add vsock device.
    ///
    /// # Arguments
    ///
    /// * `config` - Device configuration.
    /// * `vm_fd` - File descriptor of VM.
    fn add_vsock_device(&mut self, config: &VsockConfig, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Add net device.
    ///
    /// # Arguments
    ///
    /// * `config` - Device configuration.
    /// * `vm_fd` - File descriptor of VM.
    fn add_net_device(&mut self, config: &NetworkInterfaceConfig, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Add console device.
    ///
    /// # Arguments
    ///
    /// * `config` - Device configuration.
    /// * `vm_fd` - File descriptor of VM.
    fn add_console_device(&mut self, config: &ConsoleConfig, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Add memory balloon device.
    ///
    /// # Arguments
    ///
    /// * `config` - Device configuration.
    /// * `vm_fd` - File descriptor of VM.
    fn add_balloon_device(&mut self, config: &BalloonConfig, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Add peripheral devices.
    ///
    /// # Arguments
    ///
    /// * `vm_config` - VM Configuration.
    /// * `vm_fd` - File descriptor of VM.
    fn add_devices(&mut self, vm_config: &VmConfig, vm_fd: &Arc<VmFd>) -> Result<()>;

    /// Return the syscall whitelist for seccomp.
    fn syscall_whitelist(&self) -> Vec<BpfRule>;

    /// Register seccomp rules in syscall whitelist to seccomp.
    fn register_seccomp(&self, balloon_enable: bool) -> Result<()> {
        let mut seccomp_filter = SyscallFilter::new(SeccompOpt::Trap);
        let mut bpf_rules = self.syscall_whitelist();
        if balloon_enable {
            balloon_allow_list(&mut bpf_rules);
        }

        for bpf_rule in &mut bpf_rules {
            seccomp_filter.push(bpf_rule);
        }
        seccomp_filter
            .realize()
            .chain_err(|| "Failed to init seccomp filter.")?;
        Ok(())
    }

    /// Register event notifier for power button of mainboard.
    ///
    /// # Arguments
    ///
    /// * `power_button` - Eventfd of the power button.
    fn register_power_event(&self, power_button: &EventFd) -> Result<()> {
        let power_button = power_button.try_clone().unwrap();
        let button_fd = power_button.as_raw_fd();
        let power_button_handler: Arc<Mutex<Box<NotifierCallback>>> =
            Arc::new(Mutex::new(Box::new(move |_, _| {
                let _ret = power_button.read().unwrap();
                None
            })));
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            button_fd,
            None,
            EventSet::IN,
            vec![power_button_handler],
        );

        EventLoop::update_event(vec![notifier], None).chain_err(|| ErrorKind::RegNotiferErr)?;
        Ok(())
    }

    /// Realize the machine.
    ///
    /// # Arguments
    ///
    /// * `vm` - The machine structure.
    /// * `vm_config` - VM configuration.
    /// * `fds` - File descriptors obtained by opening KVM module and creating a new VM.
    fn realize(self, vm_config: &VmConfig, fds: (Kvm, &Arc<VmFd>)) -> Result<Arc<Self>>;
}
