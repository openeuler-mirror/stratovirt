// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

mod listener;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use kvm_bindings::kvm_userspace_memory_region as KvmMemSlot;
use kvm_bindings::*;
use kvm_ioctls::{Kvm, VmFd};
use vmm_sys_util::{ioctl_ioc_nr, ioctl_iow_nr};

use self::listener::KvmMemoryListener;
use super::HypervisorOps;
use address_space::{AddressSpace, Listener};
use migration::{MigrateMemSlot, MigrateOps};

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/kvm.h
pub const KVM_SET_USER_MEMORY_REGION: u32 = 0x4020_ae46;
pub const KVM_IOEVENTFD: u32 = 0x4040_ae79;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/kvm.h
ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KvmHypervisor {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<Arc<VmFd>>,
    pub mem_slots: Arc<Mutex<HashMap<u32, KvmMemSlot>>>,
}

impl KvmHypervisor {
    pub fn new(kvm_vm_fd: Option<Arc<VmFd>>) -> Result<Self> {
        match Kvm::new() {
            Ok(kvm_fd) => {
                let vm_fd: Option<Arc<VmFd>> = if kvm_vm_fd.is_some() {
                    kvm_vm_fd
                } else {
                    Some(Arc::new(match kvm_fd.create_vm() {
                        Ok(fd) => fd,
                        Err(e) => {
                            bail!("Failed to create VM in KVM: {:?}", e);
                        }
                    }))
                };
                Ok(KvmHypervisor {
                    fd: Some(kvm_fd),
                    vm_fd,
                    mem_slots: Arc::new(Mutex::new(HashMap::new())),
                })
            }
            Err(e) => {
                bail!("Failed to open /dev/kvm: {:?}", e)
            }
        }
    }

    fn create_memory_listener(&self) -> Arc<Mutex<dyn Listener>> {
        Arc::new(Mutex::new(KvmMemoryListener::new(
            self.fd.as_ref().unwrap().get_nr_memslots() as u32,
            self.vm_fd.clone(),
            self.mem_slots.clone(),
        )))
    }
}

impl HypervisorOps for KvmHypervisor {
    fn init_machine(
        &self,
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
    ) -> Result<()> {
        self.arch_init()?;

        sys_mem
            .register_listener(self.create_memory_listener())
            .with_context(|| "Failed to register hypervisor listener for memory space.")?;
        #[cfg(target_arch = "x86_64")]
        sys_io
            .register_listener(self.create_io_listener())
            .with_context(|| "Failed to register hypervisor listener for I/O address space.")?;

        Ok(())
    }
}

impl MigrateOps for KvmHypervisor {
    /// Get ram memory region from `KvmHypervisor` structure.
    fn get_mem_slots(&self) -> Arc<Mutex<HashMap<u32, MigrateMemSlot>>> {
        let mut mgt_mem_slots = HashMap::new();
        for (_, slot) in self.mem_slots.lock().unwrap().iter() {
            let mem_slot = MigrateMemSlot {
                slot: slot.slot,
                guest_phys_addr: slot.guest_phys_addr,
                userspace_addr: slot.userspace_addr,
                memory_size: slot.memory_size,
            };
            mgt_mem_slots.insert(slot.slot, mem_slot);
        }
        Arc::new(Mutex::new(mgt_mem_slots))
    }

    /// Get dirty page bitmap in kvm.
    fn get_dirty_log(&self, slot: u32, mem_size: u64) -> Result<Vec<u64>> {
        self.vm_fd
            .as_ref()
            .unwrap()
            .get_dirty_log(slot, mem_size as usize)
            .with_context(|| {
                format!(
                    "Failed to get dirty log, error is {}",
                    std::io::Error::last_os_error()
                )
            })
    }

    /// Start dirty page tracking in kvm.
    fn start_dirty_log(&self) -> Result<()> {
        for (_, region) in self.mem_slots.lock().unwrap().iter_mut() {
            region.flags = KVM_MEM_LOG_DIRTY_PAGES;
            // SAFETY: region from `KvmHypervisor` is reliable.
            unsafe {
                self.vm_fd
                    .as_ref()
                    .unwrap()
                    .set_user_memory_region(*region)
                    .with_context(|| {
                        format!(
                            "Failed to start dirty log, error is {}",
                            std::io::Error::last_os_error()
                        )
                    })?;
            }
        }

        Ok(())
    }

    /// Stop dirty page tracking in kvm.
    fn stop_dirty_log(&self) -> Result<()> {
        for (_, region) in self.mem_slots.lock().unwrap().iter_mut() {
            region.flags = 0;
            // SAFETY: region from `KvmHypervisor` is reliable.
            unsafe {
                self.vm_fd
                    .as_ref()
                    .unwrap()
                    .set_user_memory_region(*region)
                    .with_context(|| {
                        format!(
                            "Failed to stop dirty log, error is {}",
                            std::io::Error::last_os_error()
                        )
                    })?;
            }
        }

        Ok(())
    }
}
