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

mod interrupt;
#[cfg(target_arch = "x86_64")]
mod state;

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use kvm_ioctls::{Kvm, VmFd};

pub use interrupt::MsiVector;

use crate::errors::{Result, ResultExt};
use interrupt::{refact_vec_with_field, IrqRoute, IrqRouteEntry, IrqRouteTable};

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct KVMFds {
    pub fd: Option<Kvm>,
    pub vm_fd: Option<VmFd>,
    pub irq_route_table: Mutex<IrqRouteTable>,
}

impl KVMFds {
    pub fn new() -> Self {
        let kvm_fds = match Kvm::new() {
            Ok(fd) => {
                let vm_fd = match fd.create_vm() {
                    Ok(vm_fd) => vm_fd,
                    Err(e) => {
                        error!("Failed to create VM in KVM: {}", e);
                        return KVMFds::default();
                    }
                };
                let irq_route_table = Mutex::new(IrqRouteTable::new(&fd));
                KVMFds {
                    fd: Some(fd),
                    vm_fd: Some(vm_fd),
                    irq_route_table,
                }
            }
            Err(e) => {
                error!("Failed to open /dev/kvm: {}", e);
                KVMFds::default()
            }
        };

        #[cfg(target_arch = "x86_64")]
        migration::MigrationManager::register_device_instance(
            state::KvmDeviceState::descriptor(),
            Arc::new(state::KvmDevice {}),
            false,
        );

        kvm_fds
    }

    /// Sets the gsi routing table entries. It will overwrite previously set entries.
    pub fn commit_irq_routing(&self) -> Result<()> {
        let routes = self.irq_route_table.lock().unwrap().irq_routes.clone();

        // Safe because data in `routes` is reliable.
        unsafe {
            let mut irq_routing = refact_vec_with_field::<IrqRoute, IrqRouteEntry>(routes.len());
            (*irq_routing).nr = routes.len() as u32;
            (*irq_routing).flags = 0;
            let entries: &mut [IrqRouteEntry] = (*irq_routing).entries.as_mut_slice(routes.len());
            entries.copy_from_slice(&routes);

            self.vm_fd
                .as_ref()
                .unwrap()
                .set_gsi_routing(&*irq_routing)
                .chain_err(|| "Failed to set gsi routing")?;
        }

        Ok(())
    }
}

lazy_static! {
    pub static ref KVM_FDS: ArcSwap<KVMFds> = ArcSwap::from(Arc::new(KVMFds::new()));
}
