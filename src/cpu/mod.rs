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

use std::sync::Arc;
use std::thread;

use kvm_bindings::{kvm_regs, kvm_sregs};
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};

pub struct CPU {
    /// ID of this virtual CPU, `0` means this cpu is primary `CPU`.
    pub id: u8,
    /// The file descriptor of this kvm_based vCPU.
    fd: VcpuFd,
    /// Common registers for kvm_based vCPU.
    pub regs: kvm_regs,
    /// Special registers for kvm_based vCPU.
    pub sregs: kvm_sregs,
}

impl CPU {
    /// Allocates a new `CPU` for `vm`
    ///
    /// # Arguments
    ///
    /// - `vcpu_id` - vcpu_id for `CPU`, started from `0`.
    pub fn new(vm_fd: &Arc<VmFd>, vcpu_id: u8) -> Self {
        let vcpu_fd = vm_fd.create_vcpu(vcpu_id).expect("Failed to create vCPU");

        Self {
            id: vcpu_id,
            fd: vcpu_fd,
            regs: kvm_regs::default(),
            sregs: kvm_sregs::default(),
        }
    }

    /// Realize vcpu status.
    /// Get register state from kvm.
    pub fn realize(&mut self) {
        self.regs = self.fd.get_regs().expect("Failed to get common registers");
        self.sregs = self
            .fd
            .get_sregs()
            .expect("Failed to get special registers")
    }

    /// Reset kvm_based vCPU registers state by registers state in `CPU`.
    pub fn reset(&self) {
        self.fd
            .set_regs(&self.regs)
            .expect("Failed to set common registers");
        self.fd
            .set_sregs(&self.sregs)
            .expect("Failed to set special registers");
    }

    /// Start run `CPU` in seperate vcpu thread.
    ///
    /// # Arguments
    ///
    /// - `arc_cpu`: `CPU` wrapper in `Arc` to send safely during thread.
    pub fn start(arc_cpu: Arc<CPU>) -> thread::JoinHandle<()> {
        let cpu_id = arc_cpu.id;
        thread::Builder::new()
            .name(format!("CPU {}/KVM", cpu_id))
            .spawn(move || {
                arc_cpu.reset();
                loop {
                    if !arc_cpu.kvm_vcpu_exec() {
                        break;
                    }
                }
            })
            .expect(&format!("Failed to create thread for CPU {}/KVM", cpu_id))
    }

    /// Run kvm vcpu emulation.
    ///
    /// # Return value
    ///
    /// Whether to continue to emulate or not.
    fn kvm_vcpu_exec(&self) -> bool {
        match self.fd.run().unwrap() {
            VcpuExit::IoIn(addr, data) => {
                println!(
                    "vCPU{} VmExit IO in: addr 0x{:x}, data is {}",
                    self.id, addr, data[0]
                )
            }
            VcpuExit::IoOut(addr, data) => {
                println!(
                    "vCPU{} VmExit IO out: addr 0x{:x}, data is {}",
                    self.id, addr, data[0]
                )
            }
            VcpuExit::MmioRead(addr, _data) => {
                println!("vCPU{} MMIO read: addr 0x{:x}", self.id, addr)
            }
            VcpuExit::MmioWrite(addr, _data) => {
                println!("vCPU{} VmExit MMIO write: addr 0x{:x}", self.id, addr)
            }
            VcpuExit::Hlt => {
                println!("KVM_EXIT_HLT");
                return false;
            }
            r => panic!("Unexpected exit reason: {:?}", r),
        }

        true
    }
}
