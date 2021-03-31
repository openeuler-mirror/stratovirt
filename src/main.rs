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

mod cpu;
#[allow(dead_code)]
mod helper;
#[allow(dead_code)]
mod memory;

use std::sync::Arc;

use kvm_ioctls::Kvm;

use crate::cpu::CPU;
use crate::memory::GuestMemory;

// Run a simple VM on x86_64 platfrom.
// Reference: https://lwn.net/Articles/658511/.
fn main() {
    let mem_size = 0x4000;
    let guest_addr_01 = 0x1000;
    let guest_addr_02 = 0x2000;

    let asm_code: &[u8] = &[
        0xba, 0xf8, 0x03, // mov $0x3f8, %dx
        0x00, 0xd8, // add %bl, %al
        0x04, b'0', // add $'0', %al
        0xee, // out %al, (%dx)
        0xb0, b'\n', // mov $'\n', %al
        0xee,  // out %al, (%dx)
        0xf4,  // hlt
    ];

    let asm_mmio_code: &[u8] = &[
        0xc6, 0x06, 0x00, 0x80, 0x00, // movl $0, (0x8000); This generates a MMIO Write.
        0x8a, 0x16, 0x00, 0x80, // movl (0x8000), %dl; This generates a MMIO Read.
        0xf4, // hlt
    ];

    // 1. Open /dev/kvm and create a VM.
    let kvm = Kvm::new().expect("Failed to open /dev/kvm");
    let vm_fd = Arc::new(kvm.create_vm().expect("Failed to create a vm"));

    // 2. Initialize Guest Memory.
    let guest_memory = GuestMemory::new(&vm_fd, mem_size).expect("Failed to init guest memory");
    let asm_code_len = asm_code.len() as u64;
    let asm_mmio_code_len = asm_mmio_code.len() as u64;
    guest_memory
        .write(&mut asm_code[..].as_ref(), guest_addr_01, asm_code_len)
        .expect("Failed to load asm code to memory");
    guest_memory
        .write(
            &mut asm_mmio_code[..].as_ref(),
            guest_addr_02,
            asm_mmio_code_len,
        )
        .expect("Failed to load asm code to memory");

    // 3. Create vCPUs, and initialize registers.
    let mut vcpu_0 = CPU::new(&vm_fd, 0);
    let mut vcpu_1 = CPU::new(&vm_fd, 1);

    #[cfg(target_arch = "x86_64")]
    {
        vcpu_0.realize();
        vcpu_0.sregs.cs.base = 0;
        vcpu_0.sregs.cs.selector = 0;
        vcpu_0.regs.rip = guest_addr_01;
        vcpu_0.regs.rax = 2;
        vcpu_0.regs.rbx = 3;
        vcpu_0.regs.rflags = 2;

        vcpu_1.realize();
        vcpu_1.sregs.cs.base = 0;
        vcpu_1.sregs.cs.selector = 0;
        vcpu_1.regs.rip = guest_addr_02;
        vcpu_1.regs.rflags = 2;
    }

    // 4. Run vCPU.
    let cpu_task_0 = CPU::start(Arc::new(vcpu_0));
    let cpu_task_1 = CPU::start(Arc::new(vcpu_1));

    // Wait for task running over.
    cpu_task_0
        .join()
        .expect("Failed to join thread task for cpu 0");
    cpu_task_1
        .join()
        .expect("Failed to join thread task for cpu 1");
}
