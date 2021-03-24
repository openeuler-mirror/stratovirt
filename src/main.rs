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

use std::io::Write;
use std::sync::Arc;

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::Kvm;
use kvm_ioctls::VcpuExit;

// Run a simple VM on x86_64 platfrom.
// Reference: https://lwn.net/Articles/658511/.
fn main() {
    let mem_size = 0x10000;
    let guest_addr = 0x1000;

    let asm_code: &[u8] = &[
        0xba, 0xf8, 0x03, // mov $0x3f8, %dx
        0x00, 0xd8, // add %bl, %al
        0x04, b'0', // add $'0', %al
        0xee, // out %al, (%dx)
        0xb0, b'\n', // mov $'\n', %al
        0xee,  // out %al, (%dx)
        0xf4,  // hlt
    ];

    // 1. Open /dev/kvm and create a VM.
    let kvm = Kvm::new().expect("Failed to open /dev/kvm");
    let vm_fd = Arc::new(kvm.create_vm().expect("Failed to create a vm"));

    // 2. Initialize Guest Memory.
    let host_addr: *mut u8 = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        ) as *mut u8
    };

    let kvm_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: guest_addr,
        memory_size: mem_size as u64,
        userspace_addr: host_addr as u64,
        flags: 0,
    };
    unsafe {
        vm_fd
            .set_user_memory_region(kvm_region)
            .expect("Failed to set memory region to KVM")
    };
    unsafe {
        let mut slice = std::slice::from_raw_parts_mut(host_addr, mem_size);
        slice
            .write_all(&asm_code)
            .expect("Failed to load asm code to memory");
    }

    // 3. Create vCPUs, and initialize registers.
    let vcpu_fd = vm_fd.create_vcpu(0).expect("Failed to create vCPU");
    #[cfg(target_arch = "x86_64")]
    {
        let mut vcpu_sregs = vcpu_fd
            .get_sregs()
            .expect("Failed to get special registers");
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu_fd
            .set_sregs(&vcpu_sregs)
            .expect("Failed to set special registers");

        let mut vcpu_regs = vcpu_fd
            .get_regs()
            .expect("Failed to get general purpose registers");
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu_fd
            .set_regs(&vcpu_regs)
            .expect("Failed to set general purpose registers");
    }

    // 4. Run vCPU.
    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::IoIn(addr, data) => {
                println!("VmExit IO in: addr 0x{:x}, data is {}", addr, data[0])
            }
            VcpuExit::IoOut(addr, data) => {
                println!("VmExit IO out: addr 0x{:x}, data is {}", addr, data[0])
            }
            VcpuExit::MmioRead(addr, _data) => println!("VmExit MMIO read: addr 0x{:x}", addr),
            VcpuExit::MmioWrite(addr, _data) => println!("VmExit MMIO write: addr 0x{:x}", addr),
            VcpuExit::Hlt => {
                println!("KVM_EXIT_HLT");
                break;
            }
            r => panic!("Unexpected exit reason: {:?}", r),
        }
    }
}
