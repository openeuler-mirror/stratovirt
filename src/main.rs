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

mod boot_loader;
mod cpu;
#[allow(dead_code)]
mod helper;
#[allow(dead_code)]
mod memory;

use std::path::PathBuf;
use std::sync::Arc;

use kvm_bindings::{kvm_pit_config, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::Kvm;

use crate::boot_loader::{load_kernel, BootLoaderConfig};
use crate::cpu::{CPUBootConfig, CPU};
use crate::memory::{GuestMemory, LayoutEntryType, MEM_LAYOUT};

// Run a simple VM on x86_64 platfrom.
// Reference: https://lwn.net/Articles/658511/.
fn main() {
    let mem_size = 512 * 1024 * 1024;

    // 1. Open /dev/kvm and create a VM.
    let kvm = Kvm::new().expect("Failed to open /dev/kvm");
    let vm_fd = Arc::new(kvm.create_vm().expect("Failed to create a vm"));

    // 2. Initialize Guest Memory.
    let guest_memory = GuestMemory::new(&vm_fd, mem_size).expect("Failed to init guest memory");

    // 3. Prepare boot source.
    let initrd_path = PathBuf::from("/tmp/initrd.img");
    let initrd_size = match std::fs::metadata("/tmp/initrd.img") {
        Ok(meta) => meta.len() as u32,
        _ => panic!("initrd file init failed!"),
    };
    let gap_start = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
        + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
    let gap_end = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
    let boot_cfg = BootLoaderConfig {
        kernel: PathBuf::from("/tmp/vmlinux.bin"),
        initrd: initrd_path,
        initrd_size,
        kernel_cmdline: String::from("console=ttyS0 panic=1 reboot=k root=/dev/ram rdinit=/bin/sh"),
        cpu_count: 1_u8,
        gap_range: (gap_start, gap_end - gap_start),
        ioapic_addr: MEM_LAYOUT[LayoutEntryType::IoApic as usize].0 as u32,
        lapic_addr: MEM_LAYOUT[LayoutEntryType::LocalApic as usize].0 as u32,
    };
    let layout = load_kernel(&boot_cfg, &guest_memory);
    let cpu_boot_cfg = CPUBootConfig {
        boot_ip: layout.kernel_start,
        boot_sp: layout.kernel_sp,
        zero_page: layout.zero_page_addr,
        code_segment: layout.segments.code_segment,
        data_segment: layout.segments.data_segment,
        gdt_base: layout.segments.gdt_base,
        gdt_size: layout.segments.gdt_limit,
        idt_base: layout.segments.idt_base,
        idt_size: layout.segments.idt_limit,
        pml4_start: layout.boot_pml4_addr,
    };

    // 4. Init kvm_based devices.
    vm_fd.create_irq_chip().expect("Failed to create irq chip.");
    vm_fd
        .set_tss_address(0xfffb_d000_usize)
        .expect("Failed to set tss address.");

    let pit_config = kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        pad: Default::default(),
    };
    vm_fd
        .create_pit2(pit_config)
        .expect("Failed to create pit2.");

    // 5. Init vCPU.
    let arc_memory = Arc::new(guest_memory);
    let mut vcpu = CPU::new(&vm_fd, arc_memory.clone(), 0, 1);

    vcpu.realize(cpu_boot_cfg);

    // 6. Run vcpu.
    let cpu_task_0 = CPU::start(Arc::new(vcpu));
    println!("Start to run linux kernel!");
    cpu_task_0.join().expect("Failed to wait cpu task 0");
}
