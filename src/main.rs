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
mod device;
#[allow(dead_code)]
#[macro_use]
mod helper;
#[allow(dead_code)]
mod memory;

use std::path::PathBuf;
use std::sync::Arc;

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_pit_config, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::Kvm;

use crate::boot_loader::{load_kernel, BootLoader, BootLoaderConfig};
use crate::cpu::{CPUBootConfig, CPU};
use crate::device::Serial;
#[cfg(target_arch = "aarch64")]
use crate::device::{GICv3, MMIO_SERIAL_ADDR, MMIO_SERIAL_ADDR_SIZE, MMIO_SERIAL_IRQ};
#[cfg(target_arch = "aarch64")]
use crate::helper::device_tree;
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

    // 3. Init kvm_based devices.
    #[cfg(target_arch = "x86_64")]
    {
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
    }

    // 4. Init vCPU.
    let vcpu_count = 1_u32;
    let arc_memory = Arc::new(guest_memory);
    let mut vcpu = CPU::new(&vm_fd, arc_memory.clone(), 0, vcpu_count);

    // 5. load boot source and realize vCPU0.
    let cmdline = "console=ttyS0 panic=1 reboot=k root=/dev/ram rdinit=/bin/sh";
    #[cfg(target_arch = "aarch64")]
    let fdt_addr: u64;
    #[cfg(target_arch = "aarch64")]
    let initrd_range: (u64, u64);
    #[cfg(target_arch = "x86_64")]
    {
        let layout = load_boot_source(&arc_memory, cmdline);
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
        vcpu.realize(&vm_fd, cpu_boot_cfg);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let layout = load_boot_source(&arc_memory);
        let cpu_boot_cfg = CPUBootConfig {
            fdt_addr: layout.dtb_start,
            kernel_addr: layout.kernel_start,
        };
        vcpu.realize(&vm_fd, cpu_boot_cfg);
        fdt_addr = layout.dtb_start;
        initrd_range = (layout.initrd_start, layout.initrd_size);
    }

    // 6. On aarch64 platform, interrupt controller has to be created after vCPU is created.
    #[cfg(target_arch = "aarch64")]
    let gic = GICv3::new(&vm_fd, vcpu_count as u64, 192).expect("Failed to create GICv3 device");
    #[cfg(target_arch = "aarch64")]
    gic.realize().expect("Failed to realize GICv3 device");

    // 7. Initialize serial device.
    let serial = Serial::new(&vm_fd);
    vcpu.set_serial_dev(serial);

    // 8. generate device tree.
    #[cfg(target_arch = "aarch64")]
    generate_fdt(
        &arc_memory,
        &gic,
        initrd_range,
        cmdline,
        &mut vcpu,
        fdt_addr,
    );

    // 9. Run vCPU0.
    let cpu_task_0 = CPU::start(Arc::new(vcpu));
    println!("Start to run linux kernel!");
    cpu_task_0.join().expect("Failed to wait cpu task 0");
}

#[cfg(target_arch = "x86_64")]
fn load_boot_source(guest_memory: &Arc<GuestMemory>, cmdline: &str) -> BootLoader {
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
        kernel_cmdline: cmdline.to_string(),
        cpu_count: 1_u8,
        gap_range: (gap_start, gap_end - gap_start),
        ioapic_addr: MEM_LAYOUT[LayoutEntryType::IoApic as usize].0 as u32,
        lapic_addr: MEM_LAYOUT[LayoutEntryType::LocalApic as usize].0 as u32,
    };
    load_kernel(&boot_cfg, &guest_memory)
}

#[cfg(target_arch = "aarch64")]
fn load_boot_source(guest_memory: &Arc<GuestMemory>) -> BootLoader {
    let initrd_path = PathBuf::from("/tmp/initrd.img");
    let boot_cfg = BootLoaderConfig {
        kernel: PathBuf::from("/tmp/vmlinux.bin"),
        initrd: initrd_path,
        mem_start: MEM_LAYOUT[LayoutEntryType::Mem as usize].0,
    };
    load_kernel(&boot_cfg, &guest_memory)
}

#[cfg(target_arch = "aarch64")]
fn generate_fdt(
    sys_mem: &Arc<GuestMemory>,
    gic: &GICv3,
    initrd_range: (u64, u64),
    cmdline: &str,
    cpu: &mut CPU,
    fdt_addr: u64,
) {
    let mut fdt = vec![0; device_tree::FDT_MAX_SIZE as usize];

    device_tree::create_device_tree(&mut fdt);
    device_tree::set_property_string(&mut fdt, "/", "compatible", "linux,dummy-virt");
    device_tree::set_property_u32(&mut fdt, "/", "#address-cells", 0x2);
    device_tree::set_property_u32(&mut fdt, "/", "#size-cells", 0x2);
    device_tree::set_property_u32(&mut fdt, "/", "interrupt-parent", device_tree::GIC_PHANDLE);

    generate_cpu_node(&mut fdt, cpu);
    generate_memory_node(&mut fdt, sys_mem);
    generate_devices_node(&mut fdt);
    generate_chosen_node(&mut fdt, cmdline, initrd_range.0, initrd_range.1);
    gic.generate_fdt_node(&mut fdt);

    let fdt_len = fdt.len() as u64;
    sys_mem
        .write(&mut fdt.as_slice(), fdt_addr, fdt_len)
        .expect("Failed to load fdt to memory");

    device_tree::dump_dtb(&fdt, "/tmp/stratovirt.dtb");
}

#[cfg(target_arch = "aarch64")]
fn generate_memory_node(fdt: &mut Vec<u8>, sys_mem: &Arc<GuestMemory>) {
    let mem_base = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
    let mem_size = sys_mem.memory_end_address() - MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
    let node = "/memory";
    device_tree::add_sub_node(fdt, node);
    device_tree::set_property_string(fdt, node, "device_type", "memory");
    device_tree::set_property_array_u64(fdt, node, "reg", &[mem_base, mem_size as u64]);
}

#[cfg(target_arch = "aarch64")]
fn generate_cpu_node(fdt: &mut Vec<u8>, cpu: &mut CPU) {
    let node = "/cpus";
    device_tree::add_sub_node(fdt, node);
    device_tree::set_property_u32(fdt, node, "#address-cells", 0x02);
    device_tree::set_property_u32(fdt, node, "#size-cells", 0x0);

    let mpidr = cpu.state.get_mpidr(&cpu.fd);
    let node = format!("/cpus/cpu@{:x}", mpidr);
    device_tree::add_sub_node(fdt, &node);
    device_tree::set_property_u32(
        fdt,
        &node,
        "phandle",
        u32::from(cpu.id) + device_tree::CPU_PHANDLE_START,
    );
    device_tree::set_property_string(fdt, &node, "device_type", "cpu");
    device_tree::set_property_string(fdt, &node, "compatible", "arm,arm-v8");
    device_tree::set_property_u64(fdt, &node, "reg", mpidr & 0x007F_FFFF);
}

#[cfg(target_arch = "aarch64")]
fn generate_devices_node(fdt: &mut Vec<u8>) {
    // timer
    let mut cells: Vec<u32> = Vec::new();
    for &irq in [13, 14, 11, 10].iter() {
        cells.push(device_tree::GIC_FDT_IRQ_TYPE_PPI);
        cells.push(irq);
        cells.push(device_tree::IRQ_TYPE_LEVEL_HIGH);
    }
    let node = "/timer";
    device_tree::add_sub_node(fdt, node);
    device_tree::set_property_string(fdt, node, "compatible", "arm,armv8-timer");
    device_tree::set_property(fdt, node, "always-on", None);
    device_tree::set_property_array_u32(fdt, node, "interrupts", &cells);
    // clock
    let node = "/apb-pclk";
    device_tree::add_sub_node(fdt, node);
    device_tree::set_property_string(fdt, node, "compatible", "fixed-clock");
    device_tree::set_property_string(fdt, node, "clock-output-names", "clk24mhz");
    device_tree::set_property_u32(fdt, node, "#clock-cells", 0x0);
    device_tree::set_property_u32(fdt, node, "clock-frequency", 24_000_000);
    device_tree::set_property_u32(fdt, node, "phandle", device_tree::CLK_PHANDLE);
    // psci
    let node = "/psci";
    device_tree::add_sub_node(fdt, node);
    device_tree::set_property_string(fdt, node, "compatible", "arm,psci-0.2");
    device_tree::set_property_string(fdt, node, "method", "hvc");
    // serial
    let node = format!("/uart@{:x}", MMIO_SERIAL_ADDR);
    device_tree::add_sub_node(fdt, &node);
    device_tree::set_property_string(fdt, &node, "compatible", "ns16550a");
    device_tree::set_property_string(fdt, &node, "clock-names", "apb_pclk");
    device_tree::set_property_u32(fdt, &node, "clocks", device_tree::CLK_PHANDLE);
    device_tree::set_property_array_u64(
        fdt,
        &node,
        "reg",
        &[MMIO_SERIAL_ADDR, MMIO_SERIAL_ADDR_SIZE],
    );
    device_tree::set_property_array_u32(
        fdt,
        &node,
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_SPI,
            MMIO_SERIAL_IRQ,
            device_tree::IRQ_TYPE_EDGE_RISING,
        ],
    );
}

#[cfg(target_arch = "aarch64")]
fn generate_chosen_node(fdt: &mut Vec<u8>, cmdline: &str, initrd_addr: u64, initrd_size: u64) {
    let node = "/chosen";
    device_tree::add_sub_node(fdt, node);
    device_tree::set_property_string(fdt, node, "bootargs", cmdline);
    device_tree::set_property_u64(fdt, node, "linux,initrd-start", initrd_addr);
    device_tree::set_property_u64(fdt, node, "linux,initrd-end", initrd_addr + initrd_size);
}
