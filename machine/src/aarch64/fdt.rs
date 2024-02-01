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

use anyhow::Result;

use crate::MachineBase;
use cpu::PMU_INTR;
use devices::sysbus::{SysBusDevType, SysRes};
use util::device_tree::{self, FdtBuilder};

/// Function that helps to generate arm pmu in device-tree.
///
/// # Arguments
///
/// * `fdt` - Flatted device-tree blob where node will be filled into.
fn generate_pmu_node(fdt: &mut FdtBuilder) -> Result<()> {
    let node = "pmu";
    let pmu_node_dep = fdt.begin_node(node)?;
    fdt.set_property_string("compatible", "arm,armv8-pmuv3")?;
    fdt.set_property_u32("interrupt-parent", device_tree::GIC_PHANDLE)?;
    fdt.set_property_array_u32(
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_PPI,
            PMU_INTR,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ],
    )?;
    fdt.end_node(pmu_node_dep)
}

/// Function that helps to generate serial node in device-tree.
///
/// # Arguments
///
/// * `dev_info` - Device resource info of serial device.
/// * `fdt` - Flatted device-tree blob where serial node will be filled into.
fn generate_serial_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> Result<()> {
    let node = format!("pl011@{:x}", res.region_base);
    let serial_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "arm,pl011\0arm,primecell")?;
    fdt.set_property_string("clock-names", "uartclk\0apb_pclk")?;
    fdt.set_property_array_u32(
        "clocks",
        &[device_tree::CLK_PHANDLE, device_tree::CLK_PHANDLE],
    )?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.set_property_array_u32(
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_SPI,
            res.irq as u32,
            device_tree::IRQ_TYPE_EDGE_RISING,
        ],
    )?;
    fdt.end_node(serial_node_dep)
}

/// Function that helps to generate RTC node in device-tree.
///
/// # Arguments
///
/// * `dev_info` - Device resource info of RTC device.
/// * `fdt` - Flatted device-tree blob where RTC node will be filled into.
fn generate_rtc_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> Result<()> {
    let node = format!("pl031@{:x}", res.region_base);
    let rtc_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "arm,pl031\0arm,primecell\0")?;
    fdt.set_property_string("clock-names", "apb_pclk")?;
    fdt.set_property_u32("clocks", device_tree::CLK_PHANDLE)?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.set_property_array_u32(
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_SPI,
            res.irq as u32,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ],
    )?;
    fdt.end_node(rtc_node_dep)
}

/// Function that helps to generate Virtio-Mmio device's node in device-tree.
///
/// # Arguments
///
/// * `dev_info` - Device resource info of Virtio-Mmio device.
/// * `fdt` - Flatted device-tree blob where node will be filled into.
fn generate_virtio_devices_node(fdt: &mut FdtBuilder, res: &SysRes) -> Result<()> {
    let node = format!("virtio_mmio@{:x}", res.region_base);
    let virtio_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "virtio,mmio")?;
    fdt.set_property_u32("interrupt-parent", device_tree::GIC_PHANDLE)?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.set_property_array_u32(
        "interrupts",
        &[
            device_tree::GIC_FDT_IRQ_TYPE_SPI,
            res.irq as u32,
            device_tree::IRQ_TYPE_EDGE_RISING,
        ],
    )?;
    fdt.end_node(virtio_node_dep)
}

/// Function that helps to generate fw-cfg node in device-tree.
///
/// # Arguments
///
/// * `dev_info` - Device resource info of fw-cfg device.
/// * `fdt` - Flatted device-tree blob where fw-cfg node will be filled into.
fn generate_fwcfg_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> Result<()> {
    let node = format!("fw-cfg@{:x}", res.region_base);
    let fwcfg_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "qemu,fw-cfg-mmio")?;
    fdt.set_property_array_u64("reg", &[res.region_base, res.region_size])?;
    fdt.end_node(fwcfg_node_dep)
}

/// Function that helps to generate flash node in device-tree.
///
/// # Arguments
///
/// * `dev_info` - Device resource info of fw-cfg device.
/// * `flash` - Flatted device-tree blob where fw-cfg node will be filled into.
fn generate_flash_device_node(fdt: &mut FdtBuilder, res: &SysRes) -> Result<()> {
    let flash_base = res.region_base;
    let flash_size = res.region_size;
    let node = format!("flash@{:x}", flash_base);
    let flash_node_dep = fdt.begin_node(&node)?;
    fdt.set_property_string("compatible", "cfi-flash")?;
    fdt.set_property_array_u64(
        "reg",
        &[flash_base, flash_size, flash_base + flash_size, flash_size],
    )?;
    fdt.set_property_u32("bank-width", 4)?;
    fdt.end_node(flash_node_dep)
}

/// Trait that helps to generate all nodes in device-tree.
#[allow(clippy::upper_case_acronyms)]
trait CompileFDTHelper {
    /// Function that helps to generate cpu nodes.
    fn generate_cpu_nodes(&self, fdt: &mut FdtBuilder) -> Result<()>;
    /// Function that helps to generate Virtio-mmio devices' nodes.
    fn generate_devices_node(&self, fdt: &mut FdtBuilder) -> Result<()>;
    /// Function that helps to generate numa node distances.
    fn generate_distance_node(&self, fdt: &mut FdtBuilder) -> Result<()>;
}

impl CompileFDTHelper for MachineBase {
    fn generate_cpu_nodes(&self, fdt: &mut FdtBuilder) -> Result<()> {
        let node = "cpus";

        let cpus_node_dep = fdt.begin_node(node)?;
        fdt.set_property_u32("#address-cells", 0x02)?;
        fdt.set_property_u32("#size-cells", 0x0)?;

        // Generate CPU topology
        let cpu_map_node_dep = fdt.begin_node("cpu-map")?;
        for socket in 0..self.cpu_topo.sockets {
            let sock_name = format!("cluster{}", socket);
            let sock_node_dep = fdt.begin_node(&sock_name)?;
            for cluster in 0..self.cpu_topo.clusters {
                let clster = format!("cluster{}", cluster);
                let cluster_node_dep = fdt.begin_node(&clster)?;

                for core in 0..self.cpu_topo.cores {
                    let core_name = format!("core{}", core);
                    let core_node_dep = fdt.begin_node(&core_name)?;

                    for thread in 0..self.cpu_topo.threads {
                        let thread_name = format!("thread{}", thread);
                        let thread_node_dep = fdt.begin_node(&thread_name)?;
                        let vcpuid = self.cpu_topo.threads * self.cpu_topo.cores * cluster
                            + self.cpu_topo.threads * core
                            + thread;
                        fdt.set_property_u32(
                            "cpu",
                            u32::from(vcpuid) + device_tree::CPU_PHANDLE_START,
                        )?;
                        fdt.end_node(thread_node_dep)?;
                    }
                    fdt.end_node(core_node_dep)?;
                }
                fdt.end_node(cluster_node_dep)?;
            }
            fdt.end_node(sock_node_dep)?;
        }
        fdt.end_node(cpu_map_node_dep)?;

        for cpu_index in 0..self.cpu_topo.nrcpus {
            let mpidr = self.cpus[cpu_index as usize].arch().lock().unwrap().mpidr();

            let node = format!("cpu@{:x}", mpidr);
            let mpidr_node_dep = fdt.begin_node(&node)?;
            fdt.set_property_u32(
                "phandle",
                u32::from(cpu_index) + device_tree::CPU_PHANDLE_START,
            )?;
            fdt.set_property_string("device_type", "cpu")?;
            fdt.set_property_string("compatible", "arm,arm-v8")?;
            if self.cpu_topo.max_cpus > 1 {
                fdt.set_property_string("enable-method", "psci")?;
            }
            fdt.set_property_u64("reg", mpidr & 0x007F_FFFF)?;
            fdt.set_property_u32("phandle", device_tree::FIRST_VCPU_PHANDLE)?;

            if let Some(numa_nodes) = &self.numa_nodes {
                for numa_index in 0..numa_nodes.len() {
                    let numa_node = numa_nodes.get(&(numa_index as u32));
                    if numa_node.unwrap().cpus.contains(&(cpu_index)) {
                        fdt.set_property_u32("numa-node-id", numa_index as u32)?;
                    }
                }
            }

            fdt.end_node(mpidr_node_dep)?;
        }

        fdt.end_node(cpus_node_dep)?;

        if self.cpus[0].arch().lock().unwrap().get_features().pmu {
            generate_pmu_node(fdt)?;
        }

        Ok(())
    }

    fn generate_devices_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        // timer
        let mut cells: Vec<u32> = Vec::new();
        for &irq in [13, 14, 11, 10].iter() {
            cells.push(device_tree::GIC_FDT_IRQ_TYPE_PPI);
            cells.push(irq);
            cells.push(device_tree::IRQ_TYPE_LEVEL_HIGH);
        }
        let node = "timer";
        let timer_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("compatible", "arm,armv8-timer")?;
        fdt.set_property("always-on", &Vec::new())?;
        fdt.set_property_array_u32("interrupts", &cells)?;
        fdt.end_node(timer_node_dep)?;

        // clock
        let node = "apb-pclk";
        let clock_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("compatible", "fixed-clock")?;
        fdt.set_property_string("clock-output-names", "clk24mhz")?;
        fdt.set_property_u32("#clock-cells", 0x0)?;
        fdt.set_property_u32("clock-frequency", 24_000_000)?;
        fdt.set_property_u32("phandle", device_tree::CLK_PHANDLE)?;
        fdt.end_node(clock_node_dep)?;

        // psci
        let node = "psci";
        let psci_node_dep = fdt.begin_node(node)?;
        fdt.set_property_string("compatible", "arm,psci-0.2")?;
        fdt.set_property_string("method", "hvc")?;
        fdt.end_node(psci_node_dep)?;

        let mut pflash_cnt = 0;
        for dev in self.sysbus.devices.iter() {
            let locked_dev = dev.lock().unwrap();
            match locked_dev.sysbusdev_base().dev_type {
                SysBusDevType::PL011 => {
                    generate_serial_device_node(fdt, &locked_dev.sysbusdev_base().res)?
                }
                SysBusDevType::Rtc => {
                    generate_rtc_device_node(fdt, &locked_dev.sysbusdev_base().res)?
                }
                SysBusDevType::VirtioMmio => {
                    generate_virtio_devices_node(fdt, &locked_dev.sysbusdev_base().res)?
                }
                SysBusDevType::FwCfg => {
                    generate_fwcfg_device_node(fdt, &locked_dev.sysbusdev_base().res)?;
                }
                SysBusDevType::Flash => {
                    // Two pflash devices are created, but only one pflash node is required in the fdt table.
                    // Thereforce, the second pflash device needs to be skipped.
                    if pflash_cnt == 0 {
                        generate_flash_device_node(fdt, &locked_dev.sysbusdev_base().res)?;
                        pflash_cnt += 1;
                    }
                }
                _ => (),
            }
        }

        Ok(())
    }

    fn generate_distance_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        if self.numa_nodes.is_none() {
            return Ok(());
        }

        let distance_node_dep = fdt.begin_node("distance-map")?;
        fdt.set_property_string("compatible", "numa-distance-map-v1")?;

        let mut matrix = Vec::new();
        let numa_nodes = self.numa_nodes.as_ref().unwrap();
        let existing_nodes: Vec<u32> = numa_nodes.keys().cloned().collect();
        for (id, node) in numa_nodes.iter().enumerate() {
            let distances = &node.1.distances;
            for i in existing_nodes.iter() {
                matrix.push(id as u32);
                matrix.push(*i);
                let dist: u32 = if id as u32 == *i {
                    10
                } else if let Some(distance) = distances.get(i) {
                    *distance as u32
                } else {
                    20
                };
                matrix.push(dist);
            }
        }

        fdt.set_property_array_u32("distance-matrix", matrix.as_ref())?;
        fdt.end_node(distance_node_dep)
    }
}

impl device_tree::CompileFDT for MachineBase {
    fn generate_fdt_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        fdt.set_property_string("compatible", "linux,dummy-virt")?;
        fdt.set_property_u32("#address-cells", 0x2)?;
        fdt.set_property_u32("#size-cells", 0x2)?;
        fdt.set_property_u32("interrupt-parent", device_tree::GIC_PHANDLE)?;

        self.generate_cpu_nodes(fdt)?;
        self.generate_devices_node(fdt)?;
        self.irq_chip.as_ref().unwrap().generate_fdt_node(fdt)?;
        self.generate_distance_node(fdt)
    }
}
