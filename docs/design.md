# StratoVirt Design

## Overview

StratoVirt is an open-source lightweight virtualization technology based on Linux Kernel-based Virtual Machine(KVM);
StratoVirt reduces memory resource consumption and improves VM startup speed while retains isolation capability and security capability of traditional virtualization; 
StratoVirt can be applied to microservices or serverless scenarios such as function computing;
StratoVirt reserves interface and design for importing more features, even standard virtualization;

## Architecture

The following figure shows StratoVirt's core architecture which consist of three layers from top to bottom;

- OCI compatibility API: StratoVirt uses the QMP protocol to communicate with external systems and is compatible with OCI;
- BootLoader: StratoVirt uses a simple BootLoader to load the kernel image, instead of the traditional cumbersome BIOS and Grub boot modes, to achieve fast boot;
- Lightweight: To improve performance and reduce the attack surface, StratoVirt minimizes the simulation of user-mode devices; KVM simulation devices and paravirtualization devices, such as GIC, serial, RTC and virtio devices, are used;

![image](images/StratoVirt-arch.png)

## Features

- High isolation ability based on hardware;
- Fast cold boot: Benefit from the minimalist design, StratoVirt could boot a microVM in 50ms;
- Low memory overhead: StratoVirt works with a memory footprint at 4MB;
- IO enhancement: StratoVirt offers normal IO ability with minimalist IO device emulation;
- OCI compatibility: StratoVirt works with isula and kata container, and can be integrated in Kubernetes ecosystem perfectly;
- Multi-platform support: Fully support for Intel and Arm platform;
- Expansibility: StratoVirt reserves interface and design for importing more features, even expand to standard virtualization support;
- Security: lower than 35 syscalls while running;

## Implementation

#### Running Architecture

- StratoVirt VM is an independent process in Linux. The process has two types of threads: main thread and VCPU thread;
    - The main thread is a cycle for asynchronous collecting and processing events from external modules, such as a VCPU thread;
    - Each VCPU has a thread to process trap events of this VCPU;

## Restrictions

- Only the Linux operating system is supported; The recommended kernel version is 4.19;
- Only Linux is supported as the client operating system, and the recommended kernel version is 4.19;
- StratoVirt is fullly tested on openEuler;
- Supports a maximum of 254 CPUs;

