# StratoVirt Design

## Overview 

StratoVirt is an open-source lightweight virtualization technology based on a Linux kernel-based virtual machine (kernel-based virtual machine, KVM). 
StratoVirt reduces memory resource consumption and improves a VM startup speed while retaining an isolation capability and a security capability of traditional virtualization. 
StratoVirt capplies to microservices or serverless scenarios such as function computing and paravirtualization devices, such as GIC, serial, RTC, and virtio devices.
StratoVirt reserved interface and design for importing more feature, even standard virtualization support.

## Features 

- High isolation based on hardware
- Fast cold boot：Benefit from the minimalist design, StratoVirt could boot a microVM in 50ms. 
- Low memory overhead：StratoVirt works with a memory footprint at 3MB. 
- IO enhancement: StratoVirt offers normal IO ability with minimalist IO device emulation. 
- OCI compatibility：StratoVirt offers OCI-compatible interface，which connects to Kubernetes ecosystem perfectly. 
- Multi-platform support: Full support for Intel and Arm platform. 
- Expansibility：StratoVirt reserved interface and design for importing more feature, even expend to standard virtualization support. 

## Architecture 

The following figure shows the StratoVirt core architecture, which consists of three layers from top to bottom. 

- OCI compatibility API: VM management interface. It uses the QMP protocol to communicate with external systems and is compatible with OCI.
- BootLoader: StratoVirt uses a simple BootLoader to load the kernel image, instead of the traditional cumbersome BIOS and Grub boot modes, to achieve fast boot. 
- MicroVM: MicroVM is introduced. To improve performance and reduce the attack surface, StratoVirt minimizes the simulation of user-mode devices. KVM simulation devices and paravirtualization devices, such as GIC, serial, RTC, and virtio devices, are used. 

![image](images/StratoVirt-arch.png) 

## Internal Implementation 

#### Running Architecture 

A StratoVirt VM is an independent process in Linux. The process has two types of threads: main thread and VCPU thread. The main thread is a cycle for processing asynchronous time and collects events from external systems. 
For example, a VCPU thread. Each VCPU has a thread, processes trap events of the VCPU. The other is the main thread for processing events. 



## Restrictions 

- Only the Linux operating system is supported. The kernel version is 4.19. 
- Only Linux is supported as the client operating system, and the kernel version is 4.19. 
- Supports a maximum of 254 CPUs. 
