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

extern crate libc;

use crate::errors::Result;
use crate::virtio::vhost::kernel::*;
use util::seccomp::{BpfRule, SeccompCmpOpt, SeccompOpt, SyscallFilter};
use util::tap::{TUNSETIFF, TUNSETOFFLOAD, TUNSETVNETHDRSZ};

/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/futex.h
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_CMP_REQUEUE: u32 = 4;
const FUTEX_WAKE_OP: u32 = 5;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_PRIVATE_FLAG: u32 = 128;
const FUTEX_WAIT_PRIVATE: u32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: u32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
const FUTEX_CMP_REQUEUE_PRIVATE: u32 = FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_OP_PRIVATE: u32 = FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG;
const FUTEX_WAIT_BITSET_PRIVATE: u32 = FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG;

/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/fcntl.h
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_LINUX_SPECIFIC_BASE: u32 = 1024;
const F_DUPFD_CLOEXEC: u32 = F_LINUX_SPECIFIC_BASE + 6;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/ioctls.h
const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TIOCGWINSZ: u32 = 0x5413;
const FIOCLEX: u32 = 0x5451;
const FIONBIO: u32 = 0x5421;
const KVM_RUN: u32 = 0xae80;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/kvm.h
const KVM_SET_DEVICE_ATTR: u32 = 0x4018_aee1;

/// Create a syscall allowlist for seccomp.
///
/// # Notes
/// This allowlist limit syscall with:
/// * x86_64-unknown-gnu: 36 syscalls
/// * x86_64-unknown-musl: 36 syscalls
/// * aarch64-unknown-gnu: 38 syscalls
/// * aarch64-unknown-musl: 38 syscalls
/// To reduce performance losses, the syscall rules is ordered by frequency.
pub fn syscall_allow_list() -> Vec<BpfRule> {
    vec![
        BpfRule::new(libc::SYS_read),
        BpfRule::new(libc::SYS_write),
        ioctl_allow_list(),
        #[cfg(not(all(target_env = "gnu", target_arch = "x86_64")))]
        BpfRule::new(libc::SYS_epoll_pwait),
        #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
        BpfRule::new(libc::SYS_epoll_wait),
        BpfRule::new(libc::SYS_io_getevents),
        BpfRule::new(libc::SYS_io_submit),
        BpfRule::new(libc::SYS_dup),
        BpfRule::new(libc::SYS_close),
        BpfRule::new(libc::SYS_eventfd2),
        BpfRule::new(libc::SYS_epoll_ctl),
        BpfRule::new(libc::SYS_fdatasync),
        BpfRule::new(libc::SYS_recvmsg),
        BpfRule::new(libc::SYS_sendmsg),
        BpfRule::new(libc::SYS_recvfrom),
        BpfRule::new(libc::SYS_mremap),
        BpfRule::new(libc::SYS_io_setup),
        BpfRule::new(libc::SYS_brk),
        BpfRule::new(libc::SYS_fcntl)
            .add_constraint(SeccompCmpOpt::Eq, 1, F_DUPFD_CLOEXEC)
            .add_constraint(SeccompCmpOpt::Eq, 1, F_SETFD)
            .add_constraint(SeccompCmpOpt::Eq, 1, F_GETFD),
        BpfRule::new(libc::SYS_rt_sigprocmask),
        #[cfg(target_arch = "x86_64")]
        BpfRule::new(libc::SYS_open),
        #[cfg(target_arch = "aarch64")]
        BpfRule::new(libc::SYS_openat),
        BpfRule::new(libc::SYS_sigaltstack),
        BpfRule::new(libc::SYS_mmap),
        BpfRule::new(libc::SYS_munmap),
        BpfRule::new(libc::SYS_accept4),
        BpfRule::new(libc::SYS_lseek),
        BpfRule::new(libc::SYS_futex)
            .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAKE_PRIVATE)
            .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAIT_PRIVATE)
            .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_CMP_REQUEUE_PRIVATE)
            .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAKE_OP_PRIVATE)
            .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAIT_BITSET_PRIVATE),
        BpfRule::new(libc::SYS_exit),
        BpfRule::new(libc::SYS_exit_group),
        BpfRule::new(libc::SYS_rt_sigreturn),
        #[cfg(target_env = "musl")]
        BpfRule::new(libc::SYS_tkill),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_tgkill),
        BpfRule::new(libc::SYS_gettid),
        BpfRule::new(libc::SYS_getpid),
        BpfRule::new(libc::SYS_fstat),
        #[cfg(target_arch = "aarch64")]
        BpfRule::new(libc::SYS_pread64),
        #[cfg(target_arch = "aarch64")]
        BpfRule::new(libc::SYS_pwrite64),
        BpfRule::new(libc::SYS_statx),
        #[cfg(target_arch = "x86_64")]
        BpfRule::new(libc::SYS_unlink),
        #[cfg(target_arch = "aarch64")]
        BpfRule::new(libc::SYS_unlinkat),
        BpfRule::new(libc::SYS_madvise)
            .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_DONTNEED as u32)
            .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_WILLNEED as u32),
    ]
}

/// Create a syscall bpf rule for syscall `ioctl`.
fn ioctl_allow_list() -> BpfRule {
    BpfRule::new(libc::SYS_ioctl)
        .add_constraint(SeccompCmpOpt::Eq, 1, TCGETS)
        .add_constraint(SeccompCmpOpt::Eq, 1, TCSETS)
        .add_constraint(SeccompCmpOpt::Eq, 1, TIOCGWINSZ)
        .add_constraint(SeccompCmpOpt::Eq, 1, FIOCLEX)
        .add_constraint(SeccompCmpOpt::Eq, 1, FIONBIO)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_RUN)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_SET_DEVICE_ATTR)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_VSOCK_SET_GUEST_CID() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_VSOCK_SET_RUNNING() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_VRING_CALL() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_VRING_NUM() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_VRING_ADDR() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_VRING_BASE() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_VRING_KICK() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_VRING_CALL() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_OWNER() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_FEATURES() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_MEM_TABLE() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_NET_SET_BACKEND() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, TUNSETIFF() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, TUNSETOFFLOAD() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, TUNSETVNETHDRSZ() as u32)
}

/// Register seccomp rules in syscall allowlist to seccomp.
pub fn register_seccomp(bpf_rules: Vec<BpfRule>) -> Result<()> {
    let mut seccomp_filter = SyscallFilter::new(SeccompOpt::Trap);

    for mut bpf_rule in bpf_rules {
        seccomp_filter.push(&mut bpf_rule);
    }

    seccomp_filter.realize()?;

    Ok(())
}
