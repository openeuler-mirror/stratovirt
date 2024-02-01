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

#[cfg(target_arch = "aarch64")]
use crate::aarch64::micro::{arch_ioctl_allow_list, arch_syscall_whitelist};
#[cfg(target_arch = "x86_64")]
use crate::x86_64::micro::{arch_ioctl_allow_list, arch_syscall_whitelist};
use hypervisor::kvm::*;
use util::seccomp::{BpfRule, SeccompCmpOpt};
use util::tap::{TUNGETFEATURES, TUNSETIFF, TUNSETOFFLOAD, TUNSETQUEUE, TUNSETVNETHDRSZ};
use virtio::VhostKern::*;

/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/futex.h
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_CMP_REQUEUE: u32 = 4;
const FUTEX_WAKE_OP: u32 = 5;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_PRIVATE_FLAG: u32 = 128;
#[cfg(target_env = "gnu")]
const FUTEX_CLOCK_REALTIME: u32 = 256;
const FUTEX_WAIT_PRIVATE: u32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: u32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
const FUTEX_CMP_REQUEUE_PRIVATE: u32 = FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_OP_PRIVATE: u32 = FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG;
const FUTEX_WAIT_BITSET_PRIVATE: u32 = FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG;

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/asm-generic/ioctls.h
const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TIOCGWINSZ: u32 = 0x5413;
const FIOCLEX: u32 = 0x5451;
const FIONBIO: u32 = 0x5421;
const KVM_RUN: u32 = 0xae80;

/// Create a syscall whitelist for seccomp.
///
/// # Notes
///
/// To reduce performance losses, the syscall rules is ordered by frequency.
pub fn syscall_whitelist() -> Vec<BpfRule> {
    let mut syscall = vec![
        BpfRule::new(libc::SYS_read),
        BpfRule::new(libc::SYS_readv),
        BpfRule::new(libc::SYS_write),
        BpfRule::new(libc::SYS_writev),
        ioctl_allow_list(),
        BpfRule::new(libc::SYS_io_getevents),
        BpfRule::new(libc::SYS_io_submit),
        BpfRule::new(libc::SYS_io_destroy),
        BpfRule::new(libc::SYS_io_uring_enter),
        BpfRule::new(libc::SYS_io_uring_setup),
        BpfRule::new(libc::SYS_io_uring_register),
        BpfRule::new(libc::SYS_dup),
        BpfRule::new(libc::SYS_close),
        BpfRule::new(libc::SYS_eventfd2),
        BpfRule::new(libc::SYS_epoll_ctl),
        BpfRule::new(libc::SYS_fdatasync),
        BpfRule::new(libc::SYS_recvmsg),
        BpfRule::new(libc::SYS_sendmsg),
        BpfRule::new(libc::SYS_sendto),
        BpfRule::new(libc::SYS_recvfrom),
        BpfRule::new(libc::SYS_mremap),
        BpfRule::new(libc::SYS_io_setup),
        BpfRule::new(libc::SYS_brk),
        BpfRule::new(libc::SYS_fcntl)
            .add_constraint(SeccompCmpOpt::Eq, 1, libc::F_DUPFD_CLOEXEC as u32)
            .add_constraint(SeccompCmpOpt::Eq, 1, libc::F_SETFD as u32)
            .add_constraint(SeccompCmpOpt::Eq, 1, libc::F_GETFD as u32)
            .add_constraint(SeccompCmpOpt::Eq, 1, libc::F_SETLK as u32),
        BpfRule::new(libc::SYS_flock),
        BpfRule::new(libc::SYS_rt_sigprocmask),
        BpfRule::new(libc::SYS_openat),
        BpfRule::new(libc::SYS_sigaltstack),
        BpfRule::new(libc::SYS_mmap),
        BpfRule::new(libc::SYS_munmap),
        BpfRule::new(libc::SYS_accept4),
        BpfRule::new(libc::SYS_lseek),
        futex_rule(),
        BpfRule::new(libc::SYS_exit),
        BpfRule::new(libc::SYS_exit_group),
        BpfRule::new(libc::SYS_rt_sigreturn),
        #[cfg(any(target_env = "musl", target_env = "ohos"))]
        BpfRule::new(libc::SYS_tkill),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_tgkill),
        BpfRule::new(libc::SYS_gettid),
        BpfRule::new(libc::SYS_getpid),
        BpfRule::new(libc::SYS_fstat),
        BpfRule::new(libc::SYS_pread64),
        BpfRule::new(libc::SYS_preadv),
        BpfRule::new(libc::SYS_pwrite64),
        BpfRule::new(libc::SYS_pwritev),
        BpfRule::new(libc::SYS_statx),
        BpfRule::new(libc::SYS_renameat),
        BpfRule::new(libc::SYS_getrandom),
        BpfRule::new(libc::SYS_fallocate),
        BpfRule::new(libc::SYS_socket),
        BpfRule::new(libc::SYS_mprotect),
        BpfRule::new(libc::SYS_ppoll),
        BpfRule::new(libc::SYS_connect),
        #[cfg(target_env = "gnu")]
        BpfRule::new(libc::SYS_clock_gettime),
        madvise_rule(),
    ];
    syscall.append(&mut arch_syscall_whitelist());

    syscall
}

/// Create a syscall bpf rule for syscall `ioctl`.
fn ioctl_allow_list() -> BpfRule {
    let bpf_rule = BpfRule::new(libc::SYS_ioctl)
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
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_GET_VRING_BASE() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_VRING_KICK() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_OWNER() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_FEATURES() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_SET_MEM_TABLE() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, VHOST_NET_SET_BACKEND() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, TUNGETFEATURES() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, TUNSETIFF() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, TUNSETOFFLOAD() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, TUNSETVNETHDRSZ() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, TUNSETQUEUE() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_API_VERSION() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_MP_STATE() as u32)
        .add_constraint(SeccompCmpOpt::Eq, 1, KVM_GET_VCPU_EVENTS() as u32);
    arch_ioctl_allow_list(bpf_rule)
}

fn madvise_rule() -> BpfRule {
    #[cfg(any(target_env = "musl", target_env = "ohos"))]
    return BpfRule::new(libc::SYS_madvise)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_FREE as u32)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_DONTNEED as u32)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_WILLNEED as u32)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_DONTDUMP as u32)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_REMOVE as u32);
    #[cfg(target_env = "gnu")]
    return BpfRule::new(libc::SYS_madvise)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_DONTNEED as u32)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_WILLNEED as u32)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_DONTDUMP as u32)
        .add_constraint(SeccompCmpOpt::Eq, 2, libc::MADV_REMOVE as u32);
}

fn futex_rule() -> BpfRule {
    #[cfg(any(target_env = "musl", target_env = "ohos"))]
    return BpfRule::new(libc::SYS_futex)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAKE_PRIVATE)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAIT_PRIVATE)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_CMP_REQUEUE_PRIVATE)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAKE_OP_PRIVATE)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAIT_BITSET_PRIVATE);
    #[cfg(target_env = "gnu")]
    return BpfRule::new(libc::SYS_futex)
        .add_constraint(
            SeccompCmpOpt::Eq,
            1,
            FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME,
        )
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAKE_PRIVATE)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAIT_PRIVATE)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_CMP_REQUEUE_PRIVATE)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAKE_OP_PRIVATE)
        .add_constraint(SeccompCmpOpt::Eq, 1, FUTEX_WAIT_BITSET_PRIVATE);
}
