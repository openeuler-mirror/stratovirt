// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{Context, Result};

use util::seccomp::{BpfRule, SeccompOpt, SyscallFilter};

fn syscall_whitelist() -> Vec<i64> {
    let mut v = vec![libc::SYS_accept4];
    v.push(libc::SYS_brk);
    v.push(libc::SYS_bind);
    v.push(libc::SYS_capget);
    v.push(libc::SYS_capset);
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_chmod);
    v.push(libc::SYS_clock_gettime);
    v.push(libc::SYS_clone);
    v.push(libc::SYS_clone3);
    v.push(libc::SYS_close);
    v.push(libc::SYS_copy_file_range);
    v.push(libc::SYS_dup);
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_epoll_create);
    v.push(libc::SYS_epoll_create1);
    v.push(libc::SYS_epoll_ctl);
    v.push(libc::SYS_epoll_pwait);
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_epoll_wait);
    v.push(libc::SYS_eventfd2);
    v.push(libc::SYS_exit);
    v.push(libc::SYS_exit_group);
    v.push(libc::SYS_fallocate);
    v.push(libc::SYS_fchdir);
    v.push(libc::SYS_fchmod);
    v.push(libc::SYS_fchmodat);
    v.push(libc::SYS_fchownat);
    v.push(libc::SYS_fcntl);
    v.push(libc::SYS_fdatasync);
    v.push(libc::SYS_fgetxattr);
    v.push(libc::SYS_flistxattr);
    v.push(libc::SYS_flock);
    v.push(libc::SYS_fremovexattr);
    v.push(libc::SYS_fsetxattr);
    v.push(libc::SYS_fstat);
    v.push(libc::SYS_fstatfs);
    v.push(libc::SYS_fsync);
    v.push(libc::SYS_ftruncate);
    v.push(libc::SYS_futex);
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_getdents);
    v.push(libc::SYS_getdents64);
    v.push(libc::SYS_getegid);
    v.push(libc::SYS_geteuid);
    v.push(libc::SYS_getpid);
    v.push(libc::SYS_getrandom);
    v.push(libc::SYS_gettid);
    v.push(libc::SYS_gettimeofday);
    v.push(libc::SYS_getxattr);
    v.push(libc::SYS_linkat);
    v.push(libc::SYS_listen);
    v.push(libc::SYS_listxattr);
    v.push(libc::SYS_lseek);
    v.push(libc::SYS_madvise);
    v.push(libc::SYS_mkdirat);
    v.push(libc::SYS_mknodat);
    v.push(libc::SYS_mmap);
    v.push(libc::SYS_mprotect);
    v.push(libc::SYS_mremap);
    v.push(libc::SYS_munmap);
    v.push(libc::SYS_name_to_handle_at);
    v.push(libc::SYS_newfstatat);
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_open);
    v.push(libc::SYS_openat);
    v.push(libc::SYS_open_by_handle_at);
    v.push(libc::SYS_prctl);
    v.push(libc::SYS_preadv);
    v.push(libc::SYS_pread64);
    v.push(libc::SYS_pwritev);
    v.push(libc::SYS_pwrite64);
    v.push(libc::SYS_read);
    v.push(libc::SYS_readlinkat);
    v.push(libc::SYS_recvmsg);
    v.push(libc::SYS_renameat);
    v.push(libc::SYS_renameat2);
    v.push(libc::SYS_removexattr);
    v.push(libc::SYS_rt_sigaction);
    v.push(libc::SYS_rt_sigprocmask);
    v.push(libc::SYS_rt_sigreturn);
    v.push(libc::SYS_sched_getaffinity);
    v.push(libc::SYS_sendmsg);
    v.push(libc::SYS_sendto);
    v.push(libc::SYS_setresgid);
    v.push(libc::SYS_setresuid);
    v.push(libc::SYS_set_robust_list);
    v.push(libc::SYS_setxattr);
    v.push(libc::SYS_sigaltstack);
    v.push(libc::SYS_socket);
    v.push(libc::SYS_statx);
    v.push(libc::SYS_symlinkat);
    v.push(libc::SYS_syncfs);
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_time);
    v.push(libc::SYS_tgkill);
    v.push(libc::SYS_umask);
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_unlink);
    v.push(libc::SYS_unlinkat);
    v.push(libc::SYS_unshare);
    v.push(libc::SYS_utimensat);
    v.push(libc::SYS_write);
    v.push(libc::SYS_writev);
    v
}

/// Enable seccomp to limit syscall.
///
/// # Arguments
///
/// * `action` - The default action.
pub fn seccomp_filter(action: SeccompOpt) -> Result<()> {
    let mut seccomp_filter = SyscallFilter::new(action);
    let allowed_syscalls = syscall_whitelist();
    for call in allowed_syscalls {
        seccomp_filter.push(&mut BpfRule::new(call));
    }
    seccomp_filter
        .realize()
        .with_context(|| "Failed to realize seccomp filter.")?;
    Ok(())
}

pub fn string_to_seccompopt(string: String) -> SeccompOpt {
    let str = string.as_str();
    match str {
        "kill" => SeccompOpt::Kill,
        "log" => SeccompOpt::Log,
        "trap" => SeccompOpt::Trap,
        "allow" => SeccompOpt::Allow,
        _ => SeccompOpt::Kill,
    }
}
