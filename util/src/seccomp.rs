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

//! A seccomp-bpf crate.
//!
//! The crate to set bpf-filter to seccomp for process or thread.
//!
//! ## Design
//!
//! This crate offers support for:
//! 1. A quick way to set bpf-filter rules.
//! 2. Register bpf-filter rules to seccomp.
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`
//!
//! ## Examples
//!
//! A simple code to read 1024 bytes in a regular file.
//! ```no_run
//! use std::fs::File;
//! use std::io::Read;
//!
//! let mut f: File = File::open("/path/to/file").unwrap();
//! let mut buffer = [0u8; 1024];
//! f.read(&mut buffer).unwrap();
//! println!("{}", String::from_utf8_lossy(&buffer));
//! ```
//!
//! With seccomp to limit 1024 bytes read.
//!
//! ```should_panic
//! extern crate libc;
//!
//! use std::fs::File;
//! use std::io::Read;
//! use util::seccomp::*;
//!
//! let mut seccomp_filter = SyscallFilter::new(SeccompOpt::Trap);
//!
//! let nr_open = {
//!     #[cfg(target_arch = "x86_64")]
//!     let nr = libc::SYS_open;
//!     #[cfg(target_arch = "aarch64")]
//!     let nr = libc::SYS_openat;
//!     nr
//! };
//!
//! seccomp_filter.push(&mut BpfRule::new(nr_open));
//! seccomp_filter.push(&mut BpfRule::new(libc::SYS_fcntl));
//! seccomp_filter.push(&mut BpfRule::new(libc::SYS_read).add_constraint(
//!     SeccompCmpOpt::Ne,
//!     2,
//!     1024,
//! ));
//! seccomp_filter.push(&mut BpfRule::new(libc::SYS_write));
//! seccomp_filter.push(&mut BpfRule::new(libc::SYS_close));
//! seccomp_filter.push(&mut BpfRule::new(libc::SYS_sigaltstack));
//! seccomp_filter.push(&mut BpfRule::new(libc::SYS_munmap));
//! seccomp_filter.push(&mut BpfRule::new(libc::SYS_exit_group));
//! seccomp_filter.realize().unwrap();
//!
//! let mut f: File = File::open("/path/to/file").unwrap();
//! let mut buffer = [0u8; 1024];
//! f.read(&mut buffer).unwrap();
//! println!("{}", String::from_utf8_lossy(&buffer));
//! ```
//! This programe will be trapped.

use anyhow::{bail, Result};

use crate::offset_of;

// BPF Instruction classes
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L7
const BPF_LD: u16 = 0x00;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L12
const BPF_JMP: u16 = 0x05;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L13
const BPF_RET: u16 = 0x06;

// BPF ld/ldx fields
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L18
const BPF_W: u16 = 0x00;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L24
const BPF_ABS: u16 = 0x20;

// BPF alu/jmp fields
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L45
const BPF_JEQ: u16 = 0x10;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L46
const BPF_JGT: u16 = 0x20;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L47
const BPF_JGE: u16 = 0x30;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/bpf_common.h#L50
const BPF_K: u16 = 0x00;

/// BPF programs must return a 32-bit value.
///
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/seccomp.h#L33-40
const SECCOMP_RET_KILL: u32 = 0x0000_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/seccomp.h#L45
const SECCOMP_RET_MASK: u32 = 0x0000_ffff;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/seccomp.h#L16
const SECCOMP_MODE_FILTER: u32 = 1;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/seccomp.h#L21
const SECCOMP_FILETER_FLAG_TSYNC: u32 = 1;

/// System call convention as an AUDIT_ARCH_* value
#[cfg(target_arch = "x86_64")]
const EM_X86_64: u32 = 62;
#[cfg(target_arch = "aarch64")]
const EM_AARCH64: u32 = 183;
const __AUDIT_ATCH_64BIT: u32 = 0x8000_0000;
const __AUDIT_ARCH_LE: u32 = 0x4000_0000;
#[cfg(target_arch = "x86_64")]
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/audit.h#L413
const AUDIT_ARCH_X86_64: u32 = EM_X86_64 | __AUDIT_ATCH_64BIT | __AUDIT_ARCH_LE;
#[cfg(target_arch = "aarch64")]
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/audit.h#L376
const AUDIT_ARCH_AARCH64: u32 = EM_AARCH64 | __AUDIT_ATCH_64BIT | __AUDIT_ARCH_LE;

/// Compared operator in bpf filter rule.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SeccompCmpOpt {
    /// Equal.
    Eq,
    /// Not Equal.
    Ne,
    /// Greater than.
    Gt,
    /// Less than.
    Lt,
    /// Greater or equal.
    Ge,
    /// Less or equal.
    Le,
}

/// Operation defined to handle seccomp event.
///
/// # Notes
/// These operation one-to-one correspondence with BPF-filter return value:
/// `SECCOMP_RET_KILL_PROCESS`, `SECCOMP_RET_KILL_THREAD`, `SECCOMP_RET_TRAP`,
/// `SECCOMP_RET_ERRNO`, `SECCOMP_RET_TRACE`, `SECCOMP_RET_ALLOW`, `SECCOMP_RET_LOG`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SeccompOpt {
    /// Kill the task immediately.
    Kill,
    /// Disallow and force a SIGSYS.
    Trap,
    /// Returns an errno.
    Errno(u32),
    /// Pass to a tracer or disallow.
    Trace(u32),
    /// Allow.
    Allow,
    /// The syscall will be logged.
    Log,
}

impl From<SeccompOpt> for u32 {
    fn from(seccomp_opt: SeccompOpt) -> Self {
        match seccomp_opt {
            SeccompOpt::Kill => SECCOMP_RET_KILL,
            SeccompOpt::Trap => SECCOMP_RET_TRAP,
            SeccompOpt::Errno(x) => SECCOMP_RET_ERRNO | (x & SECCOMP_RET_MASK),
            SeccompOpt::Trace(x) => SECCOMP_RET_TRACE | (x & SECCOMP_RET_MASK),
            SeccompOpt::Allow => SECCOMP_RET_ALLOW,
            SeccompOpt::Log => SECCOMP_RET_LOG,
        }
    }
}

/// The format of BPF programe executes over.
///
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/seccomp.h#L56
#[repr(C, packed)]
struct SeccompData {
    /// System call number
    nr: i32,
    /// indicates system call convention as an AUDIT_ARCH_* value
    arch: u32,
    /// CPU IP
    instruction_pointer: u64,
    /// up to 6 system call arguments always stored as 64-bit values regardless
    /// of the architecture
    args: [u64; 6],
}

impl SeccompData {
    fn nr() -> u32 {
        offset_of!(SeccompData, nr) as u32
    }

    fn arch() -> u32 {
        offset_of!(SeccompData, arch) as u32
    }

    fn args(num: u32) -> u32 {
        let offset_of_u64 =
            offset_of!(SeccompData, args) - offset_of!(SeccompData, instruction_pointer);
        offset_of!(SeccompData, args) as u32 + num * offset_of_u64 as u32
    }
}

/// Filter block
///
/// See: `<https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/filter.h#L24>`
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SockFilter {
    /// Actual filter code
    code: u16,
    /// Jump true
    jt: u8,
    /// Jump false
    jf: u8,
    /// Generic multiuse field
    k: u32,
}

/// Required for SO_ATTACH_FILTER
///
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/filter.h#L31
#[repr(C)]
struct SockFProg {
    /// Number of filter blocks.
    len: u16,
    /// Point of SockFilter list.
    sock_filter: *const SockFilter,
}

#[inline(always)]
fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline(always)]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Validate the syscall's arch is correct.
fn validate_architecture() -> Vec<SockFilter> {
    vec![
        bpf_stmt(BPF_LD + BPF_W + BPF_ABS, SeccompData::arch()),
        #[cfg(target_arch = "x86_64")]
        bpf_jump(BPF_JMP + BPF_JEQ, AUDIT_ARCH_X86_64, 1, 0),
        #[cfg(target_arch = "aarch64")]
        bpf_jump(BPF_JMP + BPF_JEQ, AUDIT_ARCH_AARCH64, 1, 0),
        bpf_stmt(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    ]
}

/// Create a bpf-filter rule to get the syscall number from `SeccompData`.
fn examine_syscall() -> Vec<SockFilter> {
    vec![bpf_stmt(BPF_LD + BPF_W + BPF_ABS, SeccompData::nr())]
}

/// Create a bpf-filter rule for handle syscall undefined rule.
fn handle_process(opt: SeccompOpt) -> Vec<SockFilter> {
    vec![bpf_stmt(BPF_RET + BPF_K, opt.into())]
}

/// A wrapper structure of a list of bpf_filters for a syscall's rule.
#[derive(Debug)]
pub struct BpfRule {
    /// The staged rules to avoid jump offset overflow.
    staged_rules: Vec<SockFilter>,
    /// The first bpf_filter to compare syscall number.
    header_rule: SockFilter,
    /// The last args index.
    args_idx_last: Option<u32>,
    /// The inner rules to limit the arguments of syscall.
    inner_rules: Vec<SockFilter>,
    /// The last bpf_filter to allow syscall.
    tail_rule: SockFilter,
}

impl BpfRule {
    /// Create a new BpfRule to allow a syscall from a syscall number.
    ///
    /// # Arguments
    /// * `syscall_num` - the number of system call.
    pub fn new(syscall_num: i64) -> BpfRule {
        BpfRule {
            staged_rules: Vec::new(),
            header_rule: bpf_jump(BPF_JMP + BPF_JEQ + BPF_K, syscall_num as u32, 0, 1),
            args_idx_last: None,
            inner_rules: Vec::new(),
            tail_rule: bpf_stmt(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        }
    }

    /// Allow a syscall with arguments limitation in bpf-filter.
    ///
    /// # Arguments
    /// * `cmp` - Compare operator for given args_value and the raw args_value.
    /// * `args_idx` - The index number of system call's arguments.
    /// * `args_value` - The value of args_num you want to limit. This value used with `cmp`
    ///   together.
    pub fn add_constraint(mut self, cmp: SeccompCmpOpt, args_idx: u32, args_value: u32) -> BpfRule {
        if self.inner_rules.is_empty() {
            self.tail_rule = bpf_stmt(BPF_LD + BPF_W + BPF_ABS, SeccompData::nr());
        }

        let mut inner_append = Vec::new();

        // Reload new args if idx changes.
        if self.args_idx_last.ne(&Some(args_idx)) {
            // Create a bpf_filter to get args in `SeccompData`.
            let args_filter = bpf_stmt(BPF_LD + BPF_W + BPF_ABS, SeccompData::args(args_idx));
            inner_append.push(args_filter);
            self.args_idx_last = Some(args_idx);
        }

        // Create a bpf_filter to limit args in syscall.
        let constraint_filter = match cmp {
            SeccompCmpOpt::Eq => bpf_jump(BPF_JMP + BPF_JEQ + BPF_K, args_value, 0, 1),
            SeccompCmpOpt::Ne => bpf_jump(BPF_JMP + BPF_JEQ + BPF_K, args_value, 1, 0),
            SeccompCmpOpt::Ge => bpf_jump(BPF_JMP + BPF_JGE + BPF_K, args_value, 0, 1),
            SeccompCmpOpt::Gt => bpf_jump(BPF_JMP + BPF_JGT + BPF_K, args_value, 0, 1),
            SeccompCmpOpt::Le => bpf_jump(BPF_JMP + BPF_JGE + BPF_K, args_value, 1, 0),
            SeccompCmpOpt::Lt => bpf_jump(BPF_JMP + BPF_JGT + BPF_K, args_value, 1, 0),
        };
        inner_append.push(constraint_filter);
        inner_append.push(bpf_stmt(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));

        if !self.append(&mut inner_append) {
            self.start_new_session();
            self.add_constraint(cmp, args_idx, args_value)
        } else {
            self
        }
    }

    /// Change `BpfRules` to a list of `SockFilter`. It will be used when
    /// seccomp taking effect.
    fn as_vec(&self) -> Vec<SockFilter> {
        let mut bpf_filters = self.staged_rules.clone();
        bpf_filters.push(self.header_rule);
        bpf_filters.append(&mut self.inner_rules.clone());
        bpf_filters.push(self.tail_rule);
        bpf_filters
    }

    /// Stage current rules and start new session. Used when header rule jump
    /// is about to overflow.
    fn start_new_session(&mut self) {
        // Save current rules to staged.
        self.staged_rules.push(self.header_rule);
        self.staged_rules.append(&mut self.inner_rules);
        self.staged_rules.push(self.tail_rule);

        self.header_rule.jf = 1;
        self.args_idx_last = None;
    }

    /// Add bpf_filters to `inner_rules`.
    fn append(&mut self, bpf_filters: &mut Vec<SockFilter>) -> bool {
        let offset = bpf_filters.len() as u8;

        if let Some(jf_added) = self.header_rule.jf.checked_add(offset) {
            self.header_rule.jf = jf_added;
            self.inner_rules.append(bpf_filters);
            true
        } else {
            false
        }
    }
}

/// This structure to create, manage, realize a seccomp rule.
#[derive(Debug)]
pub struct SyscallFilter {
    /// A list of Bpf-filter.
    sock_filters: Vec<SockFilter>,
    /// Operation for all syscall call not in rules.
    opt: SeccompOpt,
}

impl SyscallFilter {
    /// Create a seccomp rule.
    ///
    /// # Arguments
    /// * `opt` - Operation for all syscall call not in rules.
    pub fn new(opt: SeccompOpt) -> SyscallFilter {
        let mut sock_filters = Vec::new();
        sock_filters.extend(validate_architecture());
        sock_filters.extend(examine_syscall());

        SyscallFilter { sock_filters, opt }
    }

    /// Add a list of Bpf-filter rules to seccomp.
    ///
    /// # Arguments
    /// * `bpf_rule` - The bpf syscall rule contains a list of Bpf-filters.
    ///
    /// # Notice
    /// The flow to add new bpf-filter rules to seccomp is irreversible after
    /// realized seccomp.
    pub fn push(&mut self, bpf_rule: &mut BpfRule) {
        self.sock_filters.append(&mut bpf_rule.as_vec());
    }

    /// Make seccomp take effect.
    ///
    /// # Notice
    /// After use this function, all rules in seccomp will take effect whatever
    /// this structure dropped or not. You can only use this function once in
    /// a thread. Otherwise you will get an error.
    pub fn realize(mut self) -> Result<()> {
        // Add opt as a bpf_filter to sock_filters.
        self.sock_filters.append(&mut handle_process(self.opt));

        let sock_bpf_vec = self.sock_filters;

        // This operation can guarantee seccomp make use for all users and subprocess.
        // SAFETY: All input parameters are constants.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            bail!("Seccomp: prctl(2) set no new privs failed.");
        }

        let prog = SockFProg {
            len: sock_bpf_vec.len() as u16,
            sock_filter: sock_bpf_vec.as_ptr(),
        };
        let bpf_prog_ptr = &prog as *const SockFProg;

        // Use seccomp(2) to make bpf rules take effect.
        // SAFETY: The pointer of bpf_prog_ptr can be guaranteed not null.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_MODE_FILTER,
                SECCOMP_FILETER_FLAG_TSYNC,
                bpf_prog_ptr,
            )
        };
        if ret != 0 {
            bail!("Seccomp: seccomp(2) set seccomp filter mode failed.");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable_syscall() {
        // a list of bpf_filter to allow `read` syscall and forbidden others
        // in x86_64.
        let bpf_vec = vec![
            // Load arch
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 4,
            },
            // Verify arch
            SockFilter {
                code: 0x15,
                jt: 1,
                jf: 0,
                #[cfg(target_arch = "x86_64")]
                k: 0xC000_003E,
                #[cfg(target_arch = "aarch64")]
                k: 0xC000_00B7,
            },
            // Ret kill
            SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // Load syscall nr
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // Verify syscall nr
            SockFilter {
                code: 0x15,
                jt: 0,
                jf: 1,
                #[cfg(target_arch = "x86_64")]
                k: 0,
                #[cfg(target_arch = "aarch64")]
                k: 63,
            },
            // Ret allow
            SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            },
        ];

        let mut seccomp_filter = SyscallFilter::new(SeccompOpt::Trap);
        seccomp_filter.push(&mut BpfRule::new(libc::SYS_read));

        assert_eq!(seccomp_filter.sock_filters, bpf_vec);
    }

    #[test]
    fn test_enable_syscall_extra() {
        // a list of bpf_filter to allow read `1024` bytes in x86_64 and
        // forbidden others
        let mut bpf_vec = vec![
            // Load arch
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 4,
            },
            // Verify arch
            SockFilter {
                code: 0x15,
                jt: 1,
                jf: 0,
                #[cfg(target_arch = "x86_64")]
                k: 0xC000_003E,
                #[cfg(target_arch = "aarch64")]
                k: 0xC000_00B7,
            },
            // Ret kill
            SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // Load syscall nr
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // Verify syscall nr
            SockFilter {
                code: 0x15,
                jt: 0,
                jf: 254,
                #[cfg(target_arch = "x86_64")]
                k: 0,
                #[cfg(target_arch = "aarch64")]
                k: 63,
            },
            // Load arg
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0x20,
            },
        ];
        for _ in 0..126 {
            bpf_vec.append(&mut vec![
                // Verify arg
                SockFilter {
                    code: 0x15,
                    jt: 0,
                    jf: 1,
                    k: 1024,
                },
                // Ret allow
                SockFilter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: 0x7fff_0000,
                },
            ]);
        }
        bpf_vec.push(
            // Load syscall nr
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
        );

        // Start new session.
        bpf_vec.append(&mut vec![
            // Verify syscall nr
            SockFilter {
                code: 0x15,
                jt: 0,
                jf: 150,
                #[cfg(target_arch = "x86_64")]
                k: 0,
                #[cfg(target_arch = "aarch64")]
                k: 63,
            },
            // Load arg
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0x20,
            },
        ]);
        for _ in 126..200 {
            bpf_vec.append(&mut vec![
                // Verify arg
                SockFilter {
                    code: 0x15,
                    jt: 0,
                    jf: 1,
                    k: 1024,
                },
                // Ret allow
                SockFilter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: 0x7fff_0000,
                },
            ]);
        }
        bpf_vec.push(
            // Load syscall nr
            SockFilter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
        );

        let mut seccomp_filter = SyscallFilter::new(SeccompOpt::Trap);
        let mut read_rules = BpfRule::new(libc::SYS_read);
        // Add enough constraint to verify that jump does not overflow.
        for _ in 0..200 {
            read_rules = read_rules.add_constraint(SeccompCmpOpt::Eq, 2, 1024);
        }
        seccomp_filter.push(&mut read_rules);

        assert_eq!(seccomp_filter.sock_filters, bpf_vec);
    }
}
