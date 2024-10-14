// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::vec;

use anyhow::{bail, Context, Result};

use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};
use oci_spec::linux::{Seccomp, SeccompAction as OciSeccompAction, SeccompOp};

use crate::utils::OzonecErr;

fn parse_action(action: OciSeccompAction, errno: Option<u32>) -> ScmpAction {
    let errno = errno.unwrap_or(libc::EPERM as u32);
    match action {
        OciSeccompAction::ScmpActKill => ScmpAction::KillThread,
        OciSeccompAction::ScmpActKillProcess => ScmpAction::KillProcess,
        OciSeccompAction::ScmpActTrap => ScmpAction::Trap,
        OciSeccompAction::ScmpActErrno => ScmpAction::Errno(errno as i32),
        OciSeccompAction::ScmpActTrace => ScmpAction::Trace(errno as u16),
        OciSeccompAction::ScmpActLog => ScmpAction::Log,
        OciSeccompAction::ScmpActAllow => ScmpAction::Allow,
        _ => ScmpAction::KillThread,
    }
}

fn parse_cmp(op: SeccompOp, mask: u64) -> ScmpCompareOp {
    match op {
        SeccompOp::ScmpCmpNe => ScmpCompareOp::NotEqual,
        SeccompOp::ScmpCmpLt => ScmpCompareOp::Less,
        SeccompOp::ScmpCmpLe => ScmpCompareOp::LessOrEqual,
        SeccompOp::ScmpCmpEq => ScmpCompareOp::Equal,
        SeccompOp::ScmpCmpGe => ScmpCompareOp::GreaterEqual,
        SeccompOp::ScmpCmpGt => ScmpCompareOp::Greater,
        SeccompOp::ScmpCmpMaskedEq => ScmpCompareOp::MaskedEqual(mask),
    }
}

fn check_seccomp(seccomp: &Seccomp) -> Result<()> {
    // We don't support NOTIFY as the default action. When the seccomp filter
    // is created with NOTIFY, the container process will have to communicate
    // the returned fd to another process. Therefore, ozonec needs to call
    // the WRITE syscall. And then READ and CLOSE syscalls are also needed to
    // be enabled to use.
    if seccomp.defaultAction == OciSeccompAction::ScmpActNotify {
        bail!("SCMP_ACT_NOTIFY is not supported as the default action");
    }
    if let Some(syscalls) = &seccomp.syscalls {
        for syscall in syscalls {
            if syscall.action == OciSeccompAction::ScmpActNotify {
                for name in &syscall.names {
                    if name == "write" {
                        bail!("SCMP_ACT_NOTIFY is not supported to be used for write syscall");
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn set_seccomp(seccomp: &Seccomp) -> Result<()> {
    check_seccomp(seccomp)?;

    let default_action = parse_action(seccomp.defaultAction, seccomp.defaultErrnoRet);
    if let Some(syscalls) = &seccomp.syscalls {
        let mut filter = ScmpFilterContext::new_filter(default_action)?;
        #[cfg(target_arch = "x86_64")]
        filter
            .add_arch(ScmpArch::X8664)
            .with_context(|| OzonecErr::AddScmpArch)?;
        #[cfg(target_arch = "aarch64")]
        filter
            .add_arch(ScmpArch::Aarch64)
            .with_context(|| OzonecErr::AddScmpArch)?;

        for syscall in syscalls {
            let action = parse_action(syscall.action, syscall.errnoRet);
            if action == default_action {
                continue;
            }

            for name in &syscall.names {
                let sc = ScmpSyscall::from_name(name)?;
                let mut comparators: Vec<ScmpArgCompare> = vec![];
                if let Some(args) = &syscall.args {
                    for arg in args {
                        let op = parse_cmp(arg.op, arg.value);
                        let cmp = match arg.op {
                            SeccompOp::ScmpCmpMaskedEq => {
                                ScmpArgCompare::new(arg.index as u32, op, arg.valueTwo.unwrap_or(0))
                            }
                            _ => ScmpArgCompare::new(arg.index as u32, op, arg.value),
                        };
                        comparators.push(cmp);
                    }
                }
                filter
                    .add_rule_conditional(action, sc, &comparators)
                    .with_context(|| "Failed to add conditional rule")?;
            }
        }
        filter
            .load()
            .with_context(|| "Failed to load filter into the kernel")?;
    }

    Ok(())
}
