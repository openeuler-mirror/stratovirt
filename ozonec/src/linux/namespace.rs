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

use std::collections::HashMap;

use anyhow::{Context, Result};
use nix::{
    fcntl::{self, OFlag},
    sched::{setns, unshare, CloneFlags},
    sys::stat::Mode,
    unistd,
};
use oci_spec::linux::{Namespace, NamespaceType};

pub struct NsController {
    pub namespaces: HashMap<CloneFlags, Namespace>,
}

impl TryFrom<Vec<Namespace>> for NsController {
    type Error = anyhow::Error;

    fn try_from(namespaces: Vec<Namespace>) -> Result<Self, Self::Error> {
        Ok(NsController {
            namespaces: namespaces
                .iter()
                .map(|ns| match ns.ns_type.try_into() {
                    Ok(flag) => Ok((flag, ns.clone())),
                    Err(e) => Err(e),
                })
                .collect::<Result<Vec<(CloneFlags, Namespace)>>>()?
                .into_iter()
                .collect(),
        })
    }
}

impl NsController {
    pub fn set_namespace(&self, ns_type: NamespaceType) -> Result<()> {
        if let Some(ns) = self.get(ns_type)? {
            match ns.path.clone() {
                Some(path) => {
                    let fd = fcntl::open(&path, OFlag::empty(), Mode::empty())
                        .with_context(|| format!("fcntl error at opening {}", path.display()))?;
                    setns(fd, ns_type.try_into()?).with_context(|| "Failed to setns")?;
                    unistd::close(fd).with_context(|| "Close fcntl fd error")?;
                }
                None => unshare(ns_type.try_into()?).with_context(|| "Failed to unshare")?,
            }
        }
        Ok(())
    }

    pub fn get(&self, ns_type: NamespaceType) -> Result<Option<&Namespace>> {
        let clone_flags: CloneFlags = ns_type.try_into()?;
        Ok(self.namespaces.get(&clone_flags))
    }
}

#[cfg(test)]
pub mod tests {
    use std::{path::PathBuf, thread::sleep, time::Duration};

    use nix::sys::{
        signal::{self, Signal},
        wait::{waitpid, WaitStatus},
    };

    use crate::linux::process::clone_process;

    use super::*;

    fn init_ns_controller(ns_type: NamespaceType) -> NsController {
        let mut ns_ctrl = NsController {
            namespaces: HashMap::new(),
        };
        let ns = Namespace {
            ns_type,
            path: None,
        };
        ns_ctrl.namespaces.insert(ns_type.try_into().unwrap(), ns);
        ns_ctrl
    }

    pub fn set_namespace(ns_type: NamespaceType) {
        let ns_ctrl = init_ns_controller(ns_type);
        ns_ctrl.set_namespace(ns_type).unwrap();
    }

    #[test]
    #[ignore = "unshare may not be permitted"]
    fn test_set_namespace() {
        let mut ns_ctrl = init_ns_controller(NamespaceType::Mount);
        let fst_child = clone_process("test_set_namespace_with_unshare", || {
            assert!(ns_ctrl.set_namespace(NamespaceType::Mount).is_ok());
            sleep(Duration::from_secs(10));
            Ok(1)
        })
        .unwrap();

        let ns_path = PathBuf::from(format!("/proc/{}/ns/mnt", fst_child.as_raw()));
        ns_ctrl
            .namespaces
            .get_mut(&CloneFlags::CLONE_NEWNS)
            .unwrap()
            .path = Some(ns_path);
        let sec_child = clone_process("test_set_namespace_with_setns", || {
            assert!(ns_ctrl.set_namespace(NamespaceType::Mount).is_ok());
            Ok(1)
        })
        .unwrap();

        match waitpid(sec_child, None) {
            Ok(WaitStatus::Exited(_, s)) => {
                assert_eq!(s, 1);
            }
            Ok(_) => (),
            Err(e) => {
                panic!("Failed to waitpid for unshare process: {e}");
            }
        }
        signal::kill(fst_child.clone(), Signal::SIGKILL).unwrap();
        match waitpid(fst_child, None) {
            Ok(WaitStatus::Exited(_, s)) => {
                assert_eq!(s, 1);
            }
            Ok(_) => (),
            Err(e) => {
                panic!("Failed to waitpid for setns process: {e}");
            }
        }
    }
}
