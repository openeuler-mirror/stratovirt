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
