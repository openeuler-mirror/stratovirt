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

use std::{
    io::{stderr, stdin, stdout},
    os::fd::{AsRawFd, RawFd},
};

use oci_spec::process::Process as OciProcess;

pub struct Process {
    pub stdin: Option<RawFd>,
    pub stdout: Option<RawFd>,
    pub stderr: Option<RawFd>,
    pub term_master: Option<RawFd>,
    pub init: bool,
    pub tty: bool,
    pub oci: OciProcess,
}

impl Process {
    pub fn new(oci: &OciProcess, init: bool) -> Self {
        let mut p = Process {
            stdin: None,
            stdout: None,
            stderr: None,
            tty: oci.terminal,
            term_master: None,
            init,
            oci: oci.clone(),
        };

        if !p.tty {
            p.stdin = Some(stdin().as_raw_fd());
            p.stdout = Some(stdout().as_raw_fd());
            p.stderr = Some(stderr().as_raw_fd());
        }
        p
    }
}
