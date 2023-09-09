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

//! This module implements a simple way to realize QMP.
//!
//! # Qmp Introduction
//!
//! [Qmp](https://wiki.qemu.org/Documentation/QMP) is a Json-based protocol
//! which allows applications to control a VM instance.
//! It has three feature:
//! 1. Qmp server is no-async service as well as Qemu's.
//! Command + events can replace asynchronous command.
//! 2. Qmp server can only be connected a client at one time.
//! It's no situation where be communicated with many clients.
//! When it must use, can use other communication way not QMP.
//! 3. Qmp's message structure base is transformed by scripts from Qemu's
//! `qmp-schema.json`. It's can be compatible by Qemu's zoology. Those
//! transformed structures can be found in `machine_manager/src/qmp/qmp_schema.rs`

pub mod qmp_channel;
pub mod qmp_response;
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod qmp_schema;
pub mod qmp_socket;
