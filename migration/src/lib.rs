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

//! # Migration
//!
//! Offer snapshot and migration interface for VM.

pub mod error;
pub mod general;
pub mod manager;
pub mod migration;
pub mod protocol;
pub mod snapshot;

pub use error::MigrationError;
pub use manager::{MigrationHook, MigrationManager};
pub use protocol::{DeviceStateDesc, FieldDesc, MemBlock, MigrationStatus, StateTransfer};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{net::TcpStream, os::unix::net::UnixStream, thread};

use anyhow::Result;
use log::error;

use machine_manager::qmp::{qmp_response::Response, qmp_schema};

#[derive(Default, Copy, Clone)]
pub struct MigrateMemSlot {
    /// number of a memory slot.
    pub slot: u32,
    /// Guest address.
    pub guest_phys_addr: u64,
    /// Host address.
    pub userspace_addr: u64,
    /// Size of memory.
    /// size = 0 represents no-region use this slot.
    pub memory_size: u64,
}

/// Start to snapshot VM.
///
/// # Arguments
///
/// * `path` - snapshot dir path. If path dir not exists, will create it.
pub fn snapshot(path: String) -> Response {
    if let Err(e) = MigrationManager::save_snapshot(&path) {
        error!("Failed to migrate to path \'{:?}\': {:?}", path, e);
        let _ = MigrationManager::set_status(MigrationStatus::Failed);
        return Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(e.to_string()),
            None,
        );
    }

    Response::create_empty_response()
}

/// Start to migrate VM with unix mode.
///
/// # Arguments
///
/// * `path` - Unix socket path, as /tmp/migration.socket.
pub fn migration_unix_mode(path: String) -> Response {
    let mut socket = match UnixStream::connect(path) {
        Ok(_sock) => {
            // Specify the tcp receiving or send timeout.
            let time_out = Some(Duration::from_secs(30));
            _sock
                .set_read_timeout(time_out)
                .unwrap_or_else(|e| error!("{:?}", e));
            _sock
                .set_write_timeout(time_out)
                .unwrap_or_else(|e| error!("{:?}", e));
            _sock
        }
        Err(e) => {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            )
        }
    };

    if let Err(e) = thread::Builder::new()
        .name("unix_migrate".to_string())
        .spawn(move || {
            if let Err(e) = MigrationManager::send_migration(&mut socket) {
                error!("Failed to send migration: {:?}", e);
                let _ = MigrationManager::recover_from_migration();
                let _ = MigrationManager::set_status(MigrationStatus::Failed)
                    .map_err(|e| error!("{:?}", e));
            }
        })
    {
        return Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(e.to_string()),
            None,
        );
    }

    Response::create_empty_response()
}

/// Start to migrate VM with tcp mode.
///
/// # Arguments
///
/// * `path` - Tcp ip and port, as 192.168.1.1:4446.
pub fn migration_tcp_mode(path: String) -> Response {
    let mut socket = match TcpStream::connect(path) {
        Ok(_sock) => {
            // Specify the tcp receiving or send timeout.
            let time_out = Some(Duration::from_secs(30));
            _sock
                .set_read_timeout(time_out)
                .unwrap_or_else(|e| error!("{:?}", e));
            _sock
                .set_write_timeout(time_out)
                .unwrap_or_else(|e| error!("{:?}", e));
            _sock
        }
        Err(e) => {
            return Response::create_error_response(
                qmp_schema::QmpErrorClass::GenericError(e.to_string()),
                None,
            )
        }
    };

    if let Err(e) = thread::Builder::new()
        .name("tcp_migrate".to_string())
        .spawn(move || {
            if let Err(e) = MigrationManager::send_migration(&mut socket) {
                error!("Failed to send migration: {:?}", e);
                let _ = MigrationManager::recover_from_migration();
                let _ = MigrationManager::set_status(MigrationStatus::Failed)
                    .map_err(|e| error!("{:?}", e));
            }
        })
    {
        return Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(e.to_string()),
            None,
        );
    };

    Response::create_empty_response()
}

/// Query the current migration status.
pub fn query_migrate() -> Response {
    let status_str = MigrationManager::status().to_string();
    let migration_info = qmp_schema::MigrationInfo {
        status: Some(status_str),
    };

    Response::create_response(serde_json::to_value(migration_info).unwrap(), None)
}

/// Cancel the current migration.
pub fn cancel_migrate() -> Response {
    if let Err(e) = MigrationManager::set_status(MigrationStatus::Canceled) {
        return Response::create_error_response(
            qmp_schema::QmpErrorClass::GenericError(e.to_string()),
            None,
        );
    }

    Response::create_empty_response()
}

pub trait MigrateOps: Send + Sync {
    fn get_mem_slots(&self) -> Arc<Mutex<HashMap<u32, MigrateMemSlot>>>;

    fn get_dirty_log(&self, _slot: u32, _mem_size: u64) -> Result<Vec<u64>>;

    fn start_dirty_log(&self) -> Result<()>;

    fn stop_dirty_log(&self) -> Result<()>;

    fn register_instance(&self) -> Result<()>;
}
