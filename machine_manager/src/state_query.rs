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
use std::sync::{Arc, RwLock};

use log::error;
use once_cell::sync::Lazy;

static STATE_QUERY_MANAGER: Lazy<RwLock<StateQueryManager>> =
    Lazy::new(|| RwLock::new(StateQueryManager::new()));

pub type StateQueryCallback = dyn Fn() -> String + Send + Sync;

struct StateQueryManager {
    query_callbacks: HashMap<String, Arc<StateQueryCallback>>,
}

impl StateQueryManager {
    fn new() -> Self {
        Self {
            query_callbacks: HashMap::new(),
        }
    }

    fn register_query_callback(&mut self, key: String, callback: Arc<StateQueryCallback>) {
        self.query_callbacks.insert(key, callback);
    }

    fn unregister_query_callback(&mut self, key: &str) {
        if self.query_callbacks.remove(key).is_none() {
            error!("There is no query callback with key {}", key);
        }
    }

    fn query_workloads(&self) -> Vec<(String, String)> {
        self.query_callbacks
            .iter()
            .map(|(module, query)| (module.clone(), query()))
            .collect()
    }
}

pub fn register_state_query_callback(key: String, callback: Arc<StateQueryCallback>) {
    STATE_QUERY_MANAGER
        .write()
        .unwrap()
        .register_query_callback(key, callback);
}

pub fn unregister_state_query_callback(key: &str) {
    STATE_QUERY_MANAGER
        .write()
        .unwrap()
        .unregister_query_callback(key);
}

pub fn query_workloads() -> Vec<(String, String)> {
    STATE_QUERY_MANAGER.read().unwrap().query_workloads()
}
