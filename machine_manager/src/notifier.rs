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

static NOTIFIER_MANAGER: Lazy<RwLock<NotifierManager>> =
    Lazy::new(|| RwLock::new(NotifierManager::new()));

pub type PauseNOtifyCallback = dyn Fn(bool) + Send + Sync;

struct NotifierManager {
    pause_notifiers: HashMap<u64, Arc<PauseNOtifyCallback>>,
    next_id: u64,
}

impl NotifierManager {
    fn new() -> Self {
        Self {
            pause_notifiers: HashMap::new(),
            next_id: 1,
        }
    }

    fn register_pause_notifier(&mut self, notifier: Arc<PauseNOtifyCallback>) -> u64 {
        let id = self.next_id;
        self.pause_notifiers.insert(id, notifier);
        self.next_id += 1;
        id
    }

    fn unregister_pause_notifier(&mut self, id: u64) {
        if self.pause_notifiers.remove(&id).is_none() {
            error!("There is no pause notifier with id {}", id);
        }
    }

    fn pause_notify(&self, paused: bool) {
        for (_, notify) in self.pause_notifiers.iter() {
            notify(paused);
        }
    }
}

pub fn register_vm_pause_notifier(notifier: Arc<PauseNOtifyCallback>) -> u64 {
    NOTIFIER_MANAGER
        .write()
        .unwrap()
        .register_pause_notifier(notifier)
}

pub fn unregister_vm_pause_notifier(id: u64) {
    NOTIFIER_MANAGER
        .write()
        .unwrap()
        .unregister_pause_notifier(id)
}

pub fn pause_notify(paused: bool) {
    NOTIFIER_MANAGER.read().unwrap().pause_notify(paused);
}
