// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

pub mod proxy_client;

use std::{os::unix::net::UnixStream, sync::Arc, thread};

use anyhow::Result;
use log::{error, info};
use proxy_client::ProxyClient;
use vmm_sys_util::eventfd::EventFd;

pub struct IppProxyManager {
    pub state_stream: UnixStream,
    pub data_stream: UnixStream,
    pub spool_dir: String,
    pub exit_evt: Arc<EventFd>,
}

impl IppProxyManager {
    pub fn new(
        state_stream: UnixStream,
        data_stream: UnixStream,
        spool_dir: String,
        exit_evt: Arc<EventFd>,
    ) -> Self {
        Self {
            state_stream,
            data_stream,
            spool_dir,
            exit_evt,
        }
    }

    pub fn realize(&mut self) -> Result<()> {
        let ipp_proxy_manager = self.try_clone()?;
        if let Err(e) = thread::Builder::new()
            .name("ipp-proxy-manager".to_string())
            .spawn(move || {
                ipp_proxy_manager_run(ipp_proxy_manager);
            })
        {
            error!(
                "failed to start ipp-proxy-manager thread with error {:?}",
                e
            );
        }
        Ok(())
    }

    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            state_stream: self.state_stream.try_clone()?,
            data_stream: self.data_stream.try_clone()?,
            spool_dir: self.spool_dir.clone(),
            exit_evt: self.exit_evt.clone(),
        })
    }
}

fn ipp_proxy_manager_run(ipp_proxy_manager: IppProxyManager) {
    let IppProxyManager {
        state_stream,
        data_stream,
        spool_dir,
        exit_evt,
    } = ipp_proxy_manager;
    let mut proxy_client = match ProxyClient::new(state_stream, data_stream, &spool_dir, exit_evt) {
        Ok(proxy_client) => proxy_client,
        Err(e) => {
            error!("ipp_proxy_manager: error initializing proxy: {:?}", e);
            return;
        }
    };

    match proxy_client.run() {
        Ok(ret) => {
            info!("ipp-proxy-manager: ProxyClient stopped with ret {:?}", ret);
        }
        Err(ref e) => {
            error!("ipp-proxy-manager: Error at ProxyClient::run(): {e}");
        }
    }
}
