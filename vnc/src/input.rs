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

use crate::VncClient;

impl VncClient {
    // Keyboard event.
    pub fn key_envent(&mut self) {
        if self.expect == 1 {
            self.expect = 8;
            return;
        }

        self.update_event_handler(1, VncClient::handle_protocol_msg);
    }

    // Mouse event.
    pub fn point_event(&mut self) {
        if self.expect == 1 {
            self.expect = 6;
            return;
        }

        self.update_event_handler(1, VncClient::handle_protocol_msg);
    }

    // Client cut text.
    pub fn client_cut_event(&mut self) {
        let buf = self.buffpool.read_front(self.expect);
        if self.expect == 1 {
            self.expect = 8;
            return;
        }
        if self.expect == 8 {
            let buf = [buf[4], buf[5], buf[6], buf[7]];
            let len = u32::from_be_bytes(buf);
            if len > 0 {
                self.expect += len as usize;
                return;
            }
        }

        self.update_event_handler(1, VncClient::handle_protocol_msg);
    }
}
