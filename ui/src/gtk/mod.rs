// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use crate::console::{DEFAULT_SURFACE_HEIGHT, DEFAULT_SURFACE_WIDTH};
use anyhow::{Context, Result};
use gtk::{
    prelude::{ApplicationExt, ApplicationExtManual},
    traits::WidgetExt,
    Application, ApplicationWindow,
};
use machine_manager::config::{DisplayConfig, UiContext};
use std::thread;

/// Gtk display init.
pub fn gtk_display_init(_ds_cfg: &DisplayConfig, _ui_context: UiContext) -> Result<()> {
    let args: Vec<String> = vec![];
    let _handle = thread::Builder::new()
        .name("gtk display".to_string())
        .spawn(move || create_gtk_thread(args))
        .with_context(|| "Fail to create gtk display thread!");
    Ok(())
}

/// Create a gtk thread.
pub fn create_gtk_thread(gtk_args: Vec<String>) {
    let application = Application::builder()
        .application_id("stratovirt.gtk")
        .build();
    application.connect_activate(build_ui);
    application.run_with_args(&gtk_args);
}

// Create window.
fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("Stratovirt")
        .default_width(DEFAULT_SURFACE_WIDTH)
        .default_height(DEFAULT_SURFACE_HEIGHT)
        .build();

    window.show_all();
}
