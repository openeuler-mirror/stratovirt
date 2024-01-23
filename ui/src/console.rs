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

use std::{
    cmp,
    mem::size_of,
    ptr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use anyhow::Result;
use log::error;
use once_cell::sync::Lazy;

use crate::pixman::{
    create_pixman_image, get_image_data, get_image_height, get_image_stride, get_image_width,
    pixman_glyph_from_vgafont, pixman_glyph_render, unref_pixman_image, ColorNames,
    COLOR_TABLE_RGB,
};
use machine_manager::event_loop::EventLoop;
use util::pixman::{pixman_format_code_t, pixman_image_t};

static CONSOLES: Lazy<Arc<Mutex<ConsoleList>>> =
    Lazy::new(|| Arc::new(Mutex::new(ConsoleList::new())));
static DISPLAY_STATE: Lazy<Arc<Mutex<DisplayState>>> =
    Lazy::new(|| Arc::new(Mutex::new(DisplayState::new())));

/// Width of font.
const FONT_WIDTH: i32 = 8;
/// Height of font.
const FONT_HEIGHT: i32 = 16;
/// Width of image in surface.
pub const DEFAULT_SURFACE_WIDTH: i32 = 800;
/// Height of image in surface.
pub const DEFAULT_SURFACE_HEIGHT: i32 = 600;
/// Maximum default window width.
pub const MAX_WINDOW_WIDTH: u16 = 2560;
/// Maximum default window height.
pub const MAX_WINDOW_HEIGHT: u16 = 2048;

/// Minimum refresh interval in ms.
pub const DISPLAY_UPDATE_INTERVAL_DEFAULT: u64 = 30;
/// Update time interval dynamically.
pub const DISPLAY_UPDATE_INTERVAL_INC: u64 = 50;
/// Maximum refresh interval in ms.
pub const DISPLAY_UPDATE_INTERVAL_MAX: u64 = 3_000;

pub enum ConsoleType {
    Graphic,
    Text,
}

/// Run stage of virtual machine.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VmRunningStage {
    Init,
    Bios,
    Os,
}

#[derive(Default)]
struct UiInfo {
    last_width: u32,
    last_height: u32,
}

/// Image data defined in display.
#[derive(Clone, Copy)]
pub struct DisplaySurface {
    /// Image format.
    pub format: pixman_format_code_t,
    /// Pointer to image
    pub image: *mut pixman_image_t,
}

impl Default for DisplaySurface {
    fn default() -> Self {
        DisplaySurface {
            format: pixman_format_code_t::PIXMAN_a8r8g8b8,
            image: ptr::null_mut(),
        }
    }
}

impl DisplaySurface {
    pub fn width(&self) -> i32 {
        get_image_width(self.image)
    }

    pub fn height(&self) -> i32 {
        get_image_height(self.image)
    }

    pub fn stride(&self) -> i32 {
        get_image_stride(self.image)
    }

    pub fn data(&self) -> *mut u32 {
        get_image_data(self.image)
    }
}

/// Cursor data defined in Display.
/// hot_x and hot_y indicate the hotspot of the cursor.
/// width and height indicate the width of the cursor in pixel.
/// The data consists of the primary and secondary colours for
/// the cursor, followed by one bitmap for the colour and
/// one bitmask for the transparency.
#[derive(Clone, Default)]
pub struct DisplayMouse {
    pub width: u32,
    pub height: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub data: Vec<u8>,
}

impl DisplayMouse {
    pub fn new(width: u32, height: u32, hot_x: u32, hot_y: u32) -> Self {
        let data_size = (width * height) as usize * size_of::<u32>();
        DisplayMouse {
            width,
            height,
            hot_x,
            hot_y,
            data: vec![0_u8; data_size],
        }
    }
}

/// UIs (such as VNC) can register interfaces related to image display.
/// After the graphic hardware processes images, these interfaces can be
/// called to display images on the user's desktop.
pub trait DisplayChangeListenerOperations {
    /// Switch the image in display surface.
    fn dpy_switch(&self, _surface: &DisplaySurface) -> Result<()>;
    /// Refresh the image.
    fn dpy_refresh(&self, _dcl: &Arc<Mutex<DisplayChangeListener>>) -> Result<()>;
    /// Update image.
    fn dpy_image_update(&self, _x: i32, _y: i32, _w: i32, _h: i32) -> Result<()>;
    /// Update the cursor data.
    fn dpy_cursor_update(&self, _cursor: &DisplayMouse) -> Result<()>;
    /// Set the current display as major.
    fn dpy_set_major(&self) -> Result<()> {
        Ok(())
    }
}

/// Callback functions registered by graphic hardware.
pub trait HardWareOperations {
    /// Update image.
    fn hw_update(&self, _con: Arc<Mutex<DisplayConsole>>) {}
    /// Ui configuration changed.
    fn hw_ui_info(&self, _con: Arc<Mutex<DisplayConsole>>, _width: u32, _height: u32) {}
}

/// Listen to the change of image and call the related
/// interface to update the image on user's desktop.
pub struct DisplayChangeListener {
    pub con_id: Option<usize>,
    pub dcl_id: Option<usize>,
    pub active: bool,
    pub update_interval: u64,
    pub dpy_opts: Arc<dyn DisplayChangeListenerOperations>,
}

impl DisplayChangeListener {
    pub fn new(con_id: Option<usize>, dpy_opts: Arc<dyn DisplayChangeListenerOperations>) -> Self {
        Self {
            con_id,
            dcl_id: None,
            active: false,
            update_interval: 0,
            dpy_opts,
        }
    }
}

/// Graphic hardware can register a console during initialization
/// and store the information of images in this structure.
pub struct DisplayConsole {
    pub con_id: usize,
    pub dev_name: String,
    pub con_type: ConsoleType,
    pub width: i32,
    pub height: i32,
    ui_info: UiInfo,
    pub surface: Option<DisplaySurface>,
    pub console_list: Weak<Mutex<ConsoleList>>,
    pub dev_opts: Arc<dyn HardWareOperations>,
    pub timer_id: Option<u64>,
    pub active: bool,
}

impl DisplayConsole {
    pub fn new(
        con_id: usize,
        dev_name: String,
        con_type: ConsoleType,
        console_list: Weak<Mutex<ConsoleList>>,
        dev_opts: Arc<dyn HardWareOperations>,
    ) -> Self {
        Self {
            con_id,
            dev_name,
            con_type,
            width: 0,
            height: 0,
            ui_info: UiInfo::default(),
            console_list,
            surface: None,
            dev_opts,
            timer_id: None,
            active: true,
        }
    }
}

/// The state of console layer.
struct DisplayState {
    /// Running stage.
    run_stage: VmRunningStage,
    /// Refresh interval, which can be dynamic changed.
    interval: u64,
    /// Whether there is a refresh task.
    is_refresh: bool,
    /// A list of DisplayChangeListeners.
    listeners: Vec<Option<Arc<Mutex<DisplayChangeListener>>>>,
    /// Total number of refresh task.
    refresh_num: i32,
}

// SAFETY: The Arc<dyn ...> in rust doesn't impl Send, it will be delivered only once during
// initialization process, and only be saved in the single thread. So implement Send is safe.
unsafe impl Send for DisplayState {}

impl DisplayState {
    fn new() -> Self {
        Self {
            run_stage: VmRunningStage::Init,
            interval: DISPLAY_UPDATE_INTERVAL_DEFAULT,
            is_refresh: false,
            listeners: Vec::new(),
            refresh_num: 0,
        }
    }

    // Get all related display by con_id.
    fn get_related_display(&self, con_id: usize) -> Result<Vec<Arc<Mutex<DisplayChangeListener>>>> {
        let mut related_dpys: Vec<Arc<Mutex<DisplayChangeListener>>> = vec![];
        let active_id = CONSOLES.lock().unwrap().activate_id;
        for dcl in self.listeners.iter().flatten() {
            match dcl.lock().unwrap().con_id {
                Some(id) if con_id == id => {
                    related_dpys.push(dcl.clone());
                }
                None if Some(con_id) == active_id => {
                    related_dpys.push(dcl.clone());
                }
                _ => {}
            }
        }

        Ok(related_dpys)
    }
}

/// The registered console will be inserted in the console list.
/// If no console is specified, the activate console will be used.
pub struct ConsoleList {
    pub activate_id: Option<usize>,
    pub console_list: Vec<Option<Arc<Mutex<DisplayConsole>>>>,
}

// SAFETY:
// 1. The raw pointer in rust doesn't impl Send, the target thread can only read the memory of image
//    by this pointer.
// 2. The Arc<dyn ...> in rust doesn't impl Send, it will be delivered only once during
//    initialization process,
// and only be saved in the single thread.
// So implement Send is safe.
unsafe impl Send for ConsoleList {}

impl ConsoleList {
    fn new() -> Self {
        Self {
            activate_id: None,
            console_list: Vec::new(),
        }
    }

    // Get console by device name.
    fn get_console_by_dev_name(&mut self, dev_name: String) -> Option<Arc<Mutex<DisplayConsole>>> {
        let mut target: Option<Arc<Mutex<DisplayConsole>>> = None;
        for con in self.console_list.iter().flatten() {
            let locked_con = con.lock().unwrap();
            if locked_con.dev_name == dev_name {
                target = Some(con.clone());
                break;
            }
        }
        target
    }

    /// Get the console by id.
    fn get_console_by_id(&mut self, con_id: Option<usize>) -> Option<Arc<Mutex<DisplayConsole>>> {
        if con_id.is_none() && self.activate_id.is_none() {
            return None;
        }

        let mut target_id: usize = 0;
        if let Some(id) = con_id {
            target_id = id;
        } else if let Some(id) = self.activate_id {
            target_id = id;
        }

        self.console_list.get(target_id)?.clone()
    }
}

/// Set currently running stage for virtual machine.
pub fn set_run_stage(run_stage: VmRunningStage) {
    DISPLAY_STATE.lock().unwrap().run_stage = run_stage
}

/// Get currently running stage.
pub fn get_run_stage() -> VmRunningStage {
    DISPLAY_STATE.lock().unwrap().run_stage
}

/// Refresh display image.
fn display_refresh() {
    let mut dcl_interval: u64;
    let mut interval: u64 = DISPLAY_UPDATE_INTERVAL_MAX;

    let mut locked_state = DISPLAY_STATE.lock().unwrap();
    let mut related_listeners: Vec<Arc<Mutex<DisplayChangeListener>>> = vec![];
    for dcl in &mut locked_state.listeners.iter_mut().flatten() {
        related_listeners.push(dcl.clone());
    }
    drop(locked_state);

    for dcl in &mut related_listeners.iter() {
        let dcl_opts = dcl.lock().unwrap().dpy_opts.clone();
        if let Err(e) = (*dcl_opts).dpy_refresh(dcl) {
            error!("{:?}", e);
            return;
        }

        // Update refresh interval.
        dcl_interval = dcl.lock().unwrap().update_interval;
        if dcl_interval == 0 {
            dcl_interval = DISPLAY_UPDATE_INTERVAL_MAX;
        }

        if interval > dcl_interval {
            interval = dcl_interval
        }
    }
    trace::console_dpy_refresh(&interval);

    let mut locked_state = DISPLAY_STATE.lock().unwrap();
    locked_state.interval = interval;
    if locked_state.interval != 0 {
        locked_state.is_refresh = true;
        setup_refresh(interval);
    }
}

/// Register the timer to execute the scheduled
/// refresh task.
fn setup_refresh(update_interval: u64) {
    let func = Box::new(move || {
        display_refresh();
    });

    if update_interval != 0 {
        EventLoop::get_ctx(None)
            .unwrap()
            .timer_add(func, Duration::from_millis(update_interval));
    }
}

/// Switch the image of surface in display.
pub fn display_replace_surface(
    console: &Option<Weak<Mutex<DisplayConsole>>>,
    surface: Option<DisplaySurface>,
) -> Result<()> {
    let con = match console.as_ref().and_then(|c| c.upgrade()) {
        Some(c) => c,
        None => return Ok(()),
    };

    let mut locked_con = con.lock().unwrap();
    let old_surface = locked_con.surface;
    if surface.is_none() {
        // Create a place holder message.
        locked_con.surface = create_msg_surface(
            locked_con.width,
            locked_con.height,
            "Display is not active.".to_string(),
        );
    } else {
        locked_con.surface = surface;
    }

    if let Some(s) = locked_con.surface {
        locked_con.width = get_image_width(s.image);
        locked_con.height = get_image_height(s.image);
    }
    let con_id = locked_con.con_id;
    if let Some(s) = old_surface {
        unref_pixman_image(s.image);
    }
    drop(locked_con);

    let related_listeners = DISPLAY_STATE.lock().unwrap().get_related_display(con_id)?;
    for dcl in related_listeners.iter() {
        let dcl_opts = dcl.lock().unwrap().dpy_opts.clone();
        if let Some(s) = &con.lock().unwrap().surface.clone() {
            (*dcl_opts).dpy_switch(s)?;
        }
    }
    Ok(())
}

/// Update area of the image.
/// `x` `y` `w` `h` marke the area of image.
pub fn display_graphic_update(
    console: &Option<Weak<Mutex<DisplayConsole>>>,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
) -> Result<()> {
    let con = match console.as_ref().and_then(|c| c.upgrade()) {
        Some(c) => c,
        None => return Ok(()),
    };
    let mut width: i32 = w;
    let mut height: i32 = h;
    let locked_con = con.lock().unwrap();
    if let Some(s) = locked_con.surface {
        width = get_image_width(s.image);
        height = get_image_height(s.image);
    }
    let mut x = cmp::max(x, 0);
    let mut y = cmp::max(y, 0);
    x = cmp::min(x, width);
    y = cmp::min(y, height);
    let w = cmp::min(w, width - x);
    let h = cmp::min(h, height - y);
    let con_id = locked_con.con_id;
    drop(locked_con);

    let related_listeners = DISPLAY_STATE.lock().unwrap().get_related_display(con_id)?;
    for dcl in related_listeners.iter() {
        let dcl_opts = dcl.lock().unwrap().dpy_opts.clone();
        (*dcl_opts).dpy_image_update(x, y, w, h)?;
    }
    Ok(())
}

/// Update cursor data in display.
///
/// # Arguments
///
/// * `con_id` - console id in console list.
/// * `cursor` - data of curosr image.
pub fn display_cursor_define(
    console: &Option<Weak<Mutex<DisplayConsole>>>,
    cursor: &DisplayMouse,
) -> Result<()> {
    let con = match console.as_ref().and_then(|c| c.upgrade()) {
        Some(c) => c,
        None => return Ok(()),
    };
    let con_id = con.lock().unwrap().con_id;
    let related_listeners = DISPLAY_STATE.lock().unwrap().get_related_display(con_id)?;

    for dcl in related_listeners.iter() {
        let dcl_opts = dcl.lock().unwrap().dpy_opts.clone();
        (*dcl_opts).dpy_cursor_update(cursor)?;
    }
    Ok(())
}

/// Set specific screen as the main display screen.
pub fn display_set_major_screen(dev_name: &str) -> Result<()> {
    let con = match CONSOLES
        .lock()
        .unwrap()
        .get_console_by_dev_name(dev_name.to_string())
    {
        Some(c) => c,
        None => return Ok(()),
    };
    let con_id = con.lock().unwrap().con_id;
    console_select(Some(con_id))?;
    let related_listeners = DISPLAY_STATE.lock().unwrap().get_related_display(con_id)?;

    for dcl in related_listeners.iter() {
        let dcl_opts = dcl.lock().unwrap().dpy_opts.clone();
        (*dcl_opts).dpy_set_major()?;
    }
    Ok(())
}

pub fn graphic_hardware_update(con_id: Option<usize>) {
    let console = CONSOLES.lock().unwrap().get_console_by_id(con_id);
    if let Some(con) = console {
        let con_opts = con.lock().unwrap().dev_opts.clone();
        (*con_opts).hw_update(con);
    }
}

pub fn graphic_hardware_ui_info(
    con: Arc<Mutex<DisplayConsole>>,
    width: u32,
    height: u32,
) -> Result<()> {
    let mut locked_con = con.lock().unwrap();
    trace::console_dpy_ui_info(
        &locked_con.dev_name,
        &width,
        &height,
        &locked_con.ui_info.last_width,
        &locked_con.ui_info.last_height,
    );
    if locked_con.ui_info.last_width == width && locked_con.ui_info.last_height == height {
        return Ok(());
    }
    locked_con.ui_info.last_width = width;
    locked_con.ui_info.last_height = height;

    let clone_con = con.clone();
    let con_opts = locked_con.dev_opts.clone();
    let func = Box::new(move || {
        (*con_opts).hw_ui_info(clone_con.clone(), width, height);
    });

    let ctx = EventLoop::get_ctx(None).unwrap();
    if let Some(timer_id) = locked_con.timer_id {
        ctx.timer_del(timer_id);
    }
    locked_con.timer_id = Some(ctx.timer_add(func, Duration::from_millis(500)));

    Ok(())
}

/// Get the weak reference of all active consoles from the console lists.
pub fn get_active_console() -> Vec<Weak<Mutex<DisplayConsole>>> {
    let mut res: Vec<Weak<Mutex<DisplayConsole>>> = vec![];
    let locked_cons = CONSOLES.lock().unwrap();
    for con in locked_cons.console_list.iter().flatten() {
        if con.lock().unwrap().active {
            res.push(Arc::downgrade(con));
        }
    }

    res
}

/// Register a dcl and return the id.
pub fn register_display(dcl: &Arc<Mutex<DisplayChangeListener>>) -> Result<()> {
    let mut dcl_id = 0;
    let mut locked_state = DISPLAY_STATE.lock().unwrap();
    let len = locked_state.listeners.len();
    for dcl in &mut locked_state.listeners.iter() {
        if dcl.is_none() {
            break;
        }
        dcl_id += 1;
    }
    if dcl_id < len {
        locked_state.listeners[dcl_id] = Some(dcl.clone());
    } else {
        locked_state.listeners.push(Some(dcl.clone()));
    }
    locked_state.refresh_num += 1;
    // Register the clock and execute the scheduled refresh event.
    if !locked_state.is_refresh && locked_state.interval != 0 {
        locked_state.is_refresh = true;
        setup_refresh(locked_state.interval);
    }
    drop(locked_state);
    dcl.lock().unwrap().dcl_id = Some(dcl_id);
    let dcl_opts = dcl.lock().unwrap().dpy_opts.clone();

    let con_id = dcl.lock().unwrap().con_id;
    let console = CONSOLES.lock().unwrap().get_console_by_id(con_id);
    if let Some(con) = console {
        if let Some(surface) = &mut con.lock().unwrap().surface.clone() {
            (*dcl_opts).dpy_switch(surface)?;
        }
    } else {
        let mut place_holder_image = create_msg_surface(
            DEFAULT_SURFACE_WIDTH,
            DEFAULT_SURFACE_HEIGHT,
            "This VM has no graphic display device.".to_string(),
        );
        if let Some(surface) = &mut place_holder_image {
            (*dcl_opts).dpy_switch(surface)?;
        }
    }

    Ok(())
}

/// Unregister display change listener.
pub fn unregister_display(dcl: &Option<Weak<Mutex<DisplayChangeListener>>>) -> Result<()> {
    let dcl = match dcl.as_ref().and_then(|d| d.upgrade()) {
        Some(d) => d,
        None => return Ok(()),
    };
    let dcl_id = dcl.lock().unwrap().dcl_id;
    let mut locked_state = DISPLAY_STATE.lock().unwrap();
    let len = locked_state.listeners.len();
    let id = dcl_id.unwrap_or(len);
    if id >= len {
        return Ok(());
    }
    locked_state.listeners[id] = None;
    // Stop refreshing if the current refreshing num is 0
    locked_state.refresh_num -= 1;
    if locked_state.refresh_num <= 0 {
        locked_state.is_refresh = false;
    }
    drop(locked_state);
    Ok(())
}

/// Create a console and add into a global list. Then returen a console id
/// for later finding the assigned console.
pub fn console_init(
    dev_name: String,
    con_type: ConsoleType,
    dev_opts: Arc<dyn HardWareOperations>,
) -> Option<Weak<Mutex<DisplayConsole>>> {
    let mut locked_consoles = CONSOLES.lock().unwrap();
    for con in locked_consoles.console_list.iter().flatten() {
        let mut locked_con = con.lock().unwrap();
        if locked_con.dev_name == dev_name {
            locked_con.active = true;
            locked_con.dev_opts = dev_opts;
            return Some(Arc::downgrade(con));
        }
    }

    let con_id = locked_consoles.console_list.len();
    let new_con = DisplayConsole::new(
        con_id,
        dev_name,
        con_type,
        Arc::downgrade(&CONSOLES),
        dev_opts,
    );
    let con = Arc::new(Mutex::new(new_con));
    locked_consoles.console_list.push(Some(con.clone()));
    if locked_consoles.activate_id.is_none() {
        locked_consoles.activate_id = Some(con_id);
    }
    drop(locked_consoles);

    let con = Arc::downgrade(&con);
    let surface = create_msg_surface(
        DEFAULT_SURFACE_WIDTH,
        DEFAULT_SURFACE_HEIGHT,
        "Guest has not initialized the display yet.".to_string(),
    );
    display_replace_surface(&Some(con.clone()), surface)
        .unwrap_or_else(|e| error!("Error occurs during surface switching: {:?}", e));
    set_run_stage(VmRunningStage::Bios);
    Some(con)
}

/// Close a console.
pub fn console_close(console: &Option<Weak<Mutex<DisplayConsole>>>) -> Result<()> {
    let con = match console.as_ref().and_then(|c| c.upgrade()) {
        Some(c) => c,
        None => return Ok(()),
    };
    let mut locked_con = con.lock().unwrap();
    if let Some(surface) = locked_con.surface {
        unref_pixman_image(surface.image);
    }
    locked_con.active = false;
    locked_con.surface = create_msg_surface(
        DEFAULT_SURFACE_WIDTH,
        DEFAULT_SURFACE_HEIGHT,
        "Display is not active.".to_string(),
    );
    let con_id = locked_con.con_id;
    drop(locked_con);

    // If the active console is closed, reset the active console.
    let mut locked_consoles = CONSOLES.lock().unwrap();
    match locked_consoles.activate_id {
        Some(active_con) if active_con == con_id => {
            let mut active_id: Option<usize> = None;
            for con in locked_consoles.console_list.iter().flatten() {
                let locked_con = con.lock().unwrap();
                if locked_con.active {
                    active_id = Some(locked_con.con_id);
                    break;
                }
            }
            locked_consoles.activate_id = active_id;
        }
        _ => {}
    }

    Ok(())
}

/// Select the default display device.
/// If con_id is none, then do nothing.
pub fn console_select(con_id: Option<usize>) -> Result<()> {
    trace::console_select(&con_id);

    let mut locked_consoles = CONSOLES.lock().unwrap();
    if locked_consoles.activate_id == con_id {
        return Ok(());
    }
    let activate_console: Option<Arc<Mutex<DisplayConsole>>> = match con_id {
        Some(id) if locked_consoles.console_list.get(id).is_some() => {
            locked_consoles.activate_id = Some(id);
            locked_consoles.console_list[id].clone()
        }
        _ => return Ok(()),
    };
    drop(locked_consoles);

    let mut related_listeners: Vec<Arc<Mutex<DisplayChangeListener>>> = vec![];
    let mut locked_state = DISPLAY_STATE.lock().unwrap();
    for dcl in locked_state.listeners.iter_mut().flatten() {
        if dcl.lock().unwrap().con_id.is_some() {
            continue;
        }

        related_listeners.push(dcl.clone());
    }
    drop(locked_state);

    let con = match activate_console {
        Some(c) => c,
        None => return Ok(()),
    };
    let width = con.lock().unwrap().width;
    let height = con.lock().unwrap().height;
    for dcl in related_listeners {
        let dpy_opts = dcl.lock().unwrap().dpy_opts.clone();
        if let Some(s) = &mut con.lock().unwrap().surface {
            (*dpy_opts).dpy_switch(s)?;
        }
    }

    display_graphic_update(&Some(Arc::downgrade(&con)), 0, 0, width, height)
}

/// Create a default image to display messages.
///
/// # Arguments
///
/// * `width` - width of image.
/// * `height` - height of image.
/// * `msg` - test messages showed in display.
pub fn create_msg_surface(width: i32, height: i32, msg: String) -> Option<DisplaySurface> {
    if !(0..MAX_WINDOW_WIDTH as i32).contains(&width)
        || !(0..MAX_WINDOW_HEIGHT as i32).contains(&height)
    {
        error!("The size of image is invalid!");
        return None;
    }
    let mut surface = DisplaySurface::default();

    // One pixel occupies four bytes.
    surface.image = create_pixman_image(surface.format, width, height, ptr::null_mut(), width * 4);
    if surface.image.is_null() {
        error!("create default surface failed!");
        return None;
    }

    let fg = COLOR_TABLE_RGB[0][ColorNames::ColorWhite as usize];
    let bg = COLOR_TABLE_RGB[0][ColorNames::ColorBlack as usize];
    let x = (width / FONT_WIDTH - msg.len() as i32) / 2;
    let y = (height / FONT_HEIGHT - 1) / 2;

    for (index, ch) in msg.chars().enumerate() {
        let glyph = pixman_glyph_from_vgafont(FONT_HEIGHT as u32, ch as u32);
        if glyph.is_null() {
            continue;
        }
        pixman_glyph_render(
            glyph,
            surface.image,
            &fg,
            &bg,
            (x + index as i32, y),
            FONT_WIDTH,
            FONT_HEIGHT,
        );
        unref_pixman_image(glyph);
    }
    Some(surface)
}

#[cfg(test)]
mod tests {
    use super::*;
    use machine_manager::config::VmConfig;
    pub struct DclOpts {}
    impl DisplayChangeListenerOperations for DclOpts {
        fn dpy_switch(&self, _surface: &DisplaySurface) -> Result<()> {
            Ok(())
        }

        fn dpy_refresh(&self, _dcl: &Arc<Mutex<DisplayChangeListener>>) -> Result<()> {
            Ok(())
        }

        fn dpy_image_update(&self, _x: i32, _y: i32, _w: i32, _h: i32) -> Result<()> {
            Ok(())
        }

        fn dpy_cursor_update(&self, _cursor: &DisplayMouse) -> Result<()> {
            Ok(())
        }
    }
    struct HwOpts {}
    impl HardWareOperations for HwOpts {}

    #[test]
    fn test_console_select() {
        let con_opts = Arc::new(HwOpts {});
        let dev_name0 = format!("test_device0");
        let con_0 = console_init(dev_name0, ConsoleType::Graphic, con_opts.clone());
        let clone_con = con_0.clone();
        assert_eq!(
            clone_con.unwrap().upgrade().unwrap().lock().unwrap().con_id,
            0
        );
        let dev_name1 = format!("test_device1");
        let con_1 = console_init(dev_name1, ConsoleType::Graphic, con_opts.clone());
        assert_eq!(con_1.unwrap().upgrade().unwrap().lock().unwrap().con_id, 1);
        let dev_name2 = format!("test_device2");
        let con_2 = console_init(dev_name2, ConsoleType::Graphic, con_opts.clone());
        assert_eq!(con_2.unwrap().upgrade().unwrap().lock().unwrap().con_id, 2);
        assert!(console_close(&con_0).is_ok());
        assert_eq!(CONSOLES.lock().unwrap().activate_id, Some(1));
        let dev_name3 = format!("test_device3");
        let con_3 = console_init(dev_name3, ConsoleType::Graphic, con_opts.clone());
        assert_eq!(con_3.unwrap().upgrade().unwrap().lock().unwrap().con_id, 3);
        assert!(console_select(Some(0)).is_ok());
        assert_eq!(CONSOLES.lock().unwrap().activate_id, Some(0));
        assert!(console_select(Some(1)).is_ok());
        assert_eq!(CONSOLES.lock().unwrap().activate_id, Some(1));
        assert!(console_select(Some(2)).is_ok());
        assert_eq!(CONSOLES.lock().unwrap().activate_id, Some(2));
        assert!(console_select(Some(3)).is_ok());
        assert_eq!(CONSOLES.lock().unwrap().activate_id, Some(3));
        assert!(console_select(None).is_ok());
        assert_eq!(CONSOLES.lock().unwrap().activate_id, Some(3));
    }

    #[test]
    fn test_register_display() {
        let vm_config = VmConfig::default();
        assert!(EventLoop::object_init(&vm_config.iothreads).is_ok());
        let dcl_opts = Arc::new(DclOpts {});
        let dcl_0 = Arc::new(Mutex::new(DisplayChangeListener::new(
            None,
            dcl_opts.clone(),
        )));
        let dcl_1 = Arc::new(Mutex::new(DisplayChangeListener::new(
            None,
            dcl_opts.clone(),
        )));
        let dcl_2 = Arc::new(Mutex::new(DisplayChangeListener::new(
            None,
            dcl_opts.clone(),
        )));
        let dcl_3 = Arc::new(Mutex::new(DisplayChangeListener::new(
            None,
            dcl_opts.clone(),
        )));

        assert!(register_display(&dcl_0).is_ok());
        assert_eq!(dcl_0.lock().unwrap().dcl_id, Some(0));
        assert!(register_display(&dcl_1).is_ok());
        assert_eq!(dcl_1.lock().unwrap().dcl_id, Some(1));
        assert!(register_display(&dcl_2).is_ok());
        assert_eq!(dcl_2.lock().unwrap().dcl_id, Some(2));
        assert!(unregister_display(&Some(Arc::downgrade(&dcl_0))).is_ok());
        assert!(register_display(&dcl_3).is_ok());
        assert_eq!(dcl_3.lock().unwrap().dcl_id, Some(0));
    }
}
