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

mod draw;
mod menu;

use std::{
    cell::RefCell,
    cmp,
    collections::HashMap,
    env, fs,
    path::Path,
    ptr,
    rc::Rc,
    sync::{Arc, Mutex, Weak},
    thread,
};

use anyhow::{bail, Context, Result};
use gettextrs::LocaleCategory;
use gtk::{
    cairo::{Format, ImageSurface},
    gdk::{self, Geometry, Gravity, WindowHints},
    gdk_pixbuf::Colorspace,
    glib::{self, Priority, SyncSender},
    prelude::{ApplicationExt, ApplicationExtManual, Continue, NotebookExtManual},
    traits::{
        CheckMenuItemExt, GtkMenuItemExt, GtkWindowExt, HeaderBarExt, LabelExt, MenuShellExt,
        RadioMenuItemExt, WidgetExt,
    },
    Application, ApplicationWindow, DrawingArea, HeaderBar, Label, RadioMenuItem,
};
use log::error;
use vmm_sys_util::eventfd::EventFd;

use crate::{
    console::{
        create_msg_surface, get_active_console, get_run_stage, graphic_hardware_update,
        register_display, DisplayChangeListener, DisplayChangeListenerOperations, DisplayConsole,
        DisplayMouse, DisplaySurface, VmRunningStage, DEFAULT_SURFACE_HEIGHT,
        DEFAULT_SURFACE_WIDTH, DISPLAY_UPDATE_INTERVAL_DEFAULT,
    },
    gtk::{draw::set_callback_for_draw_area, menu::GtkMenu},
    keycode::{DpyMod, KeyCode},
    pixman::{
        create_pixman_image, get_image_data, get_image_height, get_image_width, ref_pixman_image,
        unref_pixman_image,
    },
};
use machine_manager::config::{DisplayConfig, UiContext};
use machine_manager::qmp::qmp_schema::GpuInfo;
use util::pixman::{pixman_format_code_t, pixman_image_composite, pixman_op_t};
use util::time::gettime;

const CHANNEL_BOUND: usize = 1024;
/// Width of default window.
const DEFAULT_WINDOW_WIDTH: i32 = 1024;
/// Height of default window.
const DEFAULT_WINDOW_HEIGHT: i32 = 768;
pub(crate) const GTK_SCALE_MIN: f64 = 0.25;
pub(crate) const GTK_ZOOM_STEP: f64 = 0.25;
/// Domain name.
const DOMAIN_NAME: &str = "desktop-app-engine";
/// The path of message information is located.
const LOCALE_PATH: &str = "/usr/share/locale";

/// Gtk window display mode.
#[derive(Clone, Eq, PartialEq)]
pub struct ScaleMode {
    /// Display fill desktop.
    full_screen: bool,
    /// Scaling operation does not change the aspect ratio.
    free_scale: bool,
}

impl ScaleMode {
    fn is_full_screen(&self) -> bool {
        self.full_screen
    }

    fn is_free_scale(&self) -> bool {
        self.free_scale
    }
}

/// Display zoom operation.
/// Zoom in the display.
/// Zoom out the display.
/// Window adapt to display.
#[derive(Eq, PartialEq)]
pub enum ZoomOperate {
    ZoomIn,
    ZoomOut,
    BestFit,
}

#[derive(Debug, PartialEq)]
enum DisplayEventType {
    DisplaySwitch,
    DisplayUpdate,
    CursorDefine,
    DisplayRefresh,
    DisplaySetMajor,
}

impl Default for DisplayEventType {
    fn default() -> Self {
        Self::DisplayRefresh
    }
}

#[derive(Default)]
struct DisplayChangeEvent {
    dev_name: String,
    event_type: DisplayEventType,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    cursor: Option<DisplayMouse>,
}

impl DisplayChangeEvent {
    fn new(dev_name: String, event_type: DisplayEventType) -> Self {
        Self {
            dev_name,
            event_type,
            ..Default::default()
        }
    }
}

struct GtkInterface {
    dev_name: String,
    dce_sender: SyncSender<DisplayChangeEvent>,
}

impl GtkInterface {
    fn new(dev_name: String, dce_sender: SyncSender<DisplayChangeEvent>) -> Self {
        Self {
            dev_name,
            dce_sender,
        }
    }
}

impl DisplayChangeListenerOperations for GtkInterface {
    fn dpy_switch(&self, _surface: &crate::console::DisplaySurface) -> Result<()> {
        trace::gtk_dyp_channel_switch(&self.dev_name.clone());

        let event = DisplayChangeEvent::new(self.dev_name.clone(), DisplayEventType::DisplaySwitch);
        self.dce_sender.send(event)?;
        Ok(())
    }

    fn dpy_refresh(
        &self,
        dcl: &std::sync::Arc<std::sync::Mutex<DisplayChangeListener>>,
    ) -> Result<()> {
        trace::gtk_dyp_channel_refresh(&self.dev_name.clone());

        // The way virtio-gpu devices are used in phase OS and others is different.
        if self.dev_name.starts_with("virtio-gpu") {
            if get_run_stage() == VmRunningStage::Os {
                dcl.lock().unwrap().update_interval = 0;
            } else {
                dcl.lock().unwrap().update_interval = DISPLAY_UPDATE_INTERVAL_DEFAULT;
            }
        }

        let event =
            DisplayChangeEvent::new(self.dev_name.clone(), DisplayEventType::DisplayRefresh);
        let con_id = dcl.lock().unwrap().con_id;
        graphic_hardware_update(con_id);
        self.dce_sender.send(event)?;
        Ok(())
    }

    fn dpy_image_update(&self, x: i32, y: i32, w: i32, h: i32) -> Result<()> {
        trace::gtk_dyp_channel_image_update(&self.dev_name.clone(), &x, &y, &w, &h);

        let mut event =
            DisplayChangeEvent::new(self.dev_name.clone(), DisplayEventType::DisplayUpdate);
        event.x = x;
        event.y = y;
        event.w = w;
        event.h = h;
        self.dce_sender.send(event)?;
        Ok(())
    }

    fn dpy_cursor_update(&self, cursor_data: &DisplayMouse) -> Result<()> {
        trace::gtk_dyp_channel_cursor_update(&self.dev_name.clone());

        let mut event =
            DisplayChangeEvent::new(self.dev_name.clone(), DisplayEventType::CursorDefine);
        event.cursor = Some(cursor_data.clone());
        self.dce_sender.send(event)?;
        Ok(())
    }

    fn dpy_set_major(&self) -> Result<()> {
        let event =
            DisplayChangeEvent::new(self.dev_name.clone(), DisplayEventType::DisplaySetMajor);
        self.dce_sender.send(event)?;
        Ok(())
    }
}

pub(crate) struct GtkDisplay {
    gtk_menu: GtkMenu,
    scale_mode: Rc<RefCell<ScaleMode>>,
    pagenum2ds: HashMap<u32, Rc<RefCell<GtkDisplayScreen>>>,
    powerdown_button: Option<Arc<EventFd>>,
    shutdown_button: Option<Arc<EventFd>>,
    pause_button: Option<Arc<EventFd>>,
    resume_button: Option<Arc<EventFd>>,
    keysym2keycode: Rc<RefCell<HashMap<u16, u16>>>,
}

impl GtkDisplay {
    fn create(gtk_menu: GtkMenu, gtk_cfg: &GtkConfig) -> Self {
        // Window scale mode.
        let scale_mode = Rc::new(RefCell::new(ScaleMode {
            full_screen: false,
            free_scale: true,
        }));
        // Mapping ASCII to keycode.
        let keysym2keycode = Rc::new(RefCell::new(KeyCode::keysym_to_qkeycode(DpyMod::Gtk)));
        Self {
            gtk_menu,
            scale_mode,
            pagenum2ds: HashMap::new(),
            powerdown_button: gtk_cfg.powerdown_button.clone(),
            shutdown_button: gtk_cfg.shutdown_button.clone(),
            pause_button: gtk_cfg.pause_button.clone(),
            resume_button: gtk_cfg.resume_button.clone(),
            keysym2keycode,
        }
    }

    // Get the current active drawing_area in note_book.
    fn get_current_display(&self) -> Result<Rc<RefCell<GtkDisplayScreen>>> {
        let page_num = self.gtk_menu.note_book.current_page();
        let gs = match page_num {
            Some(num) if self.pagenum2ds.get(&num).is_some() => self.pagenum2ds.get(&num).unwrap(),
            _ => bail!("No active display"),
        };
        Ok(gs.clone())
    }

    // Get the displays based on device name.
    fn get_ds_by_pagenum(&self, page_num: Option<u32>) -> Option<Rc<RefCell<GtkDisplayScreen>>> {
        let ds = self.pagenum2ds.get(&page_num?)?;
        Some(ds.clone())
    }

    // Get the display base the page number in notebook.
    fn get_ds_by_devname(&self, dev_name: &str) -> Option<Rc<RefCell<GtkDisplayScreen>>> {
        for ds in self.pagenum2ds.values() {
            if ds.borrow().dev_name.eq(dev_name) {
                return Some(ds.clone());
            }
        }
        None
    }

    fn set_draw_area(&mut self, gs: Rc<RefCell<GtkDisplayScreen>>) -> Result<()> {
        let draw_area = DrawingArea::new();
        draw_area.set_size_request(DEFAULT_SURFACE_WIDTH, DEFAULT_SURFACE_HEIGHT);
        draw_area.set_can_focus(true);
        set_callback_for_draw_area(&draw_area, gs.clone())?;

        // Add notebook page.
        let active_con = gs.borrow().con.upgrade();
        let con = match active_con {
            Some(con) => con,
            None => bail!("No active console!"),
        };
        let label_name = con.lock().unwrap().dev_name.clone();
        let label = gtk::Label::new(Some(&label_name));
        let page_num = self
            .gtk_menu
            .note_book
            .append_page(&draw_area, Some(&label));
        self.pagenum2ds.insert(page_num, gs.clone());
        draw_area.grab_focus();

        // Create a radio button.
        // Only one screen can be displayed at a time.
        let gs_show_menu = RadioMenuItem::with_label(&label_name);
        let note_book = self.gtk_menu.note_book.clone();
        gs_show_menu.connect_activate(glib::clone!(@weak gs, @weak note_book => move |show_menu| {
            gs_show_menu_callback(&gs, note_book, show_menu).unwrap_or_else(|e| error!("Display show menu: {:?}", e));
        }));
        self.gtk_menu.view_menu.append(&gs_show_menu);

        if !self.gtk_menu.radio_group.is_empty() {
            let first_radio = &self.gtk_menu.radio_group[0];
            gs_show_menu.join_group(Some(first_radio));
        } else {
            note_book.set_current_page(Some(page_num));
        }

        self.gtk_menu.radio_group.push(gs_show_menu.clone());
        gs.borrow_mut().show_menu = gs_show_menu;
        gs.borrow_mut().draw_area = draw_area;

        Ok(())
    }

    /// Gracefully Shutdown.
    pub(crate) fn vm_powerdown(&self) {
        if let Some(button) = &self.powerdown_button {
            button
                .write(1)
                .unwrap_or_else(|e| error!("Vm power down failed: {:?}", e));
        }
    }

    /// Forced Shutdown.
    pub(crate) fn vm_shutdown(&self) {
        if let Some(button) = &self.shutdown_button {
            button
                .write(1)
                .unwrap_or_else(|e| error!("Vm shut down failed: {:?}", e));
        }
    }

    /// Pause Virtual Machine.
    pub(crate) fn vm_pause(&self) {
        if let Some(button) = &self.pause_button {
            button
                .write(1)
                .unwrap_or_else(|e| error!("Vm pause failed: {:?}", e));
        }
    }

    /// Resume Virtual Machine.
    pub(crate) fn vm_resume(&self) {
        if let Some(button) = &self.resume_button {
            button
                .write(1)
                .unwrap_or_else(|e| error!("Vm resume failed: {:?}", e));
        }
    }
}

pub struct GtkDisplayScreen {
    window: ApplicationWindow,
    dev_name: String,
    show_menu: RadioMenuItem,
    draw_area: DrawingArea,
    cursor_trsp: bool, // GTK own default cursor transparent or not
    source_surface: DisplaySurface,
    transfer_surface: Option<DisplaySurface>,
    cairo_image: Option<ImageSurface>,
    con: Weak<Mutex<DisplayConsole>>,
    dcl: Weak<Mutex<DisplayChangeListener>>,
    scale_mode: Rc<RefCell<ScaleMode>>,
    scale_x: f64,
    scale_y: f64,
    keysym2keycode: Rc<RefCell<HashMap<u16, u16>>>,
}

/// A displayscreen corresponds to a display area.
impl GtkDisplayScreen {
    fn create(
        window: ApplicationWindow,
        con: Weak<Mutex<DisplayConsole>>,
        dcl: Weak<Mutex<DisplayChangeListener>>,
        keysym2keycode: Rc<RefCell<HashMap<u16, u16>>>,
        scale_mode: Rc<RefCell<ScaleMode>>,
    ) -> Self {
        let surface = create_msg_surface(
            DEFAULT_SURFACE_WIDTH,
            DEFAULT_SURFACE_HEIGHT,
            "Please wait a moment".to_string(),
        )
        .map_or(DisplaySurface::default(), |s| s);

        // SAFETY: The image is created within the function, it can be ensure
        // that the data ptr is not nullptr and the image size matches the image data.
        let cairo_image = unsafe {
            ImageSurface::create_for_data_unsafe(
                surface.data() as *mut u8,
                Format::Rgb24,
                surface.width(),
                surface.height(),
                surface.stride(),
            )
        }
        .ok();

        let dev_name = match con.upgrade() {
            Some(c) => c.lock().unwrap().dev_name.clone(),
            None => "default".to_string(),
        };

        Self {
            window,
            dev_name,
            draw_area: DrawingArea::default(),
            cursor_trsp: false,
            show_menu: RadioMenuItem::default(),
            source_surface: surface,
            transfer_surface: None,
            cairo_image,
            con,
            dcl,
            scale_mode,
            scale_x: 1.0,
            scale_y: 1.0,
            keysym2keycode,
        }
    }

    fn get_window_size(&self) -> Option<(f64, f64)> {
        if let Some(win) = self.draw_area.window() {
            let w_width = win.width() as f64;
            let w_height = win.height() as f64;

            if w_width.ne(&0.0) && w_height.ne(&0.0) {
                return Some((w_width, w_height));
            }
        };

        None
    }

    /// Convert coordinates of the window to relative coordinates of the image.
    /// In some situation:
    /// 1. Image is scaled.
    /// 2. There may be unfilled areas between the window and the image.
    /// Input: relative coordinates of window.
    /// Output: relative coordinates of images.
    fn convert_coord(&mut self, mut x: f64, mut y: f64) -> Result<(f64, f64)> {
        let (surface_width, surface_height) = match &self.cairo_image {
            Some(image) => (image.width(), image.height()),
            None => bail!("No display image."),
        };
        let (scale_width, scale_height) = (
            (surface_width as f64) * self.scale_x,
            (surface_height as f64) * self.scale_y,
        );

        let (mut window_width, mut window_height) = (0.0, 0.0);
        if let Some((w, h)) = self.get_window_size() {
            (window_width, window_height) = (w, h);
        };
        let scale_factor = match self.draw_area.window() {
            Some(window) => window.scale_factor() as f64,
            None => bail!("No display window."),
        };

        x = x.max(0.0);
        x = x.min(window_width);
        y = y.max(0.0);
        y = y.min(window_height);

        // There may be unfilled areas between the window and the image.
        let (mut mx, mut my) = (0.0, 0.0);
        if window_width > scale_width {
            mx = (window_width - scale_width) / (2.0);
        }
        if window_height > scale_height {
            my = (window_height - scale_height) / (2.0);
        }
        let real_x = ((x - mx) / self.scale_x) * scale_factor;
        let real_y = ((y - my) / self.scale_y) * scale_factor;

        Ok((real_x, real_y))
    }
}

/// Args for creating gtk thread.
#[derive(Clone)]
struct GtkConfig {
    full_screen: bool,
    app_name: Option<String>,
    vm_name: String,
    /// Gracefully Shutdown.
    powerdown_button: Option<Arc<EventFd>>,
    /// Forced Shutdown.
    shutdown_button: Option<Arc<EventFd>>,
    /// Pause Virtual Machine.
    pause_button: Option<Arc<EventFd>>,
    /// Resume Virtual Machine.
    resume_button: Option<Arc<EventFd>>,
    gtk_args: Vec<String>,
}

/// Gtk display init.
pub fn gtk_display_init(ds_cfg: &DisplayConfig, ui_context: UiContext) -> Result<()> {
    let mut gtk_args: Vec<String> = vec![];
    if let Some(app_name) = &ds_cfg.app_name {
        gtk_args.push(app_name.clone());
    }
    let gtk_cfg = GtkConfig {
        full_screen: ds_cfg.full_screen,
        app_name: ds_cfg.app_name.clone(),
        vm_name: ui_context.vm_name,
        powerdown_button: ui_context.power_button,
        shutdown_button: ui_context.shutdown_req,
        pause_button: ui_context.pause_req,
        resume_button: ui_context.resume_req,
        gtk_args,
    };
    let _handle = thread::Builder::new()
        .name("gtk display".to_string())
        .spawn(move || create_gtk_thread(&gtk_cfg))
        .with_context(|| "Fail to create gtk display thread!")?;
    Ok(())
}

/// Create a gtk thread.
fn create_gtk_thread(gtk_cfg: &GtkConfig) {
    let application = Application::builder()
        .application_id("stratovirt.gtk")
        .build();
    let gtk_cfg_clone = gtk_cfg.clone();

    application.connect_activate(move |app| build_ui(app, &gtk_cfg_clone));
    application.run_with_args(&gtk_cfg.gtk_args);
}

// Create window.
fn build_ui(app: &Application, gtk_cfg: &GtkConfig) {
    let window = ApplicationWindow::builder()
        .application(app)
        .default_width(DEFAULT_WINDOW_WIDTH)
        .default_height(DEFAULT_WINDOW_HEIGHT)
        .build();

    set_program_attribute(gtk_cfg, &window)
        .with_context(|| "Failed to set properties for program")
        .unwrap();

    // Create menu.
    let mut gtk_menu = GtkMenu::new(window);
    let gd = Rc::new(RefCell::new(GtkDisplay::create(gtk_menu.clone(), gtk_cfg)));
    gtk_menu.set_menu();
    gtk_menu.set_signal(&gd);

    let scale_mode = gd.borrow().scale_mode.clone();
    // Gtk display init.
    graphic_display_init(gd)
        .with_context(|| "Gtk display init failed!")
        .unwrap();

    gtk_menu.show_window(scale_mode, gtk_cfg.full_screen);
}

fn set_program_attribute(gtk_cfg: &GtkConfig, window: &ApplicationWindow) -> Result<()> {
    // Set title bar.
    let header = HeaderBar::new();
    header.set_show_close_button(true);
    header.set_decoration_layout(Some("menu:minimize,maximize,close"));

    let label: Label = Label::new(Some(&gtk_cfg.vm_name));
    label.set_markup(
        &("<span font_desc='12.5' weight='normal'>".to_string() + &gtk_cfg.vm_name + "</span>"),
    );
    header.set_custom_title(Some(&label));
    window.set_titlebar(Some(&header));

    // Set default icon.
    if let Some(app_name) = &gtk_cfg.app_name {
        window.set_icon_name(Some(app_name));
    }

    // Set text attributes for the program.
    gettextrs::setlocale(LocaleCategory::LcMessages, "");
    gettextrs::setlocale(LocaleCategory::LcCType, "C.UTF-8");
    gettextrs::bindtextdomain(DOMAIN_NAME, LOCALE_PATH)?;
    gettextrs::bind_textdomain_codeset(DOMAIN_NAME, "UTF-8")?;
    gettextrs::textdomain(DOMAIN_NAME)?;

    Ok(())
}

fn graphic_display_init(gd: Rc<RefCell<GtkDisplay>>) -> Result<()> {
    let console_list = get_active_console();
    let mut borrowed_gd = gd.borrow_mut();
    let keysym2keycode = borrowed_gd.keysym2keycode.clone();
    let window = borrowed_gd.gtk_menu.window.clone();
    let scale_mode = borrowed_gd.scale_mode.clone();
    let (dce_sender, dce_receiver) =
        glib::MainContext::sync_channel::<DisplayChangeEvent>(Priority::default(), CHANNEL_BOUND);
    // Create a display area for each console.
    for con in console_list {
        let c = match con.upgrade() {
            Some(c) => c,
            None => continue,
        };
        let locked_con = c.lock().unwrap();
        let dev_name = locked_con.dev_name.clone();
        let con_id = locked_con.con_id;
        drop(locked_con);
        // Register displaychangelistener in the console.
        let gtk_opts = Arc::new(GtkInterface::new(dev_name, dce_sender.clone()));
        let dcl = Arc::new(Mutex::new(DisplayChangeListener::new(
            Some(con_id),
            gtk_opts,
        )));
        register_display(&dcl)?;
        let gs = Rc::new(RefCell::new(GtkDisplayScreen::create(
            window.clone(),
            con.clone(),
            Arc::downgrade(&dcl),
            keysym2keycode.clone(),
            scale_mode.clone(),
        )));
        borrowed_gd.set_draw_area(gs)?;
    }
    drop(borrowed_gd);

    dce_receiver.attach(
        None,
        glib::clone!(@strong gd => @default-return Continue(true), move |event| {
            gd_handle_event(&gd, event).unwrap_or_else(|e| error!("gd_handle_event: {:?}", e));
            Continue(true)
        }),
    );

    Ok(())
}

/// Receive display update events from the mainloop of Stratovirt ,
/// assigns the event to the corresponding draw display by the field
/// of device name. And then update the specific gtk display.
fn gd_handle_event(gd: &Rc<RefCell<GtkDisplay>>, event: DisplayChangeEvent) -> Result<()> {
    let ds = match gd.borrow().get_ds_by_devname(&event.dev_name) {
        Some(display) => display,
        None => return Ok(()),
    };
    match event.event_type {
        DisplayEventType::DisplaySwitch => do_switch_event(&ds),
        DisplayEventType::DisplayUpdate => do_update_event(&ds, event),
        DisplayEventType::CursorDefine => do_cursor_define(&ds, event),
        DisplayEventType::DisplayRefresh => do_refresh_event(&ds),
        DisplayEventType::DisplaySetMajor => do_set_major_event(&ds),
    }
}

// Select the specified display area.
fn gs_show_menu_callback(
    gs: &Rc<RefCell<GtkDisplayScreen>>,
    note_book: gtk::Notebook,
    show_menu: &RadioMenuItem,
) -> Result<()> {
    let borrowed_gs = gs.borrow();
    let page_num = note_book.page_num(&borrowed_gs.draw_area);
    note_book.set_current_page(page_num);

    if borrowed_gs.dev_name == "ramfb" {
        match borrowed_gs.dcl.upgrade() {
            Some(dcl) if show_menu.is_active() => dcl.lock().unwrap().update_interval = 30,
            Some(dcl) if !show_menu.is_active() => dcl.lock().unwrap().update_interval = 0,
            _ => {}
        }
    }

    borrowed_gs.draw_area.grab_focus();
    drop(borrowed_gs);
    update_window_size(gs)
}

/// Refresh image.
/// There is a situation:
/// 1. Switch operation 1, the gtk display should change the image from a to b.
/// 2. Switch operation 2, the gtk display should change the image from b to c, but
/// the channel between stratovirt mainloop and gtk mainloop lost the event.
/// 3. The gtk display always show the image.
/// So, the refresh operation will always check if the image has been switched, if
/// the result is yes, then use the switch operation to switch the latest image.
fn do_refresh_event(gs: &Rc<RefCell<GtkDisplayScreen>>) -> Result<()> {
    trace::gtk_dyp_refresh();

    let borrowed_gs = gs.borrow();
    let active_con = borrowed_gs.con.upgrade();
    let con = match active_con {
        Some(con) => con,
        None => return Ok(()),
    };
    let locked_con = con.lock().unwrap();
    let surface = match locked_con.surface {
        Some(s) => s,
        None => return Ok(()),
    };

    let width = borrowed_gs.source_surface.width();
    let height = borrowed_gs.source_surface.height();
    let surface_width = surface.width();
    let surface_height = surface.height();
    if width == 0 || height == 0 || width != surface_width || height != surface_height {
        drop(locked_con);
        drop(borrowed_gs);
        do_switch_event(gs)?;
    }
    Ok(())
}

/// Update cursor image.
fn do_cursor_define(gs: &Rc<RefCell<GtkDisplayScreen>>, event: DisplayChangeEvent) -> Result<()> {
    let c: DisplayMouse = match event.cursor {
        Some(c) => c,
        None => bail!("Invalid Cursor image"),
    };

    trace::gtk_dyp_cursor_define(&c.width, &c.height, &c.hot_x, &c.hot_y, &c.data.len());

    if c.data.len() < ((c.width * c.height) as usize) * 4 {
        bail!("Invalid Cursor image");
    }

    let borrowed_gs = gs.borrow();
    if !borrowed_gs.draw_area.is_realized() {
        bail!("The draw_area is not realized");
    }
    let display = borrowed_gs.draw_area.display();

    let pixbuf = gdk::gdk_pixbuf::Pixbuf::from_mut_slice(
        c.data,
        Colorspace::Rgb,
        true,
        8,
        c.width as i32,
        c.height as i32,
        (c.width as i32) * 4,
    );
    let gtk_cursor = gdk::Cursor::from_pixbuf(&display, &pixbuf, c.hot_x as i32, c.hot_y as i32);
    if let Some(win) = &borrowed_gs.draw_area.window() {
        win.set_cursor(Some(&gtk_cursor));
    }
    Ok(())
}

// Update dirty area of image.
fn do_update_event(gs: &Rc<RefCell<GtkDisplayScreen>>, event: DisplayChangeEvent) -> Result<()> {
    trace::gtk_dyp_update(&event.x, &event.y, &event.w, &event.h);

    let borrowed_gs = gs.borrow();
    let active_con = borrowed_gs.con.upgrade();
    let con = match active_con {
        Some(con) => con,
        None => return Ok(()),
    };
    let locked_con = con.lock().unwrap();
    let surface = match locked_con.surface {
        Some(s) => s,
        None => return Ok(()),
    };

    // drea_area is hidden behind the screen.
    if !borrowed_gs.draw_area.is_realized() {
        return Ok(());
    }

    if surface.image.is_null() {
        bail!("Image is null");
    }

    let src_width = get_image_width(surface.image);
    let src_height = get_image_height(surface.image);
    let dest_width = get_image_width(borrowed_gs.source_surface.image);
    let dest_height = get_image_height(borrowed_gs.source_surface.image);

    let surface_width = cmp::min(src_width, dest_width);
    let surface_height = cmp::min(src_height, dest_height);

    let (x, y) = (event.x, event.y);
    let x1 = cmp::min(x + event.w, surface_width);
    let y1 = cmp::min(y + event.h, surface_height);
    let w = (x1 - x).abs();
    let h = (y1 - y).abs();

    match borrowed_gs.transfer_surface {
        Some(s) if borrowed_gs.source_surface.format != pixman_format_code_t::PIXMAN_x8r8g8b8 => {
            if src_width != s.width() || src_height != s.height() {
                bail!("Wrong format of image format.");
            }
            // SAFETY: Verified that the pointer of source image and dest image
            // is not empty, and the copied data will not exceed the image area
            unsafe {
                pixman_image_composite(
                    pixman_op_t::PIXMAN_OP_SRC,
                    surface.image,
                    ptr::null_mut(),
                    s.image,
                    x as i16,
                    y as i16,
                    0,
                    0,
                    x as i16,
                    y as i16,
                    w as u16,
                    h as u16,
                )
            };
        }
        _ => {}
    };
    drop(locked_con);

    // Image scalling.
    let x1 = ((x as f64) * borrowed_gs.scale_x).floor();
    let y1 = ((y as f64) * borrowed_gs.scale_y).floor();
    let x2 = ((x as f64) * borrowed_gs.scale_x + (w as f64) * borrowed_gs.scale_x).ceil();
    let y2 = ((y as f64) * borrowed_gs.scale_y + (h as f64) * borrowed_gs.scale_y).ceil();

    let scale_width = (surface_width as f64) * borrowed_gs.scale_x;
    let scale_height = (surface_height as f64) * borrowed_gs.scale_y;
    let (window_width, window_height);
    match borrowed_gs.get_window_size() {
        Some((w, h)) => (window_width, window_height) = (w, h),
        None => return Ok(()),
    };

    let mut mx: f64 = 0.0;
    let mut my: f64 = 0.0;
    if window_width > scale_width {
        mx = (window_width - scale_width) / (2.0);
    }
    if window_height > scale_height {
        my = (window_height - scale_height) / (2.0);
    }

    borrowed_gs.draw_area.queue_draw_area(
        (mx + x1) as i32,
        (my + y1) as i32,
        (x2 - x1) as i32,
        (y2 - y1) as i32,
    );

    Ok(())
}

/// Switch display image.
fn do_switch_event(gs: &Rc<RefCell<GtkDisplayScreen>>) -> Result<()> {
    let mut borrowed_gs = gs.borrow_mut();
    let scale_mode = borrowed_gs.scale_mode.clone();
    let active_con = borrowed_gs.con.upgrade();
    let con = match active_con {
        Some(con) => con,
        None => return Ok(()),
    };
    let locked_con = con.lock().unwrap();
    let surface = match locked_con.surface {
        Some(s) => s,
        None => return Ok(()),
    };

    let mut need_resize: bool = true;

    let width = borrowed_gs.source_surface.width();
    let height = borrowed_gs.source_surface.height();
    let surface_width = surface.width();
    let surface_height = surface.height();
    let surface_stride = surface.stride();
    trace::gtk_dyp_switch(&width, &height, &surface_width, &surface_height);

    if width != 0 && height != 0 && width == surface_width && height == surface_height {
        need_resize = false;
    }

    if surface.image.is_null() {
        bail!("Image data is invalid.");
    }

    let source_surface = DisplaySurface {
        format: surface.format,
        image: ref_pixman_image(surface.image),
    };
    unref_pixman_image(borrowed_gs.source_surface.image);
    borrowed_gs.source_surface = source_surface;
    if let Some(s) = borrowed_gs.transfer_surface {
        unref_pixman_image(s.image);
        borrowed_gs.transfer_surface = None;
    }
    drop(locked_con);

    if borrowed_gs.source_surface.format == pixman_format_code_t::PIXMAN_x8r8g8b8 {
        let data = get_image_data(borrowed_gs.source_surface.image) as *mut u8;
        borrowed_gs.cairo_image =
        // SAFETY:
        // 1. It can be sure that the ptr of data is not nullptr.
        // 2. The copy range will not exceed the image data.
        unsafe {
            ImageSurface::create_for_data_unsafe(
                data as *mut u8,
                Format::Rgb24,
                surface_width,
                surface_height,
                surface_stride,
            )
        }
        .ok()
    } else {
        let transfer_image = create_pixman_image(
            pixman_format_code_t::PIXMAN_x8r8g8b8,
            surface_width,
            surface_height,
            ptr::null_mut(),
            surface_stride,
        );

        let data = get_image_data(transfer_image) as *mut u8;
        borrowed_gs.cairo_image =
        // SAFETY:
        // 1. It can be sure that the ptr of data is not nullptr.
        // 2. The copy range will not exceed the image data.
        unsafe {
            ImageSurface::create_for_data_unsafe(
                data as *mut u8,
                Format::Rgb24,
                surface_width,
                surface_height,
                surface_stride,
            )
        }
        .ok();

        // SAFETY:
        // 1. It can be sure that source ptr and dest ptr is not nullptr.
        // 2. The copy range will not exceed the image area.
        unsafe {
            pixman_image_composite(
                pixman_op_t::PIXMAN_OP_SRC,
                borrowed_gs.source_surface.image,
                ptr::null_mut(),
                transfer_image,
                0,
                0,
                0,
                0,
                0,
                0,
                surface_width as u16,
                surface_height as u16,
            )
        };
        borrowed_gs.transfer_surface = Some(DisplaySurface {
            format: pixman_format_code_t::PIXMAN_x8r8g8b8,
            image: transfer_image,
        });
    };

    let (window_width, window_height);
    match borrowed_gs.get_window_size() {
        Some((w, h)) => (window_width, window_height) = (w, h),
        None => return Ok(()),
    };
    if scale_mode.borrow().is_full_screen() || scale_mode.borrow().is_free_scale() {
        borrowed_gs.scale_x = window_width / surface_width as f64;
        borrowed_gs.scale_y = window_height / surface_height as f64;
    }

    // Vm desktop manage its own cursor, gtk cursor need to be trsp firstly.
    if !borrowed_gs.cursor_trsp {
        if let Some(win) = borrowed_gs.draw_area.window() {
            let dpy = borrowed_gs.window.display();
            let gtk_cursor = gdk::Cursor::for_display(&dpy, gdk::CursorType::BlankCursor);
            win.set_cursor(gtk_cursor.as_ref());
        }
        borrowed_gs.cursor_trsp = true;
    }

    drop(borrowed_gs);

    if need_resize {
        update_window_size(gs)
    } else {
        renew_image(gs)
    }
}

/// Activate the current screen.
fn do_set_major_event(gs: &Rc<RefCell<GtkDisplayScreen>>) -> Result<()> {
    let borrowed_gs = gs.borrow();
    if borrowed_gs.show_menu.is_active() {
        return Ok(());
    }
    borrowed_gs.show_menu.activate();
    Ok(())
}

pub(crate) fn update_window_size(gs: &Rc<RefCell<GtkDisplayScreen>>) -> Result<()> {
    let borrowed_gs = gs.borrow();
    let scale_mode = borrowed_gs.scale_mode.borrow().clone();
    let (width, height) = match &borrowed_gs.cairo_image {
        Some(image) => (image.width() as f64, image.height() as f64),
        None => (0.0, 0.0),
    };
    let (mut scale_width, mut scale_height) = if scale_mode.is_free_scale() {
        (width * GTK_SCALE_MIN, height * GTK_SCALE_MIN)
    } else {
        (width * borrowed_gs.scale_x, height * borrowed_gs.scale_y)
    };
    scale_width = scale_width.max(DEFAULT_SURFACE_WIDTH as f64);
    scale_height = scale_height.max(DEFAULT_SURFACE_HEIGHT as f64);

    let geo: Geometry = Geometry::new(
        scale_width as i32,
        scale_height as i32,
        0,
        0,
        0,
        0,
        0,
        0,
        0.0,
        0.0,
        Gravity::Center,
    );

    let geo_mask = WindowHints::MIN_SIZE;

    borrowed_gs
        .draw_area
        .set_size_request(geo.min_width(), geo.min_height());
    if let Some(window) = borrowed_gs.draw_area.window() {
        window.set_geometry_hints(&geo, geo_mask)
    }

    if !scale_mode.is_full_screen() && !scale_mode.is_free_scale() {
        borrowed_gs
            .window
            .resize(DEFAULT_SURFACE_WIDTH, DEFAULT_SURFACE_HEIGHT);
    }
    Ok(())
}

/// Ask the gtk display to update the display.
pub(crate) fn renew_image(gs: &Rc<RefCell<GtkDisplayScreen>>) -> Result<()> {
    let borrowed_gs = gs.borrow();
    let (width, height);
    match borrowed_gs.get_window_size() {
        Some((w, h)) => (width, height) = (w, h),
        None => return Ok(()),
    };

    borrowed_gs
        .draw_area
        .queue_draw_area(0, 0, width as i32, height as i32);
    Ok(())
}

pub fn qmp_query_display_image() -> Result<GpuInfo> {
    let mut gpu_info = GpuInfo::default();
    let console_list = get_active_console();
    for con in console_list {
        let c = match con.upgrade() {
            Some(c) => c,
            None => continue,
        };
        let mut locked_con = c.lock().unwrap();
        if !locked_con.active {
            continue;
        }
        let dev_name = &locked_con.dev_name.clone();

        if let Some(surface) = &mut locked_con.surface {
            // SAFETY: The image is created within the function, it can be ensure
            // that the data ptr is not nullptr and the image size matches the image data.
            let cairo_image = unsafe {
                ImageSurface::create_for_data_unsafe(
                    surface.data() as *mut u8,
                    Format::Rgb24,
                    surface.width(),
                    surface.height(),
                    surface.stride(),
                )
            }?;
            let mut file = create_file(&mut gpu_info, dev_name)?;
            cairo_image.write_to_png(&mut file)?;
        };
    }
    gpu_info.isSuccess = true;
    Ok(gpu_info)
}

fn create_file(gpu_info: &mut GpuInfo, dev_name: &String) -> Result<fs::File> {
    let temp_dir = env::temp_dir().display().to_string();
    let binding = temp_dir + "/stratovirt-images";
    let path = Path::new(&binding);

    if !path.exists() {
        fs::create_dir(path)?;
    }
    let file_dir = path.display().to_string();
    gpu_info.fileDir = file_dir.clone();
    let nsec = gettime()?.1;
    let file_name = file_dir + "/stratovirt-display-" + dev_name + "-" + &nsec.to_string() + ".png";
    let file = fs::File::create(file_name)?;
    Ok(file)
}
