pub mod base_device;
#[cfg(not(target_env = "musl"))]
pub mod dpy_device;
#[cfg(not(target_env = "musl"))]
pub mod gpu_device;
#[cfg(not(target_env = "musl"))]
pub mod kbd_pointer_device;
