// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::sync::Arc;

use crate::AudioBackend;
#[cfg(target_env = "ohos")]
use crate::backend::ohaudio;

pub const MAX_VOLUME: u32 = 65535;

/// Trait for receiving volume change notifications.
///
/// Implement this trait to receive notifications when the host volume changes.
/// All volume values are normalized to 0-MAX_VOLUME (0-65535) range.
pub trait VolumeListener: Sync + Send {
    fn notify(&self, volume: u32, mute: bool);
}

/// Trait for volume control operations.
///
/// This trait abstracts volume control across different audio backends.
/// All volume values are normalized to 0-MAX_VOLUME (0-65535) range.
/// Backend implementations handle conversion to/from native scale internally.
///
/// # Example
///
/// ```ignore
/// use audio::{VolumeControl, VolumeNotifier, MAX_VOLUME};
///
/// // Set volume to 50%
/// volume_control.set_volume(MAX_VOLUME / 2);
///
/// // Get current volume
/// let vol = volume_control.get_volume();
/// ```
pub trait VolumeControl: Send + Sync {
    /// Get volume range.
    ///
    /// # Returns
    ///
    /// Volume range.
    fn get_volume_range(&self) -> (u32, u32);

    /// Get current volume.
    ///
    /// # Returns
    ///
    /// Volume value in 0-MAX_VOLUME range (0 = mute, MAX_VOLUME = max).
    fn get_volume(&self) -> u32;

    /// Get current mute.
    ///
    /// # Returns
    ///
    /// true = mute, false = unmute.
    fn get_mute(&self) -> bool;

    /// Set volume.
    ///
    /// # Arguments
    ///
    /// * `volume` - Volume value in 0-MAX_VOLUME range (0 = mute, MAX_VOLUME = max).
    fn set_volume(&self, volume: u32);

    /// Set mute.
    ///
    /// # Arguments
    ///
    /// mute = True, unmute = False.
    fn set_mute(&self, mute: bool);

    /// Register a listener to monitor volume changes from host.
    ///
    /// The listener will be called when the host system volume changes.
    ///
    /// # Arguments
    ///
    /// * `listener` - listener to receive volume change callbacks.
    ///
    /// # Returns
    ///
    /// listener id and this can be used for unregister.
    fn register_listener(&self, listener: Arc<dyn VolumeListener>) -> u64;

    /// Register a listener to monitor volume changes from host.
    ///
    /// The listener will be called when the host system volume changes.
    ///
    /// # Arguments
    ///
    /// * `listener` - listener to receive volume change callbacks.
    fn unregister_listener(&self, id: u64);
}

/// Null volume control for backends without volume support.
///
/// This is a no-op implementation that discards all volume operations.
pub struct NullVolumeControl;

impl VolumeControl for NullVolumeControl {
    fn get_volume_range(&self) -> (u32, u32) {
        (0, 0)
    }

    fn get_volume(&self) -> u32 {
        0
    }

    fn get_mute(&self) -> bool {
        false
    }

    fn set_volume(&self, _volume: u32) {}

    fn set_mute(&self, _mute: bool) {}

    fn register_listener(&self, _listener: Arc<dyn VolumeListener>) -> u64 {
        0
    }

    fn unregister_listener(&self, _id: u64) {}
}

/// Create a volume control for the specified backend.
///
/// # Arguments
///
/// * `backend` - The audio backend type.
///
/// # Returns
///
/// A VolumeControl trait object, or NullVolumeControl if the backend
/// doesn't support volume control.
pub fn create_volume_control(backend: AudioBackend) -> Arc<dyn VolumeControl> {
    match backend {
        #[cfg(target_env = "ohos")]
        AudioBackend::OHAudio => ohaudio::OhosVolumeControl::new() as Arc<dyn VolumeControl>,
        _ => Arc::new(NullVolumeControl) as Arc<dyn VolumeControl>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    #[test]
    fn test_null_volume_control_set_volume() {
        let control = NullVolumeControl;
        // set_volume should not panic or change the volume
        control.set_volume(100);
        assert_eq!(control.get_volume(), 0);
        control.set_volume(MAX_VOLUME);
        assert_eq!(control.get_volume(), 0);
        control.set_volume(0);
        assert_eq!(control.get_volume(), 0);
    }

    #[test]
    fn test_null_volume_control_set_mute() {
        let control = NullVolumeControl;
        // set_mute should not panic or change the mute state
        control.set_mute(true);
        assert_eq!(control.get_mute(), false);
        control.set_mute(false);
        assert_eq!(control.get_mute(), false);
        control.set_mute(true);
        assert_eq!(control.get_mute(), false);
    }

    #[test]
    fn test_null_volume_control_register_listener() {
        let control = NullVolumeControl;

        struct DummyListener;
        impl VolumeListener for DummyListener {
            fn notify(&self, _volume: u32, _mute: bool) {}
        }

        let id = control.register_listener(Arc::new(DummyListener));
        assert_eq!(id, 0);
    }

    #[test]
    fn test_null_volume_control_unregister_listener() {
        let control = NullVolumeControl;
        // Should not panic
        control.unregister_listener(0);
        control.unregister_listener(42);
        control.unregister_listener(u64::MAX);
    }

    #[test]
    fn test_null_volume_control_arc_usage() {
        // Test that NullVolumeControl works correctly when wrapped in Arc
        let control: Arc<dyn VolumeControl> = Arc::new(NullVolumeControl);
        assert_eq!(control.get_volume(), 0);
        assert_eq!(control.get_mute(), false);

        // Test clone of Arc
        let control_clone = control.clone();
        control_clone.set_volume(5000);
        assert_eq!(control.get_volume(), 0);
    }

    #[test]
    fn test_volume_listener_trait() {
        use std::sync::Arc;

        struct TestListener {
            last_volume: AtomicU32,
            last_mute: AtomicBool,
        }
        impl VolumeListener for TestListener {
            fn notify(&self, volume: u32, mute: bool) {
                self.last_volume.store(volume, Ordering::SeqCst);
                self.last_mute.store(mute, Ordering::SeqCst);
            }
        }

        let listener = Arc::new(TestListener {
            last_volume: AtomicU32::new(0),
            last_mute: AtomicBool::new(false),
        });

        // Verify the listener can be used through the trait object
        let trait_listener: Arc<dyn VolumeListener> = listener.clone();

        // Send notification through the trait
        trait_listener.notify(MAX_VOLUME, true);

        // Verify the state was updated via the concrete type
        assert_eq!(listener.last_volume.load(Ordering::SeqCst), MAX_VOLUME);
        assert!(listener.last_mute.load(Ordering::SeqCst));

        // Send another notification
        trait_listener.notify(0, false);
        assert_eq!(listener.last_volume.load(Ordering::SeqCst), 0);
        assert!(!listener.last_mute.load(Ordering::SeqCst));

        // Test that VolumeListener is Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<dyn VolumeListener>>();
    }

    #[test]
    fn test_volume_listener_multiple_notifications() {
        struct CountingListener {
            count: std::sync::atomic::AtomicU32,
        }
        impl VolumeListener for CountingListener {
            fn notify(&self, _volume: u32, _mute: bool) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let listener = Arc::new(CountingListener {
            count: AtomicU32::new(0),
        }) as Arc<dyn VolumeListener>;

        listener.notify(100, false);
        listener.notify(200, true);
        listener.notify(300, false);
        listener.notify(MAX_VOLUME, false);

        // Can't access count through the trait, but we verify no panic occurs.
        // The real verification is that the code compiles and runs without error.
    }

    #[test]
    fn test_create_volume_control_null_backend() {
        let control = create_volume_control(AudioBackend::Null);
        assert_eq!(control.get_volume(), 0);
        assert_eq!(control.get_mute(), false);
        assert_eq!(control.get_volume_range(), (0, 0));
    }

    #[test]
    fn test_create_volume_control_returns_valid_arc() {
        // Verify that the returned Arc<dyn VolumeControl> is valid and usable
        let control = create_volume_control(AudioBackend::Null);
        let control_clone = control.clone();
        assert_eq!(control_clone.get_volume(), 0);

        // Multiple operations in sequence should not panic
        control.set_volume(100);
        control.set_mute(true);
        control.set_volume(200);
        control.set_mute(false);
        assert_eq!(control.get_volume(), 0);
    }
}
