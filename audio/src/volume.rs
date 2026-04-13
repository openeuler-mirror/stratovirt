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
    fn notify(&self, volume: u32);
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

    /// Set volume.
    ///
    /// # Arguments
    ///
    /// * `volume` - Volume value in 0-MAX_VOLUME range (0 = mute, MAX_VOLUME = max).
    fn set_volume(&self, volume: u32);

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

    fn set_volume(&self, _volume: u32) {}

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
