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

//! Audio authority management.
//!
//! This module provides authority control for audio capture operations.
//! It uses an observer pattern to notify multiple listeners when the
//! record authority state changes.
//!
//! ## Architecture
//!
//! - `RecordAuthority`: Core authority management with multi-listener support
//! - `AuthorityNotifier`: Trait for receiving authority change notifications
//! - Global instance: Convenient singleton for simple use cases
//!
//! ## Usage
//!
//! ```ignore
//! use audio::{get_record_authority, set_record_authority, AuthorityNotifier};
//!
//! // Check authority
//! if get_record_authority() {
//!     // Capture is permitted
//! }
//!
//! // Register a notifier
//! struct MyNotifier;
//! impl AuthorityNotifier for MyNotifier {
//!     fn on_authority_changed(&self, has_authority: bool) {
//!         println!("Authority changed to: {}", has_authority);
//!     }
//! }
//! register_authority_notifier(Arc::new(MyNotifier));
//! ```

use std::sync::{
    Arc, LazyLock, RwLock,
    atomic::{AtomicBool, Ordering},
};

/// Trait for receiving authority change notifications.
///
/// Implement this trait to be notified when the record authority state changes.
pub trait AuthorityNotifier: Send + Sync {
    /// Called when the record authority state changes.
    ///
    /// # Arguments
    ///
    /// * `has_authority` - `true` if capture is now permitted, `false` otherwise.
    fn on_authority_changed(&self, has_authority: bool);
}

/// Record authority management with multi-listener support.
///
/// This struct manages the authority state for audio capture and notifies
/// all registered listeners when the state changes.
pub struct RecordAuthority {
    /// Current authority state.
    state: AtomicBool,
    /// Registered notifiers for authority changes.
    notifiers: RwLock<Vec<Arc<dyn AuthorityNotifier>>>,
}

impl RecordAuthority {
    /// Create a new RecordAuthority with the given initial state.
    pub fn new(initial_state: bool) -> Self {
        Self {
            state: AtomicBool::new(initial_state),
            notifiers: RwLock::new(Vec::new()),
        }
    }

    /// Set the record authority state.
    ///
    /// If the state changes, all registered notifiers will be called.
    ///
    /// # Arguments
    ///
    /// * `has_authority` - `true` to permit capture, `false` to disable.
    pub fn set_authority(&self, has_authority: bool) {
        let old_state = self.state.swap(has_authority, Ordering::Relaxed);
        if old_state != has_authority {
            self.notify_all(has_authority);
        }
    }

    /// Get the current record authority state.
    ///
    /// # Returns
    ///
    /// `true` if capture is permitted, `false` otherwise.
    pub fn has_authority(&self) -> bool {
        self.state.load(Ordering::Acquire)
    }

    /// Register a notifier for authority changes.
    ///
    /// The notifier will be called whenever the authority state changes.
    ///
    /// # Arguments
    ///
    /// * `notifier` - The notifier to register.
    pub fn register_notifier(&self, notifier: Arc<dyn AuthorityNotifier>) {
        self.notifiers.write().unwrap().push(notifier);
    }

    /// Unregister a notifier.
    ///
    /// # Arguments
    ///
    /// * `notifier` - The notifier to unregister (compared by Arc pointer).
    pub fn unregister_notifier(&self, notifier: &Arc<dyn AuthorityNotifier>) {
        let mut notifiers = self.notifiers.write().unwrap();
        notifiers.retain(|n| !Arc::ptr_eq(n, notifier));
    }

    /// Clear all registered notifiers.
    pub fn clear_notifiers(&self) {
        self.notifiers.write().unwrap().clear();
    }

    /// Notify all registered notifiers of a state change.
    ///
    /// Clones the notifier list before iteration to avoid holding the read lock
    /// while calling external code, which could cause deadlock if a notifier
    /// attempts to register/unregister during its callback.
    fn notify_all(&self, has_authority: bool) {
        let notifiers: Vec<Arc<dyn AuthorityNotifier>> =
            self.notifiers.read().unwrap().iter().cloned().collect();
        for notifier in notifiers.iter() {
            notifier.on_authority_changed(has_authority);
        }
    }
}

// ============================================================================
// Global Instance API
// ============================================================================

/// Global record authority instance.
static RECORD_AUTHORITY: LazyLock<Arc<RecordAuthority>> =
    LazyLock::new(|| Arc::new(RecordAuthority::new(true)));

/// Get the global record authority instance.
///
/// This returns a reference to the global singleton. For multi-VM scenarios,
/// consider creating separate `RecordAuthority` instances instead.
pub fn global_record_authority() -> Arc<RecordAuthority> {
    RECORD_AUTHORITY.clone()
}

/// Set the record authority state on the global instance.
///
/// When `auth` is `false`, audio capture is disabled.
/// When `auth` is `true`, audio capture is enabled.
///
/// All registered notifiers will be called if the state changes.
pub fn set_record_authority(auth: bool) {
    RECORD_AUTHORITY.set_authority(auth);
}

/// Get the current record authority state from the global instance.
///
/// Returns `true` if audio capture is permitted, `false` otherwise.
pub fn get_record_authority() -> bool {
    RECORD_AUTHORITY.has_authority()
}

/// Register a notifier for authority changes on the global instance.
///
/// The notifier will be called whenever the authority state changes.
///
/// # Arguments
///
/// * `notifier` - The notifier to register.
pub fn register_authority_notifier(notifier: Arc<dyn AuthorityNotifier>) {
    RECORD_AUTHORITY.register_notifier(notifier);
}

/// Unregister a notifier from the global instance.
///
/// # Arguments
///
/// * `notifier` - The notifier to unregister (compared by Arc pointer).
pub fn unregister_authority_notifier(notifier: &Arc<dyn AuthorityNotifier>) {
    RECORD_AUTHORITY.unregister_notifier(notifier);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn test_record_authority_basic() {
        let auth = RecordAuthority::new(true);
        assert!(auth.has_authority());

        auth.set_authority(false);
        assert!(!auth.has_authority());

        auth.set_authority(true);
        assert!(auth.has_authority());
    }

    #[test]
    fn test_authority_notifier() {
        let auth = RecordAuthority::new(true);
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        struct TestNotifier {
            call_count: Arc<AtomicUsize>,
        }
        impl AuthorityNotifier for TestNotifier {
            fn on_authority_changed(&self, _has_authority: bool) {
                self.call_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let notifier = Arc::new(TestNotifier {
            call_count: call_count_clone,
        }) as Arc<dyn AuthorityNotifier>;
        auth.register_notifier(notifier.clone());

        // State changes should trigger notification
        auth.set_authority(false);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        auth.set_authority(true);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);

        // Same state should not trigger notification
        auth.set_authority(true);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);

        // Unregister should stop notifications
        auth.unregister_notifier(&notifier);
        auth.set_authority(false);
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_multiple_notifiers() {
        let auth = RecordAuthority::new(true);
        let counter = Arc::new(AtomicUsize::new(0));

        struct CountingNotifier {
            counter: Arc<AtomicUsize>,
        }
        impl AuthorityNotifier for CountingNotifier {
            fn on_authority_changed(&self, _has_authority: bool) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let n1: Arc<dyn AuthorityNotifier> = Arc::new(CountingNotifier {
            counter: counter.clone(),
        });
        let n2: Arc<dyn AuthorityNotifier> = Arc::new(CountingNotifier {
            counter: counter.clone(),
        });

        auth.register_notifier(n1.clone());
        auth.register_notifier(n2.clone());

        auth.set_authority(false);
        assert_eq!(counter.load(Ordering::SeqCst), 2); // Both notifiers called

        auth.unregister_notifier(&n1);
        auth.set_authority(true);
        assert_eq!(counter.load(Ordering::SeqCst), 3); // Only n2 called
    }

    #[test]
    fn test_global_instance() {
        // Reset to known state
        set_record_authority(true);

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        struct GlobalNotifier {
            counter: Arc<AtomicUsize>,
        }
        impl AuthorityNotifier for GlobalNotifier {
            fn on_authority_changed(&self, _has_authority: bool) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let notifier: Arc<dyn AuthorityNotifier> = Arc::new(GlobalNotifier {
            counter: counter_clone,
        });
        register_authority_notifier(notifier.clone());

        set_record_authority(false);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(!get_record_authority());

        unregister_authority_notifier(&notifier);
        set_record_authority(true);
        assert_eq!(counter.load(Ordering::SeqCst), 1); // No change after unregister
    }
}
