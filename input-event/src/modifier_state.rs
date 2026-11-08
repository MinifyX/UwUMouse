//! Process-wide view of the local keyboard modifier state.
//!
//! On KDE Wayland the input-capture connection does not learn whether Ctrl
//! was held when the pointer hit a barrier, but the emulation (sender)
//! connection receives every modifier change from the compositor. The
//! emulation backend records it here so the switch gate can read it.

use std::sync::atomic::{AtomicU8, Ordering};

const UNKNOWN: u8 = 0;
const UP: u8 = 1;
const DOWN: u8 = 2;

static CTRL: AtomicU8 = AtomicU8::new(UNKNOWN);

/// xkb modifier mask for Control
pub const XKB_CTRL_MASK: u32 = 1 << 2;

/// record the depressed xkb modifier mask reported by the compositor
pub fn set_depressed(depressed: u32) {
    let state = if depressed & XKB_CTRL_MASK != 0 { DOWN } else { UP };
    CTRL.store(state, Ordering::Relaxed);
}

/// whether Ctrl is held, if any backend has reported modifier state
pub fn ctrl_held() -> Option<bool> {
    match CTRL.load(Ordering::Relaxed) {
        UP => Some(false),
        DOWN => Some(true),
        _ => None,
    }
}
