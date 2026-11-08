//! Switch gate: conditions that must hold before the cursor may cross
//! a screen edge onto a remote device.
//!
//! The gate is process-global because the Windows backend has to consult
//! it from inside its low-level mouse hook, where no other state is reachable.

use std::sync::RwLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwitchGate {
    /// the cursor only crosses while Ctrl is held
    pub require_ctrl: bool,
    /// executable names (case-insensitive, e.g. `cs2.exe`) that block
    /// switching while one of them owns the foreground window
    pub blocked_processes: Vec<String>,
    /// block switching while any fullscreen window is in the foreground
    pub block_fullscreen: bool,
}

impl SwitchGate {
    pub const fn new() -> Self {
        Self {
            require_ctrl: true,
            blocked_processes: Vec::new(),
            block_fullscreen: false,
        }
    }
}

impl Default for SwitchGate {
    fn default() -> Self {
        Self::new()
    }
}

static GATE: RwLock<SwitchGate> = RwLock::new(SwitchGate::new());

pub fn set_switch_gate(gate: SwitchGate) {
    log::info!("switch gate: {gate:?}");
    *GATE.write().unwrap_or_else(|e| e.into_inner()) = gate;
}

pub fn switch_gate() -> SwitchGate {
    GATE.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Whether Ctrl is held right now, if the OS lets us ask.
/// `None` on Wayland, where the state is only known from captured events.
pub fn ctrl_held() -> Option<bool> {
    os::ctrl_held()
}

/// Reason why the foreground application blocks switching, if any.
pub fn foreground_block_reason(gate: &SwitchGate) -> Option<String> {
    if gate.blocked_processes.is_empty() && !gate.block_fullscreen {
        return None;
    }
    os::foreground_block_reason(gate)
}

/// Full check for backends that can query everything up front (Windows).
/// Returns the reason when switching must not happen.
pub fn check_switch_now() -> Option<String> {
    let gate = switch_gate();
    if gate.require_ctrl && ctrl_held() == Some(false) {
        return Some("ctrl not held".into());
    }
    foreground_block_reason(&gate)
}

/// Case-insensitive match of an executable path against the block list.
/// Entries match the file name (`cs2.exe`) or, without extension, its stem (`cs2`).
pub fn process_blocked(exe_path: &str, blocked: &[String]) -> bool {
    let file = exe_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(exe_path)
        .to_ascii_lowercase();
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(&file);
    blocked.iter().any(|b| {
        let b = b.to_ascii_lowercase();
        b == file || b == stem
    })
}

#[cfg(windows)]
mod os {
    use super::{SwitchGate, process_blocked};
    use windows::Win32::Foundation::{CloseHandle, HWND, RECT};
    use windows::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_CONTROL};
    use windows::Win32::UI::WindowsAndMessaging::{
        GetDesktopWindow, GetForegroundWindow, GetShellWindow, GetWindowRect,
        GetWindowThreadProcessId,
    };
    use windows::core::PWSTR;

    pub(super) fn ctrl_held() -> Option<bool> {
        // high bit set => key currently down (includes injected input)
        Some(unsafe { GetAsyncKeyState(VK_CONTROL.0 as i32) } < 0)
    }

    pub(super) fn foreground_block_reason(gate: &SwitchGate) -> Option<String> {
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.is_invalid() {
            return None;
        }
        if !gate.blocked_processes.is_empty() {
            if let Some(exe) = process_path(hwnd) {
                if process_blocked(&exe, &gate.blocked_processes) {
                    return Some(format!("blocked process in foreground: {exe}"));
                }
            }
        }
        if gate.block_fullscreen && is_fullscreen(hwnd) {
            return Some("fullscreen window in foreground".into());
        }
        None
    }

    fn process_path(hwnd: HWND) -> Option<String> {
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid == 0 {
            return None;
        }
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let res = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        let _ = unsafe { CloseHandle(process) };
        res.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn is_fullscreen(hwnd: HWND) -> bool {
        // the desktop / shell cover the whole screen but are not "fullscreen apps"
        if hwnd == unsafe { GetDesktopWindow() } || hwnd == unsafe { GetShellWindow() } {
            return false;
        }
        let mut rect = RECT::default();
        if unsafe { GetWindowRect(hwnd, &mut rect) }.is_err() {
            return false;
        }
        let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if !unsafe { GetMonitorInfoW(monitor, &mut info) }.as_bool() {
            return false;
        }
        let m = info.rcMonitor;
        rect.left <= m.left && rect.top <= m.top && rect.right >= m.right && rect.bottom >= m.bottom
    }
}

#[cfg(not(windows))]
mod os {
    use super::SwitchGate;

    pub(super) fn ctrl_held() -> Option<bool> {
        None
    }

    pub(super) fn foreground_block_reason(_gate: &SwitchGate) -> Option<String> {
        // TODO: KDE/KWin active-window query
        None
    }
}

#[cfg(test)]
mod tests {
    use super::process_blocked;

    #[test]
    fn matches_exe_and_stem_case_insensitive() {
        let list = vec!["CS2.exe".to_string(), "eldenring".to_string()];
        assert!(process_blocked(r"C:\Games\cs2\cs2.exe", &list));
        assert!(process_blocked(r"D:\ER\Game\eldenring.exe", &list));
        assert!(!process_blocked(r"C:\Windows\explorer.exe", &list));
        assert!(process_blocked("/usr/bin/eldenring", &list));
    }
}
