//! Drawn cursor for Windows machines without a mouse.
//!
//! Windows hides the pointer when no mouse device is attached, even though
//! injected motion still moves it. While input is being emulated and the
//! system cursor is not showing, a click-through topmost window draws an
//! arrow at the cursor position (like Mouse without Borders' "draw mouse").

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateSolidBrush, DeleteObject, EndPaint, FillRect, HGDIOBJ, PAINTSTRUCT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CURSOR_SHOWING, CURSORINFO, CreateWindowExW, DI_NORMAL, DefWindowProcW,
    DispatchMessageW, DrawIconEx, GetCursorInfo, GetCursorPos, GetMessageW, HICON, HWND_TOPMOST,
    IDC_ARROW, LWA_COLORKEY, LoadCursorW, MSG, RegisterClassW, SW_HIDE, SW_SHOWNOACTIVATE,
    SWP_NOACTIVATE, SWP_NOOWNERZORDER, SWP_NOSIZE, SWP_NOZORDER, SetLayeredWindowAttributes,
    SetTimer, SetWindowPos, ShowWindow, TranslateMessage, WM_PAINT, WM_TIMER, WNDCLASSW,
    WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
};
use windows::core::w;

/// overlay disappears this long after the last emulated input
const IDLE_HIDE: Duration = Duration::from_secs(3);
const SIZE: i32 = 32;
/// transparent background (color key)
const KEY: COLORREF = COLORREF(0x00FF00FF);

static START: OnceLock<Instant> = OnceLock::new();
/// ms since START of the last emulated input, 0 = never
static LAST_INPUT: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    START.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

/// Record emulated input; starts the overlay thread on first use.
pub(crate) fn notify_input() {
    static STARTED: OnceLock<()> = OnceLock::new();
    LAST_INPUT.store(now_ms(), Ordering::Relaxed);
    STARTED.get_or_init(|| {
        let _ = std::thread::Builder::new()
            .name("uwu-cursor".into())
            .spawn(|| {
                if let Err(e) = run() {
                    log::warn!("cursor overlay unavailable: {e}");
                }
            });
    });
}

fn run() -> windows::core::Result<()> {
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = w!("UwUMouseCursor");
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            hInstance: instance.into(),
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            class,
            w!("UwUMouse cursor"),
            WS_POPUP,
            0,
            0,
            SIZE,
            SIZE,
            None,
            None,
            Some(instance.into()),
            None,
        )?;
        SetLayeredWindowAttributes(hwnd, KEY, 255, LWA_COLORKEY)?;
        SetTimer(Some(hwnd), 1, 15, None);
        log::info!("cursor overlay ready");
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

static mut VISIBLE: bool = false;
static mut LAST_POS: (i32, i32) = (i32::MIN, i32::MIN);

unsafe fn tick(hwnd: HWND) {
    let last = LAST_INPUT.load(Ordering::Relaxed);
    let active = last != 0 && now_ms().saturating_sub(last) < IDLE_HIDE.as_millis() as u64;
    let mut info = CURSORINFO {
        cbSize: std::mem::size_of::<CURSORINFO>() as u32,
        ..Default::default()
    };
    let system_shows =
        unsafe { GetCursorInfo(&mut info) }.is_ok() && (info.flags.0 & CURSOR_SHOWING.0) != 0;
    let want = active && !system_shows;
    let mut pos = POINT::default();
    // Only touch the z-order when the overlay appears: re-asserting
    // HWND_TOPMOST on every tick makes light-dismiss UI (Start menu,
    // search, tray flyouts) close immediately.
    let showing_now = unsafe { want && !VISIBLE };
    if want && unsafe { GetCursorPos(&mut pos) }.is_ok() {
        unsafe {
            if showing_now || (pos.x, pos.y) != LAST_POS {
                LAST_POS = (pos.x, pos.y);
                let mut flags = SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER;
                if !showing_now {
                    flags |= SWP_NOZORDER;
                }
                let _ = SetWindowPos(hwnd, Some(HWND_TOPMOST), pos.x, pos.y, 0, 0, flags);
            }
        }
    }
    unsafe {
        if want != VISIBLE {
            VISIBLE = want;
            let _ = ShowWindow(hwnd, if want { SW_SHOWNOACTIVATE } else { SW_HIDE });
        }
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TIMER => {
            unsafe { tick(hwnd) };
            LRESULT(0)
        }
        WM_PAINT => {
            unsafe {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let brush = CreateSolidBrush(KEY);
                let rect = RECT {
                    left: 0,
                    top: 0,
                    right: SIZE,
                    bottom: SIZE,
                };
                FillRect(hdc, &rect, brush);
                let _ = DeleteObject(HGDIOBJ(brush.0));
                if let Ok(cursor) = LoadCursorW(None, IDC_ARROW) {
                    let _ = DrawIconEx(hdc, 0, 0, HICON(cursor.0), SIZE, SIZE, 0, None, DI_NORMAL);
                }
                let _ = EndPaint(hwnd, &ps);
            }
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Windows only shows its own cursor when a mouse is attached or Mouse
/// Keys are active. On a mouseless machine, turn Mouse Keys on (active
/// while NumLock is off) so the real cursor shows everywhere, including
/// the Start menu, which the overlay cannot draw over.
pub(crate) fn enable_mouse_keys_if_mouseless() {
    use windows::Win32::UI::Accessibility::MOUSEKEYS;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, MKF_AVAILABLE, MKF_MOUSEKEYSON, MKF_REPLACENUMBERS, SM_MOUSEPRESENT,
        SPI_GETMOUSEKEYS, SPI_SETMOUSEKEYS, SPIF_SENDCHANGE, SPIF_UPDATEINIFILE,
        SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SystemParametersInfoW,
    };
    let size = std::mem::size_of::<MOUSEKEYS>() as u32;
    let mut mk = MOUSEKEYS {
        cbSize: size,
        ..Default::default()
    };
    unsafe {
        if SystemParametersInfoW(
            SPI_GETMOUSEKEYS,
            size,
            Some(&mut mk as *mut _ as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
        .is_err()
        {
            return;
        }
        if mk.dwFlags & MKF_MOUSEKEYSON != 0 || GetSystemMetrics(SM_MOUSEPRESENT) != 0 {
            return;
        }
        mk.dwFlags = (mk.dwFlags | MKF_MOUSEKEYSON | MKF_AVAILABLE) & !MKF_REPLACENUMBERS;
        match SystemParametersInfoW(
            SPI_SETMOUSEKEYS,
            size,
            Some(&mut mk as *mut _ as *mut _),
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
        ) {
            Ok(()) => log::info!("no mouse attached: enabled Mouse Keys so the cursor is shown"),
            Err(e) => log::warn!("could not enable Mouse Keys: {e}"),
        }
    }
}
