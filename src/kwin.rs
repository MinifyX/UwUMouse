//! KDE integration for the switch gate: a KWin script reports the active
//! window (class, pid, fullscreen) over D-Bus, so fullscreen games and
//! blocked processes can stop the cursor from crossing, like on Windows.

use input_capture::gate::{ActiveWindow, set_active_window};
use std::path::PathBuf;

const BUS_NAME: &str = "de.minifyx.UwUMouse";
const SCRIPT_NAME: &str = "uwumouse-gate";

const SCRIPT: &str = r#"// UwUMouse: reports the active window to the UwUMouse daemon
function report(w) {
    var fs = false, cls = "", pid = "0";
    if (w) {
        fs = w.fullScreen;
        if (!fs && !w.desktopWindow && !w.dock) {
            // borderless "fullscreen" games are plain windows covering the screen
            var a = workspace.clientArea(KWin.FullScreenArea, w);
            var g = w.frameGeometry;
            fs = g.x <= a.x && g.y <= a.y &&
                 g.x + g.width >= a.x + a.width && g.y + g.height >= a.y + a.height;
        }
        cls = String(w.resourceClass || "");
        pid = String(w.pid || 0);
    }
    callDBus("de.minifyx.UwUMouse", "/Gate", "de.minifyx.UwUMouse.Gate", "Active",
             fs ? "1" : "0", cls, pid);
}
var watched = null;
function onChange() { report(workspace.activeWindow); }
function onActivated(w) {
    if (watched) {
        try { watched.fullScreenChanged.disconnect(onChange); } catch (e) {}
        try { watched.frameGeometryChanged.disconnect(onChange); } catch (e) {}
    }
    watched = w;
    if (w) {
        w.fullScreenChanged.connect(onChange);
        w.frameGeometryChanged.connect(onChange);
    }
    report(w);
}
workspace.windowActivated.connect(onActivated);
onActivated(workspace.activeWindow);
"#;

struct Gate;

#[zbus::interface(name = "de.minifyx.UwUMouse.Gate")]
impl Gate {
    async fn active(&self, fullscreen: &str, class: &str, pid: &str) {
        set_active_window(Some(ActiveWindow {
            fullscreen: fullscreen == "1",
            class: class.to_string(),
            pid: pid.parse().unwrap_or(0),
        }));
    }
}

/// Start the KDE integration on its own thread (no-op outside KDE).
pub fn start() {
    let kde = std::env::var("XDG_CURRENT_DESKTOP")
        .map(|d| d.to_ascii_uppercase().contains("KDE"))
        .unwrap_or(false);
    if !kde {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("uwu-kwin".into())
        .spawn(|| {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return log::warn!("kwin integration: {e}"),
            };
            rt.block_on(async {
                if let Err(e) = run().await {
                    log::warn!("kwin integration unavailable: {e}");
                }
            });
        });
}

fn script_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("uwumouse").join("kwin-gate.js")
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let conn = zbus::connection::Builder::session()?
        .name(BUS_NAME)?
        .serve_at("/Gate", Gate)?
        .build()
        .await?;

    let path = script_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, SCRIPT)?;

    let scripting = zbus::Proxy::new(
        &conn,
        "org.kde.KWin",
        "/Scripting",
        "org.kde.kwin.Scripting",
    )
    .await?;
    // replace a script left over from a previous run
    let _: bool = scripting
        .call("unloadScript", &(SCRIPT_NAME,))
        .await
        .unwrap_or(false);
    let id: i32 = scripting
        .call("loadScript", &(path.to_string_lossy().as_ref(), SCRIPT_NAME))
        .await?;
    scripting.call::<_, _, ()>("start", &()).await?;
    log::info!("kwin integration active (script id {id})");

    // keep serving the D-Bus object
    std::future::pending::<()>().await;
    Ok(())
}
