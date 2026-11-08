//! Clipboard and file transfer ("data channel").
//!
//! Runs on its own thread with its own tokio runtime so large transfers
//! never stall input forwarding. Peers talk TLS over TCP on
//! `lan-mouse port + 1`, authenticated with the same certificates and
//! authorized fingerprints as the input channel.
//!
//! Sync model (like Deskflow / Mouse without Borders): whenever control
//! leaves a device, that device sends its clipboard to the device that
//! takes over. Files on the clipboard are copied into
//! `Downloads/UwUMouse/<timestamp>/` on the receiver and put on its
//! clipboard, so pasting in Explorer / Dolphin drops them in place.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, RwLock, mpsc as std_mpsc},
    thread,
    time::{Duration, SystemTime},
};

use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use webrtc_dtls::crypto::Certificate;

use crate::crypto;

/// user-facing settings (`[transfer]` in config.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferConfig {
    pub clipboard: bool,
    pub files: bool,
    /// refuse to send file sets larger than this
    pub max_file_bytes: u64,
    /// where received files are stored
    pub receive_dir: PathBuf,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            clipboard: true,
            files: true,
            max_file_bytes: 4 << 30,
            receive_dir: default_receive_dir(),
        }
    }
}

pub fn default_receive_dir() -> PathBuf {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    home.map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Downloads")
        .join("UwUMouse")
}

/// largest clipboard payload (text / html / image) accepted
const MAX_CLIP_BYTES: u64 = 256 << 20;
/// largest frame header accepted
const MAX_HEADER_BYTES: u32 = 4 << 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

enum Cmd {
    /// make sure a data connection to this peer exists, then send the clipboard
    PushTo(SocketAddr),
    /// send the clipboard over an existing connection with this peer
    PushIp(IpAddr),
    Config(TransferConfig),
}

/// handle owned by the service
pub(crate) struct DataChannel {
    tx: mpsc::UnboundedSender<Cmd>,
}

impl DataChannel {
    pub(crate) fn new(
        port: u16,
        cert: Certificate,
        authorized: Arc<RwLock<HashMap<String, String>>>,
        config: TransferConfig,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        thread::Builder::new()
            .name("uwu-transfer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("transfer runtime");
                rt.block_on(async move {
                    if let Err(e) = run(port, cert, authorized, config, rx).await {
                        log::error!("data channel stopped: {e}");
                    }
                });
            })
            .expect("spawn transfer thread");
        Self { tx }
    }

    /// control moves to the peer whose lan-mouse endpoint is `addr`
    pub(crate) fn push_to(&self, addr: SocketAddr) {
        let data_addr = SocketAddr::new(addr.ip(), addr.port().wrapping_add(1));
        let _ = self.tx.send(Cmd::PushTo(data_addr));
    }

    /// control moves back to the peer at `ip` (which connected to us)
    pub(crate) fn push_ip(&self, ip: IpAddr) {
        let _ = self.tx.send(Cmd::PushIp(ip));
    }

    pub(crate) fn set_config(&self, config: TransferConfig) {
        let _ = self.tx.send(Cmd::Config(config));
    }
}

/* ---------------------------------------------------------------- wire */

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
enum Header {
    /// body: utf-8 text
    Text,
    /// body: utf-8 html
    Html {
        alt: Option<String>,
    },
    /// body: rgba8 pixels
    Image {
        width: usize,
        height: usize,
    },
    /// announces a file set, followed by one `FileData` per non-dir entry
    FilesBegin {
        id: u64,
        entries: Vec<Entry>,
    },
    /// body: contents of `entries[index]`
    FileData {
        id: u64,
        index: usize,
    },
    FilesEnd {
        id: u64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Entry {
    /// relative, `/`-separated
    path: String,
    size: u64,
    dir: bool,
}

enum Body {
    None,
    Bytes(Vec<u8>),
    File(PathBuf, u64),
}

struct Frame {
    header: Header,
    body: Body,
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: Frame) -> io::Result<()> {
    let header = serde_json::to_vec(&frame.header).map_err(io::Error::other)?;
    w.write_u32(header.len() as u32).await?;
    w.write_all(&header).await?;
    match frame.body {
        Body::None => w.write_u64(0).await?,
        Body::Bytes(b) => {
            w.write_u64(b.len() as u64).await?;
            w.write_all(&b).await?;
        }
        Body::File(path, size) => {
            w.write_u64(size).await?;
            let f = tokio::fs::File::open(&path).await?;
            // never send more than announced, even if the file grew
            let copied = tokio::io::copy(&mut f.take(size), w).await?;
            if copied != size {
                return Err(io::Error::other(format!(
                    "{} changed while sending",
                    path.display()
                )));
            }
        }
    }
    w.flush().await
}

async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(Header, u64)> {
    let len = r.read_u32().await?;
    if len > MAX_HEADER_BYTES {
        return Err(io::Error::other("header too large"));
    }
    let mut buf = vec![0; len as usize];
    r.read_exact(&mut buf).await?;
    let header = serde_json::from_slice(&buf).map_err(io::Error::other)?;
    let body_len = r.read_u64().await?;
    Ok((header, body_len))
}

async fn read_body<R: AsyncRead + Unpin>(r: &mut R, len: u64) -> io::Result<Vec<u8>> {
    if len > MAX_CLIP_BYTES {
        return Err(io::Error::other("clipboard payload too large"));
    }
    let mut buf = vec![0; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/* ------------------------------------------------------------ clipboard */

#[derive(Debug, Clone, PartialEq)]
enum ClipContent {
    Text(String),
    Html {
        html: String,
        alt: Option<String>,
    },
    Image {
        width: usize,
        height: usize,
        rgba: Vec<u8>,
    },
    Files(Vec<PathBuf>),
}

impl ClipContent {
    /// identity used to avoid re-sending what we just received / sent
    fn signature(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        match self {
            ClipContent::Text(t) => {
                h.update(b"text");
                h.update(t.as_bytes());
            }
            ClipContent::Html { html, .. } => {
                h.update(b"html");
                h.update(html.as_bytes());
            }
            ClipContent::Image {
                width,
                height,
                rgba,
            } => {
                h.update(b"image");
                h.update(width.to_le_bytes());
                h.update(height.to_le_bytes());
                h.update(rgba);
            }
            ClipContent::Files(paths) => {
                h.update(b"files");
                for p in paths {
                    h.update(p.to_string_lossy().as_bytes());
                    h.update([0]);
                }
            }
        }
        h.finalize().into()
    }
}

enum ClipOp {
    Read(oneshot::Sender<Option<ClipContent>>),
    Write(ClipContent, oneshot::Sender<bool>),
}

/// owns the OS clipboard on a dedicated thread (Wayland data-control and
/// the Windows clipboard both prefer a long-lived owner)
#[derive(Clone)]
struct ClipboardWorker {
    tx: std_mpsc::Sender<ClipOp>,
}

impl ClipboardWorker {
    fn spawn() -> Self {
        let (tx, rx) = std_mpsc::channel::<ClipOp>();
        thread::Builder::new()
            .name("uwu-clipboard".into())
            .spawn(move || {
                let mut clipboard = match arboard::Clipboard::new() {
                    Ok(c) => Some(c),
                    Err(e) => {
                        log::warn!("clipboard unavailable: {e}");
                        None
                    }
                };
                for op in rx {
                    match op {
                        ClipOp::Read(reply) => {
                            let c = clipboard.as_mut().and_then(read_clipboard);
                            let _ = reply.send(c);
                        }
                        ClipOp::Write(content, reply) => {
                            let ok = clipboard
                                .as_mut()
                                .map(|c| write_clipboard(c, content))
                                .unwrap_or(false);
                            let _ = reply.send(ok);
                        }
                    }
                }
            })
            .expect("spawn clipboard thread");
        Self { tx }
    }

    async fn read(&self) -> Option<ClipContent> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(ClipOp::Read(tx)).ok()?;
        rx.await.ok().flatten()
    }

    async fn write(&self, content: ClipContent) -> bool {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(ClipOp::Write(content, tx)).is_err() {
            return false;
        }
        rx.await.unwrap_or(false)
    }
}

fn read_clipboard(c: &mut arboard::Clipboard) -> Option<ClipContent> {
    if let Ok(files) = c.get().file_list() {
        if !files.is_empty() {
            return Some(ClipContent::Files(files));
        }
    }
    if let Ok(img) = c.get_image() {
        return Some(ClipContent::Image {
            width: img.width,
            height: img.height,
            rgba: img.bytes.into_owned(),
        });
    }
    let text = c.get_text().ok();
    if let Ok(html) = c.get().html() {
        if !html.is_empty() {
            return Some(ClipContent::Html { html, alt: text });
        }
    }
    text.filter(|t| !t.is_empty()).map(ClipContent::Text)
}

fn write_clipboard(c: &mut arboard::Clipboard, content: ClipContent) -> bool {
    let r = match content {
        ClipContent::Text(t) => c.set_text(t),
        ClipContent::Html { html, alt } => c.set_html(html, alt),
        ClipContent::Image {
            width,
            height,
            rgba,
        } => c.set_image(arboard::ImageData {
            width,
            height,
            bytes: rgba.into(),
        }),
        ClipContent::Files(paths) => c.set().file_list(&paths),
    };
    if let Err(e) = &r {
        log::warn!("could not set clipboard: {e}");
    }
    r.is_ok()
}

/* ------------------------------------------------------------------ tls */

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn identity(cert: &Certificate) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert.private_key.serialized_der.clone(),
    ));
    (cert.certificate.clone(), key)
}

/// Accepts any certificate during the handshake; authorization happens
/// afterwards by fingerprint, exactly like the input channel.
#[derive(Debug)]
struct AnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for AnyCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn acceptor(cert: &Certificate) -> Result<TlsAcceptor, rustls::Error> {
    let p = provider();
    let (chain, key) = identity(cert);
    let config = rustls::ServerConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(AnyCert(p)))
        .with_single_cert(chain, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn connector(cert: &Certificate) -> Result<TlsConnector, rustls::Error> {
    let p = provider();
    let (chain, key) = identity(cert);
    let config = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(p)))
        .with_client_auth_cert(chain, key)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/* ------------------------------------------------------------- service */

/// state shared by all connection tasks
struct Shared {
    clipboard: ClipboardWorker,
    config: RwLock<TransferConfig>,
    /// signature of what was last sent or applied, to avoid ping-pong
    last_sig: Mutex<Option<[u8; 32]>>,
    /// writer queue per connected peer
    conns: Mutex<HashMap<IpAddr, mpsc::Sender<Frame>>>,
}

async fn run(
    port: u16,
    cert: Certificate,
    authorized: Arc<RwLock<HashMap<String, String>>>,
    config: TransferConfig,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
) -> io::Result<()> {
    let acceptor = acceptor(&cert).map_err(io::Error::other)?;
    let connector = connector(&cert).map_err(io::Error::other)?;
    let shared = Arc::new(Shared {
        clipboard: ClipboardWorker::spawn(),
        config: RwLock::new(config),
        last_sig: Mutex::new(None),
        conns: Mutex::new(HashMap::new()),
    });

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    log::info!("data channel listening on tcp port {port}");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, addr) = match accepted {
                    Ok(a) => a,
                    Err(e) => { log::warn!("data channel accept: {e}"); continue }
                };
                let acceptor = acceptor.clone();
                let authorized = authorized.clone();
                let shared = shared.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    let tls = match acceptor.accept(stream).await {
                        Ok(t) => t,
                        Err(e) => return log::warn!("data channel tls from {addr}: {e}"),
                    };
                    let fingerprint = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|c| c.first())
                        .map(|c| crypto::generate_fingerprint(c));
                    let authorized = fingerprint
                        .as_ref()
                        .is_some_and(|f| authorized.read().expect("lock").contains_key(f));
                    if !authorized {
                        return log::warn!("data channel: rejected unauthorized peer {addr}");
                    }
                    log::info!("data channel: {addr} connected");
                    serve(tls, addr.ip(), shared).await;
                });
            }
            cmd = rx.recv() => match cmd {
                None => return Ok(()),
                Some(Cmd::Config(c)) => *shared.config.write().expect("lock") = c,
                Some(Cmd::PushTo(addr)) => {
                    let shared = shared.clone();
                    let connector = connector.clone();
                    tokio::spawn(async move {
                        if !shared.conns.lock().expect("lock").contains_key(&addr.ip()) {
                            if let Err(e) = dial(addr, connector, shared.clone()).await {
                                return log::warn!("data channel: cannot reach {addr}: {e}");
                            }
                        }
                        push(addr.ip(), &shared).await;
                    });
                }
                Some(Cmd::PushIp(ip)) => {
                    let shared = shared.clone();
                    tokio::spawn(async move { push(ip, &shared).await });
                }
            }
        }
    }
}

async fn dial(addr: SocketAddr, connector: TlsConnector, shared: Arc<Shared>) -> io::Result<()> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    stream.set_nodelay(true)?;
    let name = ServerName::try_from("uwumouse").expect("valid name");
    let tls = connector.connect(name, stream).await?;
    log::info!("data channel: connected to {addr}");
    let ip = addr.ip();
    // register before returning so the caller's push finds the connection
    let (tx, writer_rx) = mpsc::channel(16);
    shared.conns.lock().expect("lock").insert(ip, tx.clone());
    tokio::spawn(run_conn(tls, ip, shared, tx, writer_rx));
    Ok(())
}

async fn serve<S>(stream: S, ip: IpAddr, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, writer_rx) = mpsc::channel(16);
    shared.conns.lock().expect("lock").insert(ip, tx.clone());
    run_conn(stream, ip, shared, tx, writer_rx).await;
}

async fn run_conn<S>(
    stream: S,
    ip: IpAddr,
    shared: Arc<Shared>,
    own_tx: mpsc::Sender<Frame>,
    mut writer_rx: mpsc::Receiver<Frame>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let writer_task = tokio::spawn(async move {
        let mut writer = BufWriter::with_capacity(256 << 10, writer);
        while let Some(frame) = writer_rx.recv().await {
            if let Err(e) = write_frame(&mut writer, frame).await {
                log::warn!("data channel: send to {ip} failed: {e}");
                break;
            }
        }
    });
    if let Err(e) = receive_loop(&mut reader, ip, &shared).await {
        if e.kind() != io::ErrorKind::UnexpectedEof {
            log::warn!("data channel: {ip}: {e}");
        }
    }
    log::info!("data channel: {ip} disconnected");
    writer_task.abort();
    let mut conns = shared.conns.lock().expect("lock");
    // only remove our own entry (a reconnect may have replaced it)
    if conns.get(&ip).is_some_and(|tx| tx.same_channel(&own_tx)) {
        conns.remove(&ip);
    }
}

/* ---------------------------------------------------------------- send */

async fn push(ip: IpAddr, shared: &Shared) {
    let config = shared.config.read().expect("lock").clone();
    if !config.clipboard {
        return;
    }
    let Some(tx) = shared.conns.lock().expect("lock").get(&ip).cloned() else {
        return log::debug!("data channel: no connection to {ip}, clipboard not sent");
    };
    let Some(content) = shared.clipboard.read().await else {
        return;
    };
    let sig = content.signature();
    if *shared.last_sig.lock().expect("lock") == Some(sig) {
        return log::debug!("clipboard unchanged, not sending");
    }
    let frames = match content {
        ClipContent::Text(t) => vec![Frame {
            header: Header::Text,
            body: Body::Bytes(t.into_bytes()),
        }],
        ClipContent::Html { html, alt } => vec![Frame {
            header: Header::Html { alt },
            body: Body::Bytes(html.into_bytes()),
        }],
        ClipContent::Image {
            width,
            height,
            rgba,
        } => vec![Frame {
            header: Header::Image { width, height },
            body: Body::Bytes(rgba),
        }],
        ClipContent::Files(paths) => {
            if !config.files {
                return;
            }
            match tokio::task::spawn_blocking(move || file_frames(&paths, config.max_file_bytes))
                .await
            {
                Ok(Ok(frames)) => frames,
                Ok(Err(e)) => return log::warn!("not sending files: {e}"),
                Err(e) => return log::warn!("not sending files: {e}"),
            }
        }
    };
    *shared.last_sig.lock().expect("lock") = Some(sig);
    log::info!("sending clipboard to {ip} ({} frames)", frames.len());
    for frame in frames {
        if tx.send(frame).await.is_err() {
            return log::warn!("data channel to {ip} closed while sending");
        }
    }
}

/// walk the copied paths and build the frames for a file set
fn file_frames(paths: &[PathBuf], max_bytes: u64) -> io::Result<Vec<Frame>> {
    let mut entries = Vec::new();
    let mut sources = Vec::new();
    let mut total = 0u64;
    for root in paths {
        let base = root.parent().unwrap_or(Path::new(""));
        let mut stack = vec![root.clone()];
        while let Some(p) = stack.pop() {
            let meta = std::fs::symlink_metadata(&p)?;
            if meta.file_type().is_symlink() {
                continue;
            }
            let rel = p
                .strip_prefix(base)
                .map_err(io::Error::other)?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if meta.is_dir() {
                entries.push(Entry {
                    path: rel,
                    size: 0,
                    dir: true,
                });
                for child in std::fs::read_dir(&p)? {
                    stack.push(child?.path());
                }
            } else {
                total += meta.len();
                if total > max_bytes {
                    return Err(io::Error::other(format!(
                        "more than {} MiB (transfer.max_file_bytes)",
                        max_bytes >> 20
                    )));
                }
                sources.push((entries.len(), p.clone(), meta.len()));
                entries.push(Entry {
                    path: rel,
                    size: meta.len(),
                    dir: false,
                });
            }
        }
    }
    let id = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default();
    log::info!("sending {} files / {} MiB", sources.len(), total >> 20);
    let mut frames = vec![Frame {
        header: Header::FilesBegin { id, entries },
        body: Body::None,
    }];
    for (index, path, size) in sources {
        frames.push(Frame {
            header: Header::FileData { id, index },
            body: Body::File(path, size),
        });
    }
    frames.push(Frame {
        header: Header::FilesEnd { id },
        body: Body::None,
    });
    Ok(frames)
}

/* ------------------------------------------------------------- receive */

struct Incoming {
    id: u64,
    dir: PathBuf,
    entries: Vec<Entry>,
    roots: Vec<PathBuf>,
}

/// map a peer-supplied relative path into `base`, rejecting anything that
/// could escape it
fn safe_join(base: &Path, rel: &str) -> io::Result<PathBuf> {
    let mut out = base.to_path_buf();
    let mut any = false;
    for part in rel.split('/') {
        let p = Path::new(part);
        let mut comps = p.components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(c)), None) if !part.contains(['\\', ':']) => {
                out.push(c);
                any = true;
            }
            _ => return Err(io::Error::other(format!("unsafe path from peer: {rel:?}"))),
        }
    }
    if !any {
        return Err(io::Error::other("empty path from peer"));
    }
    Ok(out)
}

async fn receive_loop<R: AsyncRead + Unpin>(
    r: &mut R,
    ip: IpAddr,
    shared: &Shared,
) -> io::Result<()> {
    let mut incoming: Option<Incoming> = None;
    loop {
        let (header, len) = read_header(r).await?;
        let content = match header {
            Header::Text => {
                let text = String::from_utf8(read_body(r, len).await?).map_err(io::Error::other)?;
                Some(ClipContent::Text(text))
            }
            Header::Html { alt } => {
                let html = String::from_utf8(read_body(r, len).await?).map_err(io::Error::other)?;
                Some(ClipContent::Html { html, alt })
            }
            Header::Image { width, height } => {
                let rgba = read_body(r, len).await?;
                if rgba.len() != width.saturating_mul(height).saturating_mul(4) {
                    return Err(io::Error::other("image size mismatch"));
                }
                Some(ClipContent::Image {
                    width,
                    height,
                    rgba,
                })
            }
            Header::FilesBegin { id, entries } => {
                let config = shared.config.read().expect("lock").clone();
                if !config.files {
                    return Err(io::Error::other("file transfer disabled"));
                }
                let total: u64 = entries.iter().map(|e| e.size).sum();
                if total > config.max_file_bytes {
                    return Err(io::Error::other("incoming file set too large"));
                }
                let stamp = chrono_stamp();
                let dir = config.receive_dir.join(stamp);
                let mut roots: Vec<PathBuf> = Vec::new();
                for e in &entries {
                    let target = safe_join(&dir, &e.path)?;
                    if e.dir {
                        tokio::fs::create_dir_all(&target).await?;
                    }
                    let first = e.path.split('/').next().unwrap_or_default();
                    let root = dir.join(first);
                    if !roots.contains(&root) {
                        roots.push(root);
                    }
                }
                tokio::fs::create_dir_all(&dir).await?;
                log::info!(
                    "receiving {} entries / {} MiB from {ip} into {}",
                    entries.len(),
                    total >> 20,
                    dir.display()
                );
                incoming = Some(Incoming {
                    id,
                    dir,
                    entries,
                    roots,
                });
                None
            }
            Header::FileData { id, index } => {
                let inc = incoming
                    .as_ref()
                    .filter(|i| i.id == id)
                    .ok_or_else(|| io::Error::other("file data without announcement"))?;
                let entry = inc
                    .entries
                    .get(index)
                    .filter(|e| !e.dir && e.size == len)
                    .ok_or_else(|| io::Error::other("file data does not match announcement"))?;
                let target = safe_join(&inc.dir, &entry.path)?;
                if let Some(parent) = target.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let mut f = BufWriter::new(tokio::fs::File::create(&target).await?);
                let copied = tokio::io::copy(&mut (&mut *r).take(len), &mut f).await?;
                f.flush().await?;
                if copied != len {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                None
            }
            Header::FilesEnd { id } => match incoming.take() {
                Some(inc) if inc.id == id => {
                    log::info!("files from {ip} complete: {}", inc.dir.display());
                    Some(ClipContent::Files(inc.roots))
                }
                _ => return Err(io::Error::other("unexpected end of file set")),
            },
        };
        if let Some(content) = content {
            let sig = content.signature();
            if shared.clipboard.write(content).await {
                log::info!("clipboard updated from {ip}");
                *shared.last_sig.lock().expect("lock") = Some(sig);
            }
        }
    }
}

/// local timestamp-ish folder name without pulling in a date crate
fn chrono_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    // days since epoch -> civil date (UTC), Howard Hinnant's algorithm
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}_{:02}-{:02}-{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_escapes() {
        let base = Path::new("/tmp/base");
        assert!(safe_join(base, "a/b.txt").is_ok());
        assert!(safe_join(base, "../x").is_err());
        assert!(safe_join(base, "/etc/passwd").is_err());
        assert!(safe_join(base, "a/../../x").is_err());
        assert!(safe_join(base, "C:\\x").is_err());
        assert!(safe_join(base, "a\\..\\x").is_err());
        assert!(safe_join(base, "").is_err());
        assert!(safe_join(base, "a//b").is_err());
    }

    #[test]
    fn stamp_shape() {
        let s = chrono_stamp();
        assert_eq!(s.len(), 19, "{s}");
    }

    #[tokio::test]
    async fn frame_roundtrip_with_file() {
        let dir = tempdir();
        let src = dir.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"hello").unwrap();
        std::fs::write(src.join("sub/b.bin"), vec![7u8; 300_000]).unwrap();
        let frames = file_frames(&[src.clone()], 1 << 30).unwrap();

        let mut wire = Vec::new();
        for f in frames {
            write_frame(&mut wire, f).await.unwrap();
        }

        let recv_dir = dir.join("recv");
        let shared = Shared {
            clipboard: ClipboardWorker {
                tx: std_mpsc::channel().0,
            },
            config: RwLock::new(TransferConfig {
                receive_dir: recv_dir.clone(),
                ..Default::default()
            }),
            last_sig: Mutex::new(None),
            conns: Mutex::new(HashMap::new()),
        };
        let mut r = &wire[..];
        let err = receive_loop(&mut r, "127.0.0.1".parse().unwrap(), &shared)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let stamp_dir = std::fs::read_dir(&recv_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            std::fs::read(stamp_dir.join("src/a.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(
            std::fs::read(stamp_dir.join("src/sub/b.bin"))
                .unwrap()
                .len(),
            300_000
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn tls_handshake_exposes_client_fingerprint() {
        let server_cert = Certificate::generate_self_signed(["a".to_owned()]).unwrap();
        let client_cert = Certificate::generate_self_signed(["b".to_owned()]).unwrap();
        let expected = crypto::certificate_fingerprint(&client_cert);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = acceptor(&server_cert).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(s).await.unwrap();
            let fp = crypto::generate_fingerprint(&tls.get_ref().1.peer_certificates().unwrap()[0]);
            let (header, len) = read_header(&mut tls).await.unwrap();
            let body = read_body(&mut tls, len).await.unwrap();
            (fp, header, body)
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector(&client_cert)
            .unwrap()
            .connect(ServerName::try_from("uwumouse").unwrap(), stream)
            .await
            .unwrap();
        write_frame(
            &mut tls,
            Frame {
                header: Header::Text,
                body: Body::Bytes("grüße".as_bytes().to_vec()),
            },
        )
        .await
        .unwrap();

        let (fp, header, body) = server.await.unwrap();
        assert_eq!(fp, expected);
        assert!(matches!(header, Header::Text));
        assert_eq!(String::from_utf8(body).unwrap(), "grüße");
    }

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("uwu-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
