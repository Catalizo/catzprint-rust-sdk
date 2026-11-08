//! Token stores: where the SDK keeps its local token and the station
//! endpoint list between runs.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::models::LocalEndpoint;

/// What the SDK keeps in a [`TokenStore`] for one device: its local token and
/// the last station endpoint list from the cloud, so a hub that restarts
/// while the internet is down can still find and trust its stations. Its
/// `Debug` output never shows the token.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredToken {
    /// The local token (`"czl1…"`); empty when only endpoints are stored
    /// (e.g. with a static [`crate::LocalConfig::token`]).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// The token's ID (`jti`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token_id: String,
    /// When the token expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The last endpoint list from the cloud.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stations: Vec<LocalEndpoint>,
    /// When the endpoint list was fetched (`None`: never).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stations_updated_at: Option<DateTime<Utc>>,
    /// When a station's `401 token_expired` last caused a re-mint (at most
    /// once per 10 minutes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_remint_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for StoredToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredToken")
            .field("token", &super::models::redacted(&self.token))
            .field("token_id", &self.token_id)
            .field("expires_at", &self.expires_at)
            .field("stations", &self.stations)
            .field("stations_updated_at", &self.stations_updated_at)
            .field("last_remint_at", &self.last_remint_at)
            .finish()
    }
}

/// The future a [`TokenStore`] method returns.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Persists local tokens between runs. Implementations must be safe for
/// concurrent use. `load` returns `Ok(None)` when nothing is stored under
/// `key`. Keys are opaque strings chosen by the SDK; they never contain the
/// API key itself.
///
/// Store failures never stop printing: they only mean the token or endpoint
/// list won't survive a restart ([`crate::Local::store_error`]).
///
/// ```
/// use catzprint::{StoreFuture, StoredToken, TokenStore};
///
/// #[derive(Debug, Default)]
/// struct NoStore;
///
/// impl TokenStore for NoStore {
///     fn load<'a>(&'a self, _key: &'a str) -> StoreFuture<'a, Option<StoredToken>> {
///         Box::pin(async { Ok(None) })
///     }
///     fn save<'a>(&'a self, _key: &'a str, _token: &'a StoredToken) -> StoreFuture<'a, ()> {
///         Box::pin(async { Ok(()) })
///     }
/// }
/// ```
pub trait TokenStore: Send + Sync {
    /// Loads what is stored under `key`.
    fn load<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<StoredToken>>;
    /// Stores `token` under `key`.
    fn save<'a>(&'a self, key: &'a str, token: &'a StoredToken) -> StoreFuture<'a, ()>;
}

impl<T: TokenStore + ?Sized> TokenStore for Arc<T> {
    fn load<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<StoredToken>> {
        (**self).load(key)
    }
    fn save<'a>(&'a self, key: &'a str, token: &'a StoredToken) -> StoreFuture<'a, ()> {
        (**self).save(key, token)
    }
}

/// Keeps tokens in memory (the default). Tokens are minted again after a
/// restart.
#[derive(Debug, Default)]
pub struct MemoryTokenStore {
    m: Mutex<HashMap<String, StoredToken>>,
}

impl MemoryTokenStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for MemoryTokenStore {
    fn load<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<StoredToken>> {
        let v = self
            .m
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned();
        Box::pin(async move { Ok(v) })
    }
    fn save<'a>(&'a self, key: &'a str, token: &'a StoredToken) -> StoreFuture<'a, ()> {
        self.m
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), token.clone());
        Box::pin(async { Ok(()) })
    }
}

/// Keeps tokens in a JSON file readable only by the current user (mode 0600
/// on Unix; the directory is created with 0700). On Unix an existing file or
/// directory that another user owns, or that is group- or world-writable, is
/// refused: loads and saves fail with `PermissionDenied`
/// ([`crate::Local::store_error`]) and the tokens are kept in memory only. Every save writes a
/// temporary file next to it and renames it into place, so the file is never
/// half-written. One file can hold several keys. File I/O runs on tokio's
/// blocking pool.
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    inner: Arc<FileInner>,
}

#[derive(Debug)]
struct FileInner {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileTokenStore {
    /// A store backed by the file at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileTokenStore {
            inner: Arc::new(FileInner {
                path: path.into(),
                lock: Mutex::new(()),
            }),
        }
    }

    /// The file the store uses.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }
}

/// The directory a store file lives in.
fn store_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The EFFECTIVE user ID of this process (the owner of the files it
/// creates), found without `unsafe`:
/// `/proc/self/status` on Linux, else the owner of a file created for the
/// purpose in the temporary directory. Cached.
#[cfg(unix)]
fn current_uid() -> io::Result<u32> {
    use std::os::unix::fs::MetadataExt as _;
    static UID: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    let found = *UID.get_or_init(|| {
        if let Ok(st) = std::fs::read_to_string("/proc/self/status") {
            let euid = st
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse().ok());
            if euid.is_some() {
                return euid;
            }
        }
        let probe = std::env::temp_dir().join(format!(
            ".catzprint-uid.{}.{:016x}",
            std::process::id(),
            fastrand::u64(..)
        ));
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .ok()?;
        let uid = f.metadata().ok().map(|m| m.uid());
        drop(f);
        let _ = std::fs::remove_file(&probe);
        uid
    });
    found.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "couldn't determine the current user to check the token store's owner",
        )
    })
}

/// Refuses a token store file or directory that another user owns or that
/// is group- or world-writable: someone else could read, plant or swap the
/// tokens. Missing paths are fine (the SDK creates them, owned by us).
#[cfg(unix)]
fn check_private(path: &Path, what: &str) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let m = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let uid = current_uid()?;
    if m.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing the token store {what} {}: it is owned by uid {}, not the current \
                 user (uid {uid})",
                path.display(),
                m.uid()
            ),
        ));
    }
    if m.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing the token store {what} {}: it is group- or world-writable (mode {:o})",
                path.display(),
                m.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

/// Windows: ACLs, not modes; the check is skipped.
#[cfg(not(unix))]
fn check_private(_path: &Path, _what: &str) -> io::Result<()> {
    Ok(())
}

impl FileInner {
    /// Checks the store's directory and file before any use.
    fn check(&self) -> io::Result<()> {
        check_private(&store_dir(&self.path), "directory")?;
        check_private(&self.path, "file")
    }

    fn read_all(&self) -> io::Result<HashMap<String, StoredToken>> {
        let b = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(e),
        };
        if b.iter().all(u8::is_ascii_whitespace) {
            return Ok(HashMap::new());
        }
        serde_json::from_slice(&b).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("token store {} is corrupt: {e}", self.path.display()),
            )
        })
    }

    fn load(&self, key: &str) -> io::Result<Option<StoredToken>> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.check()?;
        Ok(self.read_all()?.remove(key))
    }

    fn save(&self, key: &str, tok: StoredToken) -> io::Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.check()?;
        // A corrupt file is replaced rather than blocking printing.
        let mut m = self.read_all().unwrap_or_default();
        m.insert(key.to_string(), tok);
        let data = serde_json::to_vec_pretty(&m).map_err(io::Error::other)?;
        write_atomic(&self.path, &data)
    }
}

impl TokenStore for FileTokenStore {
    fn load<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<StoredToken>> {
        let inner = self.inner.clone();
        let key = key.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || inner.load(&key))
                .await
                .map_err(io::Error::other)?
        })
    }
    fn save<'a>(&'a self, key: &'a str, token: &'a StoredToken) -> StoreFuture<'a, ()> {
        let inner = self.inner.clone();
        let key = key.to_string();
        let token = token.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || inner.save(&key, token))
                .await
                .map_err(io::Error::other)?
        })
    }
}

/// Writes `data` to a temporary file (mode 0600) next to `path`, syncs it and
/// renames it into place.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let dir = store_dir(path);
    let mut db = std::fs::DirBuilder::new();
    db.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        db.mode(0o700);
    }
    db.create(&dir)?;
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tokens".into());
    let tmp = dir.join(format!(
        ".{base}.{}.{:016x}.tmp",
        std::process::id(),
        fastrand::u64(..)
    ));
    let mut oo = std::fs::OpenOptions::new();
    oo.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        oo.mode(0o600);
    }
    let result = (|| {
        let mut f = oo.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The owner check compares with the EFFECTIVE uid: the owner of a file
    /// this process creates.
    #[test]
    fn current_uid_is_the_effective_uid() {
        use std::os::unix::fs::MetadataExt as _;
        let p = std::env::temp_dir().join(format!(
            ".catzprint-euid-test.{}.{:016x}",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::write(&p, b"x").unwrap();
        let owner = std::fs::metadata(&p).unwrap().uid();
        let _ = std::fs::remove_file(&p);
        assert_eq!(current_uid().unwrap(), owner);
        // /proc/self/status lists real, effective, saved, fs: the second.
        if let Ok(st) = std::fs::read_to_string("/proc/self/status") {
            let line = st.lines().find(|l| l.starts_with("Uid:")).unwrap();
            let eff: u32 = line.split_whitespace().nth(2).unwrap().parse().unwrap();
            assert_eq!(current_uid().unwrap(), eff);
        }
    }
}
