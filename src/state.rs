//! Estado partilhado: raiz mutável, progresso de operações em tempo real,
//! e a quarentena persistente (manifesto em disco).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::auth::Sessions;
use crate::scan::DupGroup;

#[derive(Serialize, Default)]
pub struct ScanResult {
    pub total_files: usize,
    pub root_size: u64,
    pub reclaimable: u64,
    pub groups: Vec<DupGroup>,
}

/// Fase corrente de trabalho (guia a progressbar da UI).
pub const IDLE: &str = "idle";
pub const ENUMERATING: &str = "enumerating";
pub const HASHING: &str = "hashing";
pub const DELETING: &str = "deleting";
pub const QUARANTINING: &str = "quarantining";
pub const PURGING: &str = "purging";
pub const RESTORING: &str = "restoring";

// ---- Quarentena -----------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct QEntry {
    pub id: u64,
    /// caminho original de onde o ficheiro foi movido
    pub original: String,
    pub size: u64,
    pub hash: String,
    /// epoch (s) em que foi colocado em quarentena
    pub ts: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    next_id: u64,
    entries: Vec<QEntry>,
}

pub struct Quarantine {
    /// pasta base da quarentena (ex.: ~/.local/share/doppel/quarantine)
    pub dir: PathBuf,
    /// onde os ficheiros ficam guardados (dir/store/<id>)
    pub store: PathBuf,
    next_id: u64,
    pub entries: Vec<QEntry>,
}

impl Quarantine {
    pub fn load(dir: PathBuf) -> Self {
        let store = dir.join("store");
        let _ = std::fs::create_dir_all(&store);
        let manifest_path = dir.join("manifest.json");
        let m: Manifest = std::fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            dir,
            store,
            next_id: m.next_id,
            entries: m.entries,
        }
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.dir.join("manifest.json")
    }

    pub fn save(&self) {
        let m = Manifest {
            next_id: self.next_id,
            entries: self.entries.clone(),
        };
        if let Ok(s) = serde_json::to_string_pretty(&m) {
            let _ = std::fs::write(self.manifest_path(), s);
        }
    }

    pub fn alloc_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    pub fn store_path(&self, id: u64) -> PathBuf {
        self.store.join(id.to_string())
    }

    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }
}

// ---- Estado global --------------------------------------------------------

pub struct AppState {
    pub run_user: String,
    pub run_home: PathBuf,
    pub root: RwLock<PathBuf>,
    pub result: Mutex<ScanResult>,

    pub phase: Mutex<String>,
    pub op_done: AtomicUsize,
    pub op_total: AtomicUsize,

    pub freed: AtomicU64,
    pub removed: AtomicUsize,

    pub version: AtomicU64,
    pub busy: AtomicBool,

    pub sessions: Sessions,
    pub quarantine: Mutex<Quarantine>,
}

impl AppState {
    pub fn new(run_user: String, run_home: PathBuf, root: PathBuf, q_dir: PathBuf) -> Self {
        Self {
            run_user,
            run_home,
            root: RwLock::new(root),
            result: Mutex::new(ScanResult::default()),
            phase: Mutex::new(IDLE.into()),
            op_done: AtomicUsize::new(0),
            op_total: AtomicUsize::new(0),
            freed: AtomicU64::new(0),
            removed: AtomicUsize::new(0),
            version: AtomicU64::new(0),
            busy: AtomicBool::new(false),
            sessions: Sessions::new(),
            quarantine: Mutex::new(Quarantine::load(q_dir)),
        }
    }

    pub fn root(&self) -> PathBuf {
        self.root.read().unwrap().clone()
    }

    pub fn set_phase(&self, p: &str) {
        *self.phase.lock().unwrap() = p.into();
    }

    pub fn phase(&self) -> String {
        self.phase.lock().unwrap().clone()
    }

    pub fn set_progress(&self, done: usize, total: usize) {
        self.op_done.store(done, Ordering::Relaxed);
        self.op_total.store(total, Ordering::Relaxed);
    }

    pub fn tick(&self) {
        self.op_done.fetch_add(1, Ordering::Relaxed);
    }

    pub fn bump_version(&self) {
        self.version.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Diretório de dados da quarentena para um dado home.
pub fn quarantine_dir(home: &Path) -> PathBuf {
    home.join(".local/share/doppel/quarantine")
}
