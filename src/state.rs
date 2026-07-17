//! Estado partilhado: raiz mutável, progresso de operações em tempo real,
//! e a quarentena persistente (manifesto em disco).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sysinfo::System;

use crate::auth::Sessions;
use crate::scan::DupGroup;

/// Tempo de vida do resultado de análise em cache (segundos) — 30 minutos.
pub const SCAN_TTL: u64 = 30 * 60;
/// Limite de entradas na cache de hashes (bound de memória do serviço).
pub const HASH_CACHE_CAP: usize = 300_000;
/// Nº máximo de pastas com resultado em cache.
pub const SCAN_CACHE_CAP: usize = 8;

/// Nº máximo de amostras no histórico de KPIs (~10 min a 3s).
pub const HISTORY_CAP: usize = 200;

/// Uma amostra de KPIs no tempo (para os gráficos históricos).
#[derive(Serialize, Clone, Copy)]
pub struct Sample {
    pub t: u64,
    pub cpu: f32,
    pub mem: f32,
    pub temp: f32,
    pub gpu: f32,
    /// taxa de rede (bytes/s) recebida e enviada
    pub net_in: f64,
    pub net_out: f64,
}

extern "C" {
    fn malloc_trim(pad: usize) -> i32;
}

/// Pede ao alocador (glibc) para devolver heap livre ao SO. Chamado depois de
/// trabalho pesado (scan/remoção) para que o RSS não fique inflado.
pub fn release_memory() {
    unsafe {
        let _ = malloc_trim(0);
    }
}

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

// ---- Caches ---------------------------------------------------------------

/// Resultado de análise em cache para uma pasta (com carimbo temporal).
#[derive(Clone)]
pub struct CachedScan {
    pub ts: u64,
    pub total_files: usize,
    pub root_size: u64,
    pub reclaimable: u64,
    pub groups: Vec<DupGroup>,
}

/// Entrada da cache de hashes: identidade do ficheiro (mtime,size) → hash.
#[derive(Clone)]
pub struct HashEntry {
    pub mtime: u64,
    pub size: u64,
    pub hash: String,
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

    /// Cache do resultado de análise por pasta (TTL = SCAN_TTL).
    pub scan_cache: Mutex<HashMap<String, CachedScan>>,
    /// Cache de hashes por caminho (evita re-hashear ficheiros inalterados).
    pub hash_cache: Mutex<HashMap<String, HashEntry>>,
    /// `System` reutilizado para amostrar processos (CPU precisa de 2 amostras).
    pub proc_sys: Mutex<System>,
    /// Histórico de KPIs para os gráficos (ring buffer).
    pub history: Mutex<VecDeque<Sample>>,
    /// Sessões de terminal ativas (id → PTY).
    pub terms: Mutex<HashMap<String, crate::term::TermSession>>,
    /// Porta do listener WebSocket do terminal (0 = indisponível).
    pub ws_port: Mutex<u16>,
    /// Cache do geoip (ms, valor).
    pub geoip_cache: Mutex<Option<(u128, serde_json::Value)>>,
    /// Cache de geolocalização por IP remoto (mapa de tráfego).
    pub ipgeo_cache: Mutex<HashMap<String, crate::pubnet::Endpoint>>,
    /// Taxa de rede atual, calculada SÓ pelo sampler (in/s, out/s, rx, tx).
    /// Fonte única — evita que vários pollers partilhem contadores e falseiem a taxa.
    pub net_now: Mutex<(f64, f64, u64, u64)>,
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
            scan_cache: Mutex::new(HashMap::new()),
            hash_cache: Mutex::new(HashMap::new()),
            proc_sys: Mutex::new(System::new()),
            history: Mutex::new(VecDeque::with_capacity(HISTORY_CAP)),
            terms: Mutex::new(HashMap::new()),
            ws_port: Mutex::new(0),
            geoip_cache: Mutex::new(None),
            ipgeo_cache: Mutex::new(HashMap::new()),
            net_now: Mutex::new((0.0, 0.0, 0, 0)),
        }
    }

    /// Acrescenta uma amostra ao histórico, respeitando o limite.
    pub fn push_sample(&self, s: Sample) {
        let mut h = self.history.lock().unwrap();
        if h.len() >= HISTORY_CAP {
            h.pop_front();
        }
        h.push_back(s);
    }

    pub fn root(&self) -> PathBuf {
        self.root.read().unwrap().clone()
    }

    /// Devolve a idade (s) do resultado em cache para `path`, se ainda fresco.
    pub fn cache_age(&self, path: &str) -> Option<u64> {
        let c = self.scan_cache.lock().unwrap();
        c.get(path).map(|e| now().saturating_sub(e.ts)).filter(|age| *age < SCAN_TTL)
    }

    /// Nº de pastas com resultado em cache (fresco).
    pub fn cache_count(&self) -> usize {
        let c = self.scan_cache.lock().unwrap();
        c.values().filter(|e| now().saturating_sub(e.ts) < SCAN_TTL).count()
    }

    /// Limpa ambas as caches (resultado + hashes).
    pub fn clear_caches(&self) {
        self.scan_cache.lock().unwrap().clear();
        self.hash_cache.lock().unwrap().clear();
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
