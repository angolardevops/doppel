//! Varredura da pasta: recolhe ficheiros, agrupa por tamanho, faz hash BLAKE3
//! dos candidatos em paralelo e produz os grupos de duplicados.

use std::collections::HashMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

use rayon::prelude::*;
use serde::Serialize;
use walkdir::WalkDir;

use crate::state::{self, AppState};

#[derive(Serialize, Clone)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    /// epoch em segundos da última modificação (se disponível)
    pub modified: Option<u64>,
}

#[derive(Serialize, Clone)]
pub struct DupGroup {
    /// hash BLAKE3 (hex) partilhado por todos os ficheiros do grupo
    pub hash: String,
    /// tamanho (bytes) de cada ficheiro do grupo — todos idênticos
    pub size: u64,
    pub count: usize,
    /// espaço desperdiçado = size * (count - 1)
    pub wasted: u64,
    pub files: Vec<FileInfo>,
}

/// Executa a varredura completa e escreve o resultado no estado partilhado.
/// Pensado para correr numa thread dedicada.
pub fn run(state: &AppState) {
    let root = state.root();

    // Fase 1 — enumerar todos os ficheiros regulares não vazios.
    {
        let mut r = state.result.lock().unwrap();
        r.groups.clear();
        r.reclaimable = 0;
        r.root_size = 0;
        r.total_files = 0;
    }
    state.set_phase(state::ENUMERATING);
    state.set_progress(0, 0); // indeterminado

    let mut all: Vec<FileInfo> = Vec::new();
    let mut root_size: u64 = 0;
    for entry in WalkDir::new(&root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let size = meta.len();
        root_size += size;
        if size == 0 {
            continue; // ficheiros vazios: todos "iguais" mas sem valor — ignorados
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        all.push(FileInfo {
            path: entry.path().to_string_lossy().into_owned(),
            size,
            modified,
        });
    }

    {
        let mut r = state.result.lock().unwrap();
        r.total_files = all.len();
        r.root_size = root_size;
    }

    // Fase 2 — agrupar por tamanho; só tamanhos com >1 ficheiro são candidatos.
    let mut by_size: HashMap<u64, Vec<FileInfo>> = HashMap::new();
    for f in all {
        by_size.entry(f.size).or_default().push(f);
    }
    let candidates: Vec<FileInfo> = by_size
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .flat_map(|(_, v)| v)
        .collect();

    state.set_phase(state::HASHING);
    state.set_progress(0, candidates.len());

    // Fase 3 — hash BLAKE3 dos candidatos em paralelo.
    let hashed: Vec<(String, FileInfo)> = candidates
        .into_par_iter()
        .filter_map(|f| {
            let h = hash_file(Path::new(&f.path));
            state.tick();
            h.map(|hash| (hash, f))
        })
        .collect();

    // Fase 4 — reagrupar por (tamanho, hash) e formar grupos de duplicados.
    let mut by_hash: HashMap<String, Vec<FileInfo>> = HashMap::new();
    for (h, f) in hashed {
        // a chave inclui o tamanho implicitamente (hash já o distingue)
        by_hash.entry(h).or_default().push(f);
    }

    let mut groups: Vec<DupGroup> = by_hash
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(hash, mut files)| {
            // ordena por data (mais antigo primeiro) — bom candidato a "manter"
            files.sort_by(|a, b| a.modified.cmp(&b.modified).then(a.path.cmp(&b.path)));
            let size = files[0].size;
            let count = files.len();
            DupGroup {
                hash,
                size,
                count,
                wasted: size * (count as u64 - 1),
                files,
            }
        })
        .collect();

    groups.sort_by(|a, b| b.wasted.cmp(&a.wasted));
    let reclaimable: u64 = groups.iter().map(|g| g.wasted).sum();

    {
        let mut r = state.result.lock().unwrap();
        r.groups = groups;
        r.reclaimable = reclaimable;
    }
    state.set_phase(state::IDLE);
    state.set_progress(0, 0);
    state.bump_version();
}

/// Hash BLAKE3 de um ficheiro por streaming (memória constante).
pub fn hash_file(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().to_hex().to_string())
}
