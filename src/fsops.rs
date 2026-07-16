//! Gestor de ficheiros — opera SEMPRE com as permissões do utilizador autenticado
//! (sem elevação). Listar, criar pasta/ficheiro, renomear, apagar e chmod.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::Serialize;

#[derive(Serialize)]
pub struct FEntry {
    pub name: String,
    pub path: String,
    /// "dir" | "file" | "link"
    pub kind: String,
    pub size: u64,
    pub modified: Option<u64>,
    /// permissões em octal (ex.: "755")
    pub mode: String,
    /// permissões simbólicas (ex.: "rwxr-xr-x")
    pub perms: String,
    pub owner: String,
    pub group: String,
    pub writable: bool,
}

#[derive(Serialize)]
pub struct FListing {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<FEntry>,
    pub error: Option<String>,
}

pub fn list(path: &Path) -> FListing {
    let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let parent = path.parent().map(|p| p.to_string_lossy().into_owned());
    let users = id_map("/etc/passwd");
    let groups = id_map("/etc/group");

    let mut entries = Vec::new();
    let mut error = None;
    match fs::read_dir(&path) {
        Ok(rd) => {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let meta = match e.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let ft = e.file_type().ok();
                let kind = if ft.map(|t| t.is_symlink()).unwrap_or(false) {
                    "link"
                } else if meta.is_dir() {
                    "dir"
                } else {
                    "file"
                };
                let mode_bits = meta.permissions().mode();
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                entries.push(FEntry {
                    name,
                    path: e.path().to_string_lossy().into_owned(),
                    kind: kind.into(),
                    size: meta.len(),
                    modified,
                    mode: format!("{:03o}", mode_bits & 0o777),
                    perms: symbolic(mode_bits),
                    owner: users.get(&meta.uid()).cloned().unwrap_or_else(|| meta.uid().to_string()),
                    group: groups.get(&meta.gid()).cloned().unwrap_or_else(|| meta.gid().to_string()),
                    writable: !meta.permissions().readonly(),
                });
            }
            entries.sort_by(|a, b| {
                (b.kind == "dir").cmp(&(a.kind == "dir")).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
        }
        Err(e) => error = Some(format!("não foi possível ler: {e}")),
    }

    FListing { path: path.to_string_lossy().into_owned(), parent, entries, error }
}

/// Junta `parent` + `name` validando que `name` não escapa a pasta (sem '/').
fn safe_join(parent: &str, name: &str) -> Result<PathBuf, String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err("nome inválido".into());
    }
    Ok(PathBuf::from(parent).join(name))
}

pub fn mkdir(parent: &str, name: &str) -> Result<(), String> {
    let p = safe_join(parent, name)?;
    fs::create_dir(&p).map_err(|e| e.to_string())
}

pub fn mkfile(parent: &str, name: &str) -> Result<(), String> {
    let p = safe_join(parent, name)?;
    if p.exists() {
        return Err("já existe".into());
    }
    fs::File::create(&p).map(|_| ()).map_err(|e| e.to_string())
}

pub fn rename(path: &str, newname: &str) -> Result<(), String> {
    let src = PathBuf::from(path);
    let parent = src.parent().ok_or("sem pasta-mãe")?;
    let dst = safe_join(&parent.to_string_lossy(), newname)?;
    if dst.exists() {
        return Err("o destino já existe".into());
    }
    fs::rename(&src, &dst).map_err(|e| e.to_string())
}

pub fn delete(path: &str, recursive: bool) -> Result<(), String> {
    let p = PathBuf::from(path);
    let meta = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
    if meta.is_dir() {
        if recursive {
            fs::remove_dir_all(&p).map_err(|e| e.to_string())
        } else {
            fs::remove_dir(&p).map_err(|e| e.to_string())
        }
    } else {
        fs::remove_file(&p).map_err(|e| e.to_string())
    }
}

pub fn chmod(path: &str, mode_octal: &str) -> Result<(), String> {
    let bits = u32::from_str_radix(mode_octal.trim_start_matches("0o").trim_start_matches('0').trim(), 8)
        .or_else(|_| u32::from_str_radix(mode_octal.trim(), 8))
        .map_err(|_| "modo octal inválido (ex.: 755)".to_string())?;
    if bits > 0o7777 {
        return Err("modo fora do intervalo".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(bits)).map_err(|e| e.to_string())
}

/// Mapa id → nome a partir de /etc/passwd ou /etc/group (campo 0=nome, 2=id).
fn id_map(file: &str) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    if let Ok(s) = fs::read_to_string(file) {
        for line in s.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 3 {
                if let Ok(id) = f[2].parse::<u32>() {
                    m.entry(id).or_insert_with(|| f[0].to_string());
                }
            }
        }
    }
    m
}

/// Permissões estilo `ls -l` a partir dos bits do modo.
fn symbolic(mode: u32) -> String {
    let f = mode & 0o777;
    let rwx = |bits: u32| {
        format!(
            "{}{}{}",
            if bits & 0o4 != 0 { 'r' } else { '-' },
            if bits & 0o2 != 0 { 'w' } else { '-' },
            if bits & 0o1 != 0 { 'x' } else { '-' },
        )
    };
    format!("{}{}{}", rwx(f >> 6 & 7), rwx(f >> 3 & 7), rwx(f & 7))
}
