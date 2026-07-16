//! Listagem de diretórios para o seletor de pasta da UI.

use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Serialize)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
}

#[derive(Serialize)]
pub struct Listing {
    pub path: String,
    pub parent: Option<String>,
    pub dirs: Vec<DirEntry>,
    pub error: Option<String>,
}

/// Lista os subdiretórios de `path` (ficheiros são ignorados). Oculta entradas
/// começadas por '.' exceto quando o próprio caminho já está dentro de uma.
pub fn list(path: &Path) -> Listing {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let parent = path.parent().map(|p| p.to_string_lossy().into_owned());

    let mut dirs = Vec::new();
    let mut error = None;
    match std::fs::read_dir(&path) {
        Ok(rd) => {
            for e in rd.flatten() {
                let ft = match e.file_type() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                // segue symlinks para diretórios também
                let is_dir = ft.is_dir()
                    || (ft.is_symlink() && e.path().is_dir());
                if !is_dir {
                    continue;
                }
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    continue;
                }
                dirs.push(DirEntry {
                    name,
                    path: e.path().to_string_lossy().into_owned(),
                });
            }
            dirs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        }
        Err(e) => error = Some(format!("não foi possível ler: {e}")),
    }

    Listing {
        path: path.to_string_lossy().into_owned(),
        parent,
        dirs,
        error,
    }
}

/// Valida que um caminho recebido do cliente é um diretório existente.
pub fn valid_dir(path: &str) -> Option<PathBuf> {
    let p = PathBuf::from(path);
    match std::fs::canonicalize(&p) {
        Ok(c) if c.is_dir() => Some(c),
        _ => None,
    }
}
