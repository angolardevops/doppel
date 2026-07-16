//! Discos: árvore de dispositivos (`lsblk -J`), uso por pasta (`du`, on-demand)
//! e S.M.A.R.T. (via `sudo smartctl`, se instalado).

use std::process::Command;

use serde::Serialize;
use serde_json::{json, Value};

use crate::elevate;

/// Devolve a árvore de dispositivos de bloco tal como o lsblk a dá (JSON),
/// mais se o smartctl está disponível.
pub fn blocks() -> Value {
    let out = Command::new("lsblk")
        .args(["-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL,RM,RO,SERIAL"])
        .output();
    let tree = out
        .ok()
        .and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok())
        .unwrap_or_else(|| json!({ "blockdevices": [] }));
    json!({ "tree": tree, "smart": smart_available() })
}

pub fn smart_available() -> bool {
    Command::new("smartctl").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

#[derive(Serialize)]
pub struct DuEntry {
    pub path: String,
    pub size: u64,
}

/// Uso de disco por subpasta imediata de `path` (bytes). Corre como o utilizador.
pub fn du(path: &str) -> Result<Vec<DuEntry>, String> {
    if !std::path::Path::new(path).is_dir() {
        return Err("pasta inválida".into());
    }
    let out = Command::new("du")
        .args(["-b", "--max-depth=1", "--", path])
        .output()
        .map_err(|e| e.to_string())?;
    let mut entries: Vec<DuEntry> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.splitn(2, '\t');
            let size = it.next()?.trim().parse::<u64>().ok()?;
            let p = it.next()?.to_string();
            Some(DuEntry { path: p, size })
        })
        .collect();
    entries.sort_by(|a, b| b.size.cmp(&a.size));
    Ok(entries)
}

/// Saúde S.M.A.R.T. de um dispositivo, via sudo — devolve o texto do smartctl.
pub fn smart(admin: &str, pw: &str, dev: &str) -> Result<String, String> {
    // valida o nome do dispositivo (ex.: /dev/sda, /dev/nvme0n1)
    if !dev.starts_with("/dev/") || dev.contains(['\n', ' ', ';', '|', '&']) {
        return Err("dispositivo inválido".into());
    }
    elevate::sudo_output(admin, pw, &["smartctl", "-H", "-i", dev])
}
