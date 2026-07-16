//! Gestão de pacotes APT. Listar atualizáveis e pesquisar (sem root);
//! update/upgrade/install/remove via `sudo` (wizard de elevação).

use std::process::Command;

use serde::Serialize;

use crate::elevate;

#[derive(Serialize)]
pub struct Upgradable {
    pub name: String,
    pub from: String,
    pub to: String,
    pub arch: String,
}

#[derive(Serialize)]
pub struct Found {
    pub name: String,
    pub description: String,
}

/// Pacotes com atualização disponível (`apt list --upgradable`).
pub fn upgradable() -> Vec<Upgradable> {
    let out = match Command::new("apt").args(["list", "--upgradable"]).output() {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let mut list = Vec::new();
    for line in String::from_utf8_lossy(&out).lines() {
        // brave-browser/stable 1.92.140 amd64 [upgradable from: 1.92.139]
        if !line.contains("[upgradable from:") {
            continue;
        }
        let name = line.split('/').next().unwrap_or("").to_string();
        let f: Vec<&str> = line.split_whitespace().collect();
        let to = f.get(1).unwrap_or(&"").to_string();
        let arch = f.get(2).unwrap_or(&"").to_string();
        let from = line
            .split("from:")
            .nth(1)
            .map(|s| s.trim().trim_end_matches(']').trim().to_string())
            .unwrap_or_default();
        if !name.is_empty() {
            list.push(Upgradable { name, from, to, arch });
        }
    }
    list
}

/// Pesquisa de pacotes disponíveis (`apt-cache search`).
pub fn search(q: &str) -> Vec<Found> {
    if q.trim().is_empty() || q.len() > 64 || !q.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | ' ')) {
        return Vec::new();
    }
    let out = match Command::new("apt-cache").args(["search", "--", q]).output() {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    String::from_utf8_lossy(&out)
        .lines()
        .take(200)
        .filter_map(|l| {
            let mut it = l.splitn(2, " - ");
            let name = it.next()?.trim().to_string();
            let description = it.next().unwrap_or("").trim().to_string();
            if name.is_empty() {
                None
            } else {
                Some(Found { name, description })
            }
        })
        .collect()
}

fn valid_pkg(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err("nome de pacote inválido".into())
    }
}

/// Corre um subcomando do apt-get como root, sem interação, e devolve o texto.
fn apt_get(admin: &str, pw: &str, extra: &[&str]) -> Result<String, String> {
    let mut argv = vec!["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y"];
    argv.extend_from_slice(extra);
    elevate::sudo_output(admin, pw, &argv)
}

pub fn update(admin: &str, pw: &str) -> Result<String, String> {
    apt_get(admin, pw, &["update"])
}
pub fn upgrade(admin: &str, pw: &str) -> Result<String, String> {
    apt_get(admin, pw, &["upgrade"])
}
pub fn install(admin: &str, pw: &str, name: &str) -> Result<String, String> {
    valid_pkg(name)?;
    apt_get(admin, pw, &["install", name])
}
pub fn remove(admin: &str, pw: &str, name: &str) -> Result<String, String> {
    valid_pkg(name)?;
    apt_get(admin, pw, &["remove", name])
}
