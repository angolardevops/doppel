//! Backups por `rsync`. Guarda "tarefas" (origem→destino, espelho) num ficheiro
//! JSON no home do utilizador e corre-as on-demand. Opera como o utilizador.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Job {
    pub id: u64,
    pub name: String,
    pub source: String,
    pub dest: String,
    /// espelho: apaga no destino o que já não existe na origem (--delete)
    pub mirror: bool,
}

fn file(home: &Path) -> PathBuf {
    home.join(".local/share/doppel/backups.json")
}

pub fn list(home: &Path) -> Vec<Job> {
    std::fs::read_to_string(file(home))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(home: &Path, jobs: &[Job]) -> Result<(), String> {
    let f = file(home);
    if let Some(p) = f.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    std::fs::write(f, serde_json::to_string_pretty(jobs).unwrap_or_default()).map_err(|e| e.to_string())
}

fn valid_paths(source: &str, dest: &str) -> Result<(), String> {
    if !Path::new(source).is_dir() {
        return Err("a origem tem de ser uma pasta existente".into());
    }
    if dest.len() < 2 || !dest.starts_with('/') || dest == "/" {
        return Err("destino inválido (caminho absoluto)".into());
    }
    let s = std::fs::canonicalize(source).unwrap_or_else(|_| PathBuf::from(source));
    let d = PathBuf::from(dest);
    if d.starts_with(&s) {
        return Err("o destino não pode estar dentro da origem".into());
    }
    Ok(())
}

pub fn add(home: &Path, name: &str, source: &str, dest: &str, mirror: bool) -> Result<(), String> {
    valid_paths(source, dest)?;
    let mut jobs = list(home);
    let id = jobs.iter().map(|j| j.id).max().unwrap_or(0) + 1;
    jobs.push(Job {
        id,
        name: if name.trim().is_empty() { source.to_string() } else { name.trim().to_string() },
        source: source.to_string(),
        dest: dest.to_string(),
        mirror,
    });
    save(home, &jobs)
}

pub fn remove(home: &Path, id: u64) -> Result<(), String> {
    let mut jobs = list(home);
    jobs.retain(|j| j.id != id);
    save(home, &jobs)
}

/// Agenda um backup: acrescenta uma linha ao crontab do utilizador que corre o
/// rsync na expressão `cron` dada (5 campos). Caminhos são citados (sem shell-injection
/// via aspas simples; recusa caminhos com `'`).
pub fn schedule(cron: &str, source: &str, dest: &str, mirror: bool) -> Result<(), String> {
    valid_paths(source, dest)?;
    let fields = cron.split_whitespace().count();
    if fields != 5 {
        return Err("expressão cron inválida (5 campos: min hora dia mês dia-semana)".into());
    }
    if source.contains('\'') || dest.contains('\'') {
        return Err("caminhos com aspas simples não são suportados no agendamento".into());
    }
    let src = if source.ends_with('/') { source.to_string() } else { format!("{source}/") };
    let del = if mirror { " --delete" } else { "" };
    let line = format!("{} rsync -a{} '{}' '{}' >/dev/null 2>&1  # doppel-backup", cron.trim(), del, src, dest);

    let mut content = crate::cron::get();
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&line);
    content.push('\n');
    crate::cron::set(&content)
}

/// Corre um rsync origem→destino e devolve a saída (stats + erros).
pub fn run(source: &str, dest: &str, mirror: bool) -> Result<String, String> {
    valid_paths(source, dest)?;
    // barra final na origem → copia o CONTEÚDO da pasta
    let src = if source.ends_with('/') { source.to_string() } else { format!("{source}/") };

    let mut args: Vec<&str> = vec!["-a", "--human-readable", "--info=stats2,progress0"];
    if mirror {
        args.push("--delete");
    }
    let out = std::process::Command::new("rsync")
        .args(&args)
        .arg("--")
        .arg(&src)
        .arg(dest)
        .output()
        .map_err(|e| format!("rsync indisponível: {e}"))?;

    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text.push_str("\n--- erros ---\n");
        text.push_str(&err);
    }
    if out.status.success() {
        Ok(text)
    } else {
        Err(if text.trim().is_empty() { "rsync falhou".into() } else { text })
    }
}
