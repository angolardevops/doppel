//! Crontab do utilizador (sem elevação — cada um gere o seu). Ler e substituir.

use std::io::Write;
use std::process::{Command, Stdio};

/// Devolve o crontab do utilizador (vazio se não existir).
pub fn get() -> String {
    match Command::new("crontab").arg("-l").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => String::new(), // "no crontab for user" → tratado como vazio
    }
}

/// Substitui o crontab do utilizador por `content` (via `crontab -`).
pub fn set(content: &str) -> Result<(), String> {
    if content.len() > 64 * 1024 {
        return Err("crontab demasiado grande".into());
    }
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        let mut body = content.to_string();
        if !body.ends_with('\n') {
            body.push('\n');
        }
        let _ = stdin.write_all(body.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
