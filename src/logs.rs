//! Logs do sistema via `journalctl` (só leitura; o utilizador precisa de estar
//! nos grupos `adm`/`systemd-journal` para ver o journal do sistema).

use std::process::Command;

use serde::Serialize;

#[derive(Serialize)]
pub struct Logs {
    pub lines: Vec<String>,
    pub error: Option<String>,
}

fn valid_unit(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 256
        && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | ':' | '-' | '\\'))
}

/// Últimas `lines` entradas do journal, filtráveis por unit e prioridade.
pub fn recent(unit: &str, lines: u32, priority: &str, grep: &str) -> Logs {
    let n = lines.clamp(10, 2000).to_string();
    let mut args: Vec<String> = vec![
        "-n".into(),
        n,
        "--no-pager".into(),
        "-o".into(),
        "short-iso".into(),
    ];
    if !unit.is_empty() {
        if !valid_unit(unit) {
            return Logs { lines: vec![], error: Some("unit inválida".into()) };
        }
        args.push("-u".into());
        args.push(unit.to_string());
    }
    // prioridade: 0..7 ou nome (emerg..debug)
    if !priority.is_empty() && priority.chars().all(|c| c.is_ascii_alphanumeric()) {
        args.push("-p".into());
        args.push(priority.to_string());
    }
    if !grep.is_empty() && grep.len() <= 200 && !grep.contains('\n') {
        args.push("-g".into());
        args.push(grep.to_string());
    }

    let out = match Command::new("journalctl").args(&args).output() {
        Ok(o) => o,
        Err(e) => return Logs { lines: vec![], error: Some(format!("journalctl indisponível: {e}")) },
    };
    if !out.status.success() {
        let e = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Logs {
            lines: vec![],
            error: Some(if e.is_empty() { "sem acesso ao journal (grupo adm/systemd-journal?)".into() } else { e }),
        };
    }
    let lines = String::from_utf8_lossy(&out.stdout).lines().map(|l| l.to_string()).collect();
    Logs { lines, error: None }
}
