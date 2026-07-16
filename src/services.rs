//! Gestão de serviços systemd. Listagem via `systemctl` (sem root); ações
//! (start/stop/restart/enable/disable) via `sudo systemctl` (wizard de elevação).

use std::collections::HashMap;
use std::process::Command;

use serde::Serialize;

use crate::elevate;

#[derive(Serialize)]
pub struct ServiceInfo {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
    /// estado no arranque: enabled | disabled | static | masked | …
    pub enabled: String,
}

pub fn list() -> Vec<ServiceInfo> {
    // estado de arranque (unit → enabled/disabled/…)
    let mut startup: HashMap<String, String> = HashMap::new();
    if let Ok(out) = Command::new("systemctl")
        .args(["list-unit-files", "--type=service", "--no-legend", "--no-pager", "--plain"])
        .output()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut it = line.split_whitespace();
            if let (Some(unit), Some(state)) = (it.next(), it.next()) {
                startup.insert(unit.to_string(), state.to_string());
            }
        }
    }

    let mut services = Vec::new();
    if let Ok(out) = Command::new("systemctl")
        .args(["list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"])
        .output()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            let unit = f[0].to_string();
            let description = f[4..].join(" ");
            let enabled = startup.get(&unit).cloned().unwrap_or_else(|| "-".into());
            services.push(ServiceInfo {
                enabled,
                load: f[1].to_string(),
                active: f[2].to_string(),
                sub: f[3].to_string(),
                description,
                unit,
            });
        }
    }
    services.sort_by(|a, b| a.unit.cmp(&b.unit));
    services
}

#[derive(Serialize)]
pub struct TimerInfo {
    pub unit: String,
    pub activates: String,
    pub schedule: String,
}

/// Lista os timers systemd (agendamentos). `list-timers` mostra próximo/último.
pub fn timers() -> Vec<TimerInfo> {
    let mut out = Vec::new();
    if let Ok(o) = Command::new("systemctl")
        .args(["list-timers", "--all", "--no-legend", "--no-pager"])
        .output()
    {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 2 {
                continue;
            }
            // os 2 últimos tokens são UNIT (.timer) e ACTIVATES (.service);
            // o resto é o horário (NEXT / LEFT / LAST / PASSED).
            let activates = f[f.len() - 1].to_string();
            let unit = f[f.len() - 2].to_string();
            let schedule = f[..f.len() - 2].join(" ");
            out.push(TimerInfo { unit, activates, schedule });
        }
    }
    out
}

fn valid_unit(u: &str) -> Result<(), String> {
    let ok = !u.is_empty()
        && u.len() <= 256
        && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | ':' | '-' | '\\'));
    if ok {
        Ok(())
    } else {
        Err("nome de unit inválido".into())
    }
}

/// Ação sobre um serviço via `sudo systemctl <action> <unit>`.
pub fn action(admin: &str, pw: &str, unit: &str, action: &str) -> Result<(), String> {
    valid_unit(unit)?;
    let act = match action {
        "start" | "stop" | "restart" | "reload" | "enable" | "disable" => action,
        _ => return Err("ação desconhecida".into()),
    };
    elevate::sudo_exec(admin, pw, &["systemctl", act, unit])
}
