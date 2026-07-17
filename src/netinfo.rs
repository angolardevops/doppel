//! Rede (só leitura): interfaces/IPs via `ip -json addr` e sockets via `ss`.

use std::process::Command;

use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
pub struct Addr {
    pub family: String,
    pub ip: String,
    pub prefix: u64,
}
#[derive(Serialize)]
pub struct Iface {
    pub name: String,
    pub mac: String,
    pub state: String,
    pub mtu: u64,
    pub addrs: Vec<Addr>,
}
#[derive(Serialize)]
pub struct Sock {
    pub proto: String,
    pub state: String,
    pub local: String,
    pub peer: String,
}
#[derive(Serialize)]
pub struct Route {
    pub dst: String,
    pub gateway: String,
    pub dev: String,
    pub proto: String,
}
#[derive(Serialize)]
pub struct NetInfo {
    pub ifaces: Vec<Iface>,
    pub sockets: Vec<Sock>,
    pub routes: Vec<Route>,
    pub dns: Vec<String>,
}

pub fn info() -> NetInfo {
    NetInfo { ifaces: ifaces(), sockets: sockets(), routes: routes(), dns: dns() }
}

fn routes() -> Vec<Route> {
    let out = match Command::new("ip").args(["-json", "route"]).output() {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let v: Value = serde_json::from_slice(&out).unwrap_or(Value::Null);
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|e| Route {
                    dst: e.get("dst").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    gateway: e.get("gateway").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    dev: e.get("dev").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    proto: e.get("protocol").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn dns() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(s) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in s.lines() {
            let l = line.trim();
            if let Some(ns) = l.strip_prefix("nameserver ") {
                out.push(format!("nameserver {}", ns.trim()));
            } else if let Some(sr) = l.strip_prefix("search ") {
                out.push(format!("search {}", sr.trim()));
            }
        }
    }
    out
}

fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 255 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_'))
}

/// ping a um host (como o utilizador; ICMP não-privilegiado no Linux moderno).
pub fn ping(host: &str, count: u32) -> Result<String, String> {
    if !valid_host(host) {
        return Err("host inválido".into());
    }
    let n = count.clamp(1, 20).to_string();
    let out = Command::new("ping")
        .args(["-c", &n, "-W", "2", "-n", "--", host])
        .output()
        .map_err(|e| format!("ping indisponível: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() || !text.trim().is_empty() {
        Ok(text)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// traceroute a um host (usa `traceroute` se existir, senão `tracepath`).
pub fn trace(host: &str) -> Result<String, String> {
    if !valid_host(host) {
        return Err("host inválido".into());
    }
    let (cmd, args): (&str, Vec<&str>) = if which("traceroute") {
        ("traceroute", vec!["-m", "20", "-w", "2", "-n", "--", host])
    } else {
        ("tracepath", vec!["-m", "20", host])
    };
    let out = Command::new(cmd).args(&args).output().map_err(|e| format!("{cmd} indisponível: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text.push_str(&err);
    }
    Ok(text)
}

fn which(cmd: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {cmd}")]).output().map(|o| o.status.success()).unwrap_or(false)
}

fn ifaces() -> Vec<Iface> {
    let out = match Command::new("ip").args(["-json", "addr", "show"]).output() {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let v: Value = serde_json::from_slice(&out).unwrap_or(Value::Null);
    let arr = match v.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .map(|e| {
            let addrs = e
                .get("addr_info")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .map(|ai| Addr {
                            family: ai.get("family").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            ip: ai.get("local").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            prefix: ai.get("prefixlen").and_then(|x| x.as_u64()).unwrap_or(0),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Iface {
                name: e.get("ifname").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                mac: e.get("address").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                state: e.get("operstate").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                mtu: e.get("mtu").and_then(|x| x.as_u64()).unwrap_or(0),
                addrs,
            }
        })
        .collect()
}

fn sockets() -> Vec<Sock> {
    // -t tcp, -u udp, -n numérico, -a todos, -H sem cabeçalho
    let out = match Command::new("ss").args(["-tunaH"]).output() {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let mut socks = Vec::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        socks.push(Sock {
            proto: f[0].to_string(),
            state: f[1].to_string(),
            local: f[4].to_string(),
            peer: f[5].to_string(),
        });
        if socks.len() >= 500 {
            break;
        }
    }
    // ouvintes primeiro
    socks.sort_by(|a, b| (b.state == "LISTEN").cmp(&(a.state == "LISTEN")));
    socks
}
