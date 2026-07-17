//! Rede pública/geo: IP público + ISP + geolocalização (ip-api.com, com cache),
//! dispositivos vizinhos (cache ARP via `ip neigh`) e taxas de I/O de rede.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

use crate::state::AppState;

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// GET HTTP/1.0 minimalista (sem dependências) — devolve o corpo da resposta.
fn http_get(host: &str, path: &str) -> Result<String, String> {
    let mut s = TcpStream::connect((host, 80)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(6))).ok();
    s.set_write_timeout(Some(Duration::from_secs(6))).ok();
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: doppel\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf);
    Ok(text.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

/// IP público, ISP e geolocalização (cache de 5 min para respeitar o rate-limit).
pub fn geoip(state: &AppState) -> Value {
    {
        let c = state.geoip_cache.lock().unwrap();
        if let Some((ms, v)) = c.as_ref() {
            if now_ms().saturating_sub(*ms) < 300_000 {
                return v.clone();
            }
        }
    }
    let v = http_get(
        "ip-api.com",
        "/json/?fields=status,message,query,isp,org,as,city,regionName,country,countryCode,lat,lon,timezone",
    )
    .ok()
    .and_then(|b| serde_json::from_str::<Value>(&b).ok())
    .unwrap_or_else(|| json!({"status":"fail","message":"sem ligação a ip-api.com"}));
    *state.geoip_cache.lock().unwrap() = Some((now_ms(), v.clone()));
    v
}

#[derive(Serialize)]
pub struct Neighbor {
    pub ip: String,
    pub dev: String,
    pub mac: String,
    pub state: String,
}

/// Dispositivos vizinhos na rede (cache ARP/NDP — agentless, sem root).
pub fn neighbors() -> Vec<Neighbor> {
    let out = match Command::new("ip").args(["neigh"]).output() {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let mut list = Vec::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let ip = f[0].to_string();
        let dev = f.iter().position(|&x| x == "dev").and_then(|i| f.get(i + 1)).unwrap_or(&"").to_string();
        let mac = f.iter().position(|&x| x == "lladdr").and_then(|i| f.get(i + 1)).unwrap_or(&"").to_string();
        let state = f.last().unwrap_or(&"").to_string();
        if !mac.is_empty() {
            list.push(Neighbor { ip, dev, mac, state });
        }
    }
    list.sort_by(|a, b| a.ip.cmp(&b.ip));
    list
}

/// Totais rx/tx (bytes) de todas as interfaces exceto loopback (/proc/net/dev).
pub fn net_totals() -> (u64, u64) {
    let (mut rx, mut tx) = (0u64, 0u64);
    if let Ok(s) = std::fs::read_to_string("/proc/net/dev") {
        for line in s.lines().skip(2) {
            if let Some((name, rest)) = line.split_once(':') {
                if name.trim() == "lo" {
                    continue;
                }
                let f: Vec<&str> = rest.split_whitespace().collect();
                rx += f.first().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
                tx += f.get(8).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
            }
        }
    }
    (rx, tx)
}

/// Taxa de rede atual (in/s, out/s, rx, tx) — publicada pelo sampler.
pub fn net_now(state: &AppState) -> (f64, f64, u64, u64) {
    *state.net_now.lock().unwrap()
}

// ---- scanner de rede (crate netscan — Rust puro, sem root, sem nmap) -------

/// Sub-redes locais (CIDR de rede) derivadas das interfaces IPv4 não-loopback.
pub fn local_cidrs() -> Vec<String> {
    let out = match Command::new("ip").args(["-json", "addr", "show"]).output() {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let v: Value = serde_json::from_slice(&out).unwrap_or(Value::Null);
    let mut cidrs = Vec::new();
    for e in v.as_array().unwrap_or(&vec![]) {
        let name = e.get("ifname").and_then(|x| x.as_str()).unwrap_or("");
        if name == "lo" {
            continue;
        }
        for ai in e.get("addr_info").and_then(|a| a.as_array()).unwrap_or(&vec![]) {
            if ai.get("family").and_then(|x| x.as_str()) != Some("inet") {
                continue;
            }
            let ip = ai.get("local").and_then(|x| x.as_str()).unwrap_or("");
            let plen = ai.get("prefixlen").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            if plen == 0 || plen > 32 {
                continue;
            }
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                let bits = u32::from(addr);
                let mask = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
                let net = std::net::Ipv4Addr::from(bits & mask);
                let c = format!("{net}/{plen}");
                if !cidrs.contains(&c) {
                    cidrs.push(c);
                }
            }
        }
    }
    cidrs
}

#[derive(Serialize)]
pub struct ScanHost {
    pub ip: String,
    pub hostname: String,
    pub mac: String,
    pub vendor: String,
    pub latency: String,
    pub via: String,
}

#[derive(Serialize)]
pub struct ScanPort {
    pub port: u16,
    pub service: String,
    pub banner: String,
}

/// Descoberta de hosts na sub-rede — Rust puro (crate `netscan`), **sem root**.
pub fn scan(target: &str) -> Result<Vec<ScanHost>, String> {
    let hosts = netscan::discover(target, 300)?;
    Ok(hosts
        .into_iter()
        .map(|h| ScanHost {
            ip: h.ip,
            hostname: h.hostname,
            mac: h.mac,
            vendor: h.vendor,
            latency: h.rtt_ms.map(|r| format!("{r:.0} ms")).unwrap_or_default(),
            via: h.via,
        })
        .collect())
}

/// Portas/serviços de um host — TCP connect + banner, **sem root**.
pub fn host_scan(ip: &str) -> Result<Vec<ScanPort>, String> {
    let ports = netscan::scan_ports(ip, &netscan::TOP_PORTS, 400)?;
    Ok(ports
        .into_iter()
        .map(|p| ScanPort { port: p.port, service: p.service, banner: p.banner })
        .collect())
}
