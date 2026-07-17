//! Rede pública/geo: IP público + ISP + geolocalização (ip-api.com, com cache),
//! dispositivos vizinhos (cache ARP via `ip neigh`) e taxas de I/O de rede.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// POST HTTP/1.0 minimalista com corpo JSON — devolve o corpo da resposta.
fn http_post_json(host: &str, path: &str, body: &str) -> Result<String, String> {
    let mut s = TcpStream::connect((host, 80)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    s.set_write_timeout(Some(Duration::from_secs(8))).ok();
    let req = format!(
        "POST {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: doppel\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
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

// ---- teste de velocidade (nativo, sem speedtest-cli) -----------------------

/// Servidor de teste: a Cloudflare serve `__down`/`__up` em HTTP simples e é
/// anycast (responde do PoP mais próximo), por isso mede a ligação e não a
/// distância a um servidor longínquo.
const SPEED_HOST: &str = "speed.cloudflare.com";

#[derive(Serialize)]
pub struct Speed {
    pub down_bps: f64,
    pub up_bps: f64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub server: String,
    pub down_bytes: u64,
    pub up_bytes: u64,
}

/// Latência TCP (min) e jitter (desvio médio) em N ligações ao servidor.
fn tcp_latency(host: &str, samples: usize) -> (f64, f64) {
    use std::net::ToSocketAddrs;
    let addr = match (host, 80u16).to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return (0.0, 0.0),
    };
    let mut rtts = Vec::new();
    for _ in 0..samples {
        let t0 = Instant::now();
        if TcpStream::connect_timeout(&addr, Duration::from_secs(4)).is_ok() {
            rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
    }
    if rtts.is_empty() {
        return (0.0, 0.0);
    }
    let min = rtts.iter().cloned().fold(f64::MAX, f64::min);
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    let jitter = rtts.iter().map(|r| (r - avg).abs()).sum::<f64>() / rtts.len() as f64;
    (min, jitter)
}

/// Descarrega `bytes` medindo o débito. Conta a partir do 1º byte do corpo
/// (exclui a latência inicial) e descarta os dados (memória constante).
fn measure_download(bytes: u64, cap: Duration) -> Result<(u64, f64), String> {
    let mut s = TcpStream::connect((SPEED_HOST, 80)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let req = format!(
        "GET /__down?bytes={bytes} HTTP/1.0\r\nHost: {SPEED_HOST}\r\nUser-Agent: doppel\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 64 * 1024];
    let (mut total, mut started) = (0u64, None::<Instant>);
    let mut header_done = false;
    let mut pending = Vec::new();
    loop {
        let n = match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if !header_done {
            // salta os cabeçalhos; o corpo começa depois de \r\n\r\n
            pending.extend_from_slice(&buf[..n]);
            if let Some(p) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                header_done = true;
                started = Some(Instant::now());
                total += (pending.len() - (p + 4)) as u64;
            }
        } else {
            total += n as u64;
        }
        if let Some(t) = started {
            if t.elapsed() > cap {
                break;
            }
        }
    }
    let secs = started.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
    if total == 0 || secs <= 0.0 {
        return Err("download sem dados".into());
    }
    Ok((total, secs))
}

/// Envia `bytes` medindo o débito de subida.
fn measure_upload(bytes: u64, cap: Duration) -> Result<(u64, f64), String> {
    let mut s = TcpStream::connect((SPEED_HOST, 80)).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(10))).ok();
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let req = format!(
        "POST /__up HTTP/1.0\r\nHost: {SPEED_HOST}\r\nUser-Agent: doppel\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;

    let chunk = vec![0u8; 64 * 1024];
    let t0 = Instant::now();
    let mut sent = 0u64;
    while sent < bytes {
        let n = std::cmp::min(chunk.len() as u64, bytes - sent) as usize;
        if s.write_all(&chunk[..n]).is_err() {
            break;
        }
        sent += n as u64;
        if t0.elapsed() > cap {
            break;
        }
    }
    let _ = s.flush();
    // IMPORTANTE: `write_all` devolve quando os bytes entram no buffer do kernel,
    // não quando saem para a rede — parar o cronómetro aqui mediria o buffer e
    // inflacionaria o resultado. Só paramos quando o servidor responde, o que
    // prova que os dados chegaram mesmo ao outro lado.
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
    let secs = t0.elapsed().as_secs_f64();
    if sent == 0 || secs <= 0.0 {
        return Err("upload sem dados".into());
    }
    Ok((sent, secs))
}

/// Teste de velocidade completo (download, upload, latência e jitter).
/// Consome largura de banda real — só deve correr a pedido do utilizador.
pub fn speedtest() -> Result<Speed, String> {
    let (latency_ms, jitter_ms) = tcp_latency(SPEED_HOST, 5);
    let (dbytes, dsecs) = measure_download(25_000_000, Duration::from_secs(8))?;
    let (ubytes, usecs) = measure_upload(10_000_000, Duration::from_secs(8))?;
    Ok(Speed {
        down_bps: (dbytes as f64 * 8.0) / dsecs,
        up_bps: (ubytes as f64 * 8.0) / usecs,
        latency_ms,
        jitter_ms,
        server: format!("{SPEED_HOST} (anycast)"),
        down_bytes: dbytes,
        up_bytes: ubytes,
    })
}

// ---- mapa de tráfego: para onde as minhas ligações vão ---------------------

#[derive(Serialize, Clone)]
pub struct Endpoint {
    pub ip: String,
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub city: String,
    pub org: String,
    /// nº de ligações estabelecidas para este destino
    pub count: u32,
}

/// `true` se o IP é encaminhável na Internet (exclui privados/locais).
fn is_public_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v)) => {
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_multicast() || v.is_unspecified() || v.is_broadcast()
                || v.octets()[0] == 100 && (64..128).contains(&v.octets()[1])) // CGNAT 100.64/10
        }
        Ok(std::net::IpAddr::V6(v)) => {
            let o = v.octets();
            !(v.is_loopback() || v.is_multicast() || v.is_unspecified()
                || (o[0] & 0xfe) == 0xfc            // ULA fc00::/7
                || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80)) // link-local fe80::/10
        }
        Err(_) => false,
    }
}

#[cfg(test)]
pub fn is_public_ip_for_test(ip: &str) -> bool {
    is_public_ip(ip)
}
#[cfg(test)]
pub fn ip_of_peer_for_test(p: &str) -> Option<String> {
    ip_of_peer(p)
}

/// Extrai o IP de "1.2.3.4:443" ou "[2a00:1450::1]:443".
fn ip_of_peer(peer: &str) -> Option<String> {
    if let Some(rest) = peer.strip_prefix('[') {
        rest.split(']').next().map(|s| s.to_string())
    } else {
        peer.rsplit_once(':').map(|(ip, _)| ip.to_string())
    }
}

/// Destinos das ligações TCP estabelecidas, geolocalizados (com cache por IP).
/// É a base do "mapa de para onde estou a navegar" — CDNs incluídos.
pub fn traffic(state: &AppState) -> Vec<Endpoint> {
    // 1) ligações estabelecidas → IPs remotos públicos, com contagem
    let out = match Command::new("ss").args(["-tunH", "state", "established"]).output() {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let mut counts: HashMap<String, u32> = HashMap::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        if let Some(ip) = ip_of_peer(f[4]) {
            if is_public_ip(&ip) {
                *counts.entry(ip).or_insert(0) += 1;
            }
        }
    }
    if counts.is_empty() {
        return Vec::new();
    }

    // 2) geolocaliza os que ainda não estão em cache (batch, máx. 100)
    let missing: Vec<String> = {
        let cache = state.ipgeo_cache.lock().unwrap();
        counts.keys().filter(|ip| !cache.contains_key(*ip)).take(100).cloned().collect()
    };
    if !missing.is_empty() {
        let body = serde_json::to_string(&missing).unwrap_or_else(|_| "[]".into());
        if let Ok(txt) = http_post_json("ip-api.com", "/batch?fields=status,query,lat,lon,country,city,org,as", &body) {
            if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&txt) {
                let mut cache = state.ipgeo_cache.lock().unwrap();
                for e in arr {
                    if e.get("status").and_then(|s| s.as_str()) != Some("success") {
                        continue;
                    }
                    let ip = e.get("query").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    if ip.is_empty() {
                        continue;
                    }
                    let org = {
                        let o = e.get("org").and_then(|x| x.as_str()).unwrap_or("");
                        if o.is_empty() { e.get("as").and_then(|x| x.as_str()).unwrap_or("") } else { o }
                    };
                    cache.insert(
                        ip.clone(),
                        Endpoint {
                            ip,
                            lat: e.get("lat").and_then(|x| x.as_f64()).unwrap_or(0.0),
                            lon: e.get("lon").and_then(|x| x.as_f64()).unwrap_or(0.0),
                            country: e.get("country").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            city: e.get("city").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            org: org.to_string(),
                            count: 0,
                        },
                    );
                }
            }
        }
    }

    // 3) junta contagens atuais à geo em cache
    let cache = state.ipgeo_cache.lock().unwrap();
    let mut eps: Vec<Endpoint> = counts
        .iter()
        .filter_map(|(ip, n)| {
            cache.get(ip).map(|e| Endpoint { count: *n, ..e.clone() })
        })
        .collect();
    eps.sort_by(|a, b| b.count.cmp(&a.count));
    eps
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
