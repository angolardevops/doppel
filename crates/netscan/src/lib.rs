//! netscan — descoberta de hosts e varrimento de portas em Rust puro.
//!
//! Substitui o `nmap` no contexto do Doppel, **sem root e sem instalar nada**.
//!
//! ## Como descobre hosts sem privilégios
//! O `nmap` precisa de root porque envia ARP em sockets raw. Aqui usamos duas
//! propriedades do kernel Linux:
//!
//! 1. **Uma tentativa de TCP connect para um IP da LAN obriga o kernel a
//!    resolver ARP** para esse IP. Se o host estiver vivo, responde ao ARP e o
//!    par IP↔MAC fica na cache (`/proc/net/arp`) — mesmo que ignore o TCP.
//! 2. **`ECONNREFUSED` prova que o host está vivo** (respondeu com RST).
//!
//! Portanto: varremos a sub-rede com connects curtos em paralelo e depois lemos
//! a cache ARP. O resultado é equivalente a um ARP-scan, sem qualquer privilégio.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use rayon::prelude::*;

/// Base de fabricantes (IEEE OUI) embebida: "PREFIXO\tFabricante" por linha.
const OUI: &str = include_str!("../oui.tsv");

/// Portas sondadas na descoberta. Bastaria UMA para provocar o ARP (é isso que
/// encontra a maioria dos hosts); as outras só acrescentam confirmação por TCP
/// e o RTT. Poucas portas = varrimento bastante mais rápido em IPs mortos.
const PROBE_PORTS: [u16; 3] = [80, 443, 22];

/// Portas varridas por omissão no detalhe de um host (as mais úteis).
pub const TOP_PORTS: [u16; 32] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 8888, 9090, 9200, 27017, 5000, 5353, 631, 161, 1883,
];

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        443 => "https",
        445 => "smb",
        631 => "ipp",
        993 => "imaps",
        995 => "pop3s",
        1723 => "pptp",
        1883 => "mqtt",
        3306 => "mysql",
        3389 => "rdp",
        5000 => "upnp/http",
        5353 => "mdns",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        8888 => "http-alt",
        9090 => "http/prometheus",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "",
    }
}

#[derive(Debug, Clone)]
pub struct Host {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub hostname: String,
    /// tempo de resposta em ms (só se respondeu a TCP)
    pub rtt_ms: Option<f64>,
    /// como foi detetado: "arp", "tcp" ou "arp+tcp"
    pub via: String,
}

#[derive(Debug, Clone)]
pub struct Port {
    pub port: u16,
    pub service: String,
    pub banner: String,
}

/// Expande um CIDR IPv4 (ex.: "192.168.1.0/24") nos IPs de host utilizáveis.
pub fn hosts_in_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (addr, plen) = cidr.split_once('/').ok_or("CIDR inválido (ex.: 192.168.1.0/24)")?;
    let base: Ipv4Addr = addr.trim().parse().map_err(|_| "IP inválido".to_string())?;
    let plen: u32 = plen.trim().parse().map_err(|_| "prefixo inválido".to_string())?;
    if plen > 32 {
        return Err("prefixo inválido".into());
    }
    let hosts = 1u64 << (32 - plen);
    if hosts > 4096 {
        return Err("intervalo demasiado grande (máx. /20)".into());
    }
    let mask = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
    let net = u32::from(base) & mask;
    let bcast = net | !mask;
    let mut out = Vec::new();
    if plen >= 31 {
        // /31 e /32 não têm rede/broadcast reservados
        for i in net..=bcast {
            out.push(Ipv4Addr::from(i));
        }
    } else {
        for i in (net + 1)..bcast {
            out.push(Ipv4Addr::from(i));
        }
    }
    Ok(out)
}

/// Fabricante a partir do MAC (prefixo OUI). `None` se desconhecido.
pub fn vendor_of(mac: &str) -> Option<&'static str> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).take(6).collect::<String>().to_uppercase();
    if hex.len() < 6 {
        return None;
    }
    OUI.lines().find(|l| l.starts_with(&hex)).and_then(|l| l.split_once('\t')).map(|(_, v)| v)
}

/// `true` se o MAC é *locally administered* (bit 1 do 1º octeto): não pertence a
/// nenhum fabricante — é um **MAC aleatório de privacidade** (típico de
/// telemóveis modernos e de interfaces virtuais).
pub fn is_randomized(mac: &str) -> bool {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).take(2).collect();
    u8::from_str_radix(&hex, 16).map(|b| b & 0b10 != 0).unwrap_or(false)
}

/// Descrição do fabricante pronta a mostrar: nome real, "MAC aleatório" ou vazio.
pub fn vendor_label(mac: &str) -> String {
    if mac.is_empty() {
        return String::new();
    }
    match vendor_of(mac) {
        Some(v) => v.to_string(),
        None if is_randomized(mac) => "MAC aleatório (privacidade)".to_string(),
        None => String::new(),
    }
}

/// Lê a cache ARP do kernel (`/proc/net/arp`) → IP → MAC (só entradas completas).
pub fn arp_cache() -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Ok(s) = std::fs::read_to_string("/proc/net/arp") {
        for line in s.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            // flags 0x2 = ATF_COM (entrada completa/válida)
            let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).unwrap_or(0);
            if flags & 0x2 == 0 || f[3] == "00:00:00:00:00:00" {
                continue;
            }
            m.insert(f[0].to_string(), f[3].to_uppercase());
        }
    }
    m
}

/// Sonda um IP: devolve o RTT se o host reagir (aceitar OU recusar a ligação).
fn probe(ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
    for p in PROBE_PORTS {
        let t0 = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::from((ip, p)), timeout) {
            Ok(_) => return Some(t0.elapsed().as_secs_f64() * 1000.0),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                // RST → o host existe e está vivo
                return Some(t0.elapsed().as_secs_f64() * 1000.0);
            }
            Err(_) => continue, // timeout/filtrado → tenta a próxima porta
        }
    }
    None
}

/// Resolve o nome de um IP por DNS inverso (getnameinfo).
pub fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr.s_addr = u32::from(ip).to_be();
    // `c_char` é i8 em x86_64 mas u8 em aarch64 — usar o alias mantém isto
    // portável (com `i8` fixo, a compilação em ARM falha).
    let mut host = [0 as libc::c_char; 256];
    let r = unsafe {
        libc::getnameinfo(
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if r != 0 {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }.to_str().ok().map(|s| s.to_string())
}

/// Descobre hosts numa sub-rede: varrimento TCP paralelo (que provoca ARP) e
/// depois leitura da cache ARP. Não precisa de root.
pub fn discover(cidr: &str, timeout_ms: u64) -> Result<Vec<Host>, String> {
    let ips = hosts_in_cidr(cidr)?;
    let timeout = Duration::from_millis(timeout_ms.clamp(50, 2000));

    // 1) varrimento paralelo — provoca a resolução ARP de cada IP
    let alive: Vec<(Ipv4Addr, Option<f64>)> = ips.par_iter().map(|ip| (*ip, probe(*ip, timeout))).collect();

    // 2) a cache ARP revela os hosts vivos, mesmo os que ignoram TCP
    let arp = arp_cache();

    // 3) une as duas fontes
    let mut hosts: Vec<Host> = alive
        .into_iter()
        .filter_map(|(ip, rtt)| {
            let key = ip.to_string();
            let mac = arp.get(&key).cloned();
            if rtt.is_none() && mac.is_none() {
                return None; // sem sinal → não está lá
            }
            let via = match (&mac, &rtt) {
                (Some(_), Some(_)) => "arp+tcp",
                (Some(_), None) => "arp",
                _ => "tcp",
            };
            let mac = mac.unwrap_or_default();
            Some(Host {
                vendor: vendor_label(&mac),
                ip: key,
                mac,
                hostname: String::new(),
                rtt_ms: rtt,
                via: via.to_string(),
            })
        })
        .collect();

    // 4) nomes por DNS inverso, em paralelo (só para os encontrados)
    let names: Vec<String> = hosts
        .par_iter()
        .map(|h| h.ip.parse::<Ipv4Addr>().ok().and_then(reverse_dns).unwrap_or_default())
        .collect();
    for (h, n) in hosts.iter_mut().zip(names) {
        h.hostname = n;
    }

    hosts.sort_by(|a, b| {
        let pa = a.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0);
        let pb = b.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0);
        pa.cmp(&pb)
    });
    Ok(hosts)
}

/// Varre portas de um host (TCP connect) e tenta ler o banner do serviço.
pub fn scan_ports(ip: &str, ports: &[u16], timeout_ms: u64) -> Result<Vec<Port>, String> {
    let addr: Ipv4Addr = ip.parse().map_err(|_| "IP inválido".to_string())?;
    let timeout = Duration::from_millis(timeout_ms.clamp(50, 3000));
    let mut open: Vec<Port> = ports
        .par_iter()
        .filter_map(|&p| {
            let mut s = TcpStream::connect_timeout(&SocketAddr::from((addr, p)), timeout).ok()?;
            let banner = grab_banner(&mut s, p);
            Some(Port { port: p, service: service_name(p).to_string(), banner })
        })
        .collect();
    open.sort_by_key(|p| p.port);
    Ok(open)
}

/// Lê o banner do serviço (best-effort): alguns falam primeiro, outros só após
/// um pedido — por isso enviamos um HEAD em portas do tipo HTTP.
fn grab_banner(s: &mut TcpStream, port: u16) -> String {
    let _ = s.set_read_timeout(Some(Duration::from_millis(600)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(600)));
    if matches!(port, 80 | 8080 | 8888 | 9090 | 5000) {
        let _ = s.write_all(b"HEAD / HTTP/1.0\r\n\r\n");
    }
    let mut buf = [0u8; 256];
    match s.read(&mut buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_control())
            .take(120)
            .collect(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expande_cidr() {
        let h = hosts_in_cidr("192.168.1.0/30").unwrap();
        assert_eq!(h, vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]);
        let h = hosts_in_cidr("10.0.0.0/24").unwrap();
        assert_eq!(h.len(), 254);
        assert_eq!(h[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(h[253], Ipv4Addr::new(10, 0, 0, 254));
        // /32 → o próprio host
        assert_eq!(hosts_in_cidr("8.8.8.8/32").unwrap().len(), 1);
        // intervalos absurdos e lixo são recusados
        assert!(hosts_in_cidr("10.0.0.0/8").is_err());
        assert!(hosts_in_cidr("nao-e-cidr").is_err());
        assert!(hosts_in_cidr("10.0.0.0/33").is_err());
    }

    #[test]
    fn fabricante_do_oui() {
        // OUI real da IEEE embebido
        assert_eq!(vendor_of("BC:24:11:87:A4:C7"), Some("Proxmox Server Solutions GmbH"));
        assert_eq!(vendor_of("bc2411000000"), Some("Proxmox Server Solutions GmbH"));
        assert!(vendor_of("FF:FF:FF:FF:FF:FF").is_none());
        assert!(vendor_of("xx").is_none());
    }

    #[test]
    fn mac_aleatorio_e_reconhecido() {
        // bit 1 do 1º octeto ligado → locally administered (privacidade)
        assert!(is_randomized("22:FF:63:10:BB:0B")); // 0x22 & 0b10 != 0
        assert!(is_randomized("F6:3A:22:58:60:D9"));
        assert!(is_randomized("0A:F3:5D:D5:88:B2"));
        // OUIs reais de fabricante não são aleatórios
        assert!(!is_randomized("A0:B3:39:65:88:94")); // Intel
        assert!(!is_randomized("BC:24:11:87:A4:C7")); // Proxmox
        // etiqueta pronta a mostrar
        assert_eq!(vendor_label("BC:24:11:87:A4:C7"), "Proxmox Server Solutions GmbH");
        assert_eq!(vendor_label("22:FF:63:10:BB:0B"), "MAC aleatório (privacidade)");
        assert_eq!(vendor_label(""), "");
    }

    #[test]
    fn cache_arp_le_do_kernel() {
        // não deve entrar em pânico; entradas válidas têm MAC completo
        let m = arp_cache();
        assert!(m.values().all(|v| v.len() == 17 && v != "00:00:00:00:00:00"));
    }

    #[test]
    fn portas_invalidas_recusadas() {
        assert!(scan_ports("nao-e-ip", &[80], 100).is_err());
    }
}

#[cfg(test)]
mod live {
    /// Validação real contra a LAN (ignorada por omissão):
    ///   cargo test -p netscan --release -- --ignored --nocapture descobre_rede_real
    #[test]
    #[ignore]
    fn descobre_rede_real() {
        let cidr = std::env::var("NETSCAN_CIDR").unwrap_or_else(|_| "172.16.95.0/24".into());
        let t0 = std::time::Instant::now();
        let hosts = super::discover(&cidr, 300).expect("discover");
        println!("\n[netscan] {cidr} → {} hosts em {:.1}s", hosts.len(), t0.elapsed().as_secs_f64());
        for h in &hosts {
            println!(
                "  {:<15} {:<18} {:<32} {} {}",
                h.ip,
                if h.mac.is_empty() { "-" } else { &h.mac },
                if h.vendor.is_empty() { "-" } else { &h.vendor },
                h.hostname,
                h.via
            );
        }
        assert!(!hosts.is_empty(), "deve encontrar pelo menos o gateway");
    }
}
