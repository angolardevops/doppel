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
pub struct NetInfo {
    pub ifaces: Vec<Iface>,
    pub sockets: Vec<Sock>,
}

pub fn info() -> NetInfo {
    NetInfo { ifaces: ifaces(), sockets: sockets() }
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
