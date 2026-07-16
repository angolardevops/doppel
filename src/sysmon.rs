//! Monitorização do host em tempo real: CPU (global + por-core + online/offline),
//! RAM/swap, load, uptime, temperaturas, GPU (NVIDIA/AMD) e partições (FHS).

use serde::Serialize;
use sysinfo::{Components, Disks, System};

#[derive(Serialize)]
pub struct Core {
    pub id: usize,
    pub usage: f32,
    pub freq: u64,
}

#[derive(Serialize)]
pub struct Temp {
    pub label: String,
    pub celsius: f32,
}

#[derive(Serialize)]
pub struct Gpu {
    pub name: String,
    pub util: Option<f32>,
    pub mem_used: Option<u64>,
    pub mem_total: Option<u64>,
    pub temp: Option<f32>,
}

#[derive(Serialize)]
pub struct Part {
    pub mount: String,
    pub fs: String,
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub removable: bool,
}

#[derive(Serialize)]
pub struct Monitor {
    pub cpu: f32,
    pub cores: Vec<Core>,
    pub cores_online: usize,
    pub cores_total: usize,
    pub mem_total: u64,
    pub mem_used: u64,
    pub mem_available: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub load: [f64; 3],
    pub uptime: u64,
    pub temp_max: Option<f32>,
    pub temps: Vec<Temp>,
    pub gpus: Vec<Gpu>,
    pub parts: Vec<Part>,
}

/// Constrói o retrato de monitorização. O `System` deve já ter `refresh_cpu_all`
/// e `refresh_memory` chamados (feito no handler, para o delta de CPU ser real).
pub fn snapshot(sys: &System) -> Monitor {
    let cores: Vec<Core> = sys
        .cpus()
        .iter()
        .enumerate()
        .map(|(i, c)| Core { id: i, usage: c.cpu_usage(), freq: c.frequency() })
        .collect();
    let (cores_online, cores_total) = core_counts(cores.len());

    let comps = Components::new_with_refreshed_list();
    let mut temps: Vec<Temp> = comps
        .iter()
        .map(|c| Temp { label: c.label().to_string(), celsius: c.temperature() })
        .filter(|t| t.celsius.is_finite() && t.celsius > 0.0)
        .collect();
    temps.sort_by(|a, b| b.celsius.partial_cmp(&a.celsius).unwrap_or(std::cmp::Ordering::Equal));
    let temp_max = temps.first().map(|t| t.celsius);
    temps.truncate(8);

    let disks = Disks::new_with_refreshed_list();
    let mut parts: Vec<Part> = disks
        .iter()
        .map(|d| {
            let total = d.total_space();
            let free = d.available_space();
            Part {
                mount: d.mount_point().to_string_lossy().into_owned(),
                fs: d.file_system().to_string_lossy().into_owned(),
                total,
                free,
                used: total.saturating_sub(free),
                removable: d.is_removable(),
            }
        })
        .collect();
    parts.sort_by(|a, b| b.total.cmp(&a.total));

    let la = System::load_average();

    Monitor {
        cpu: sys.global_cpu_usage(),
        cores,
        cores_online,
        cores_total,
        mem_total: sys.total_memory(),
        mem_used: sys.used_memory(),
        mem_available: sys.available_memory(),
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
        load: [la.one, la.five, la.fifteen],
        uptime: System::uptime(),
        temp_max,
        temps,
        gpus: gpu_snapshot(),
        parts,
    }
}

/// Conta cores lógicos totais vs online via /sys (cpu0 nunca tem 'online').
fn core_counts(fallback: usize) -> (usize, usize) {
    let mut total = 0usize;
    let mut online = 0usize;
    if let Ok(rd) = std::fs::read_dir("/sys/devices/system/cpu") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_cpu = name.strip_prefix("cpu").is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
            if !is_cpu {
                continue;
            }
            total += 1;
            let on = std::fs::read_to_string(e.path().join("online"))
                .map(|s| s.trim() == "1")
                .unwrap_or(true); // cpu0 sem ficheiro → sempre online
            if on {
                online += 1;
            }
        }
    }
    if total == 0 {
        (fallback, fallback)
    } else {
        (online, total)
    }
}

/// GPU: tenta NVIDIA (nvidia-smi) e depois AMD/Intel (/sys/class/drm).
fn gpu_snapshot() -> Vec<Gpu> {
    if let Ok(out) = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
            "--format=csv,noheader,nounits",
        ])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            let gpus: Vec<Gpu> = s
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let f: Vec<&str> = l.split(',').map(|x| x.trim()).collect();
                    let mib = |i: usize| f.get(i).and_then(|x| x.parse::<u64>().ok()).map(|m| m * 1024 * 1024);
                    Gpu {
                        name: f.first().map(|x| x.to_string()).unwrap_or_else(|| "GPU".into()),
                        util: f.get(1).and_then(|x| x.parse().ok()),
                        mem_used: mib(2),
                        mem_total: mib(3),
                        temp: f.get(4).and_then(|x| x.parse().ok()),
                    }
                })
                .collect();
            if !gpus.is_empty() {
                return gpus;
            }
        }
    }

    // AMD/Intel: utilização via gpu_busy_percent
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/drm") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_card = name.strip_prefix("card").is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
            if !is_card {
                continue;
            }
            if let Ok(s) = std::fs::read_to_string(e.path().join("device/gpu_busy_percent")) {
                if let Ok(u) = s.trim().parse::<f32>() {
                    out.push(Gpu { name: format!("GPU {name}"), util: Some(u), mem_used: None, mem_total: None, temp: None });
                }
            }
        }
    }
    out
}
