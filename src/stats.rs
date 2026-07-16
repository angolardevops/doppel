//! Métricas em tempo real: memória do sistema e ocupação do disco onde a pasta vive.

use std::path::Path;

use serde::Serialize;
use sysinfo::{Disks, System};

#[derive(Serialize)]
pub struct MemStats {
    pub total: u64,
    pub used: u64,
    pub available: u64,
}

#[derive(Serialize)]
pub struct DiskStats {
    pub mount: String,
    pub total: u64,
    pub free: u64,
    pub used: u64,
}

#[derive(Serialize)]
pub struct SysStats {
    pub mem: MemStats,
    pub disk: Option<DiskStats>,
}

pub fn collect(root: &Path) -> SysStats {
    let mut sys = System::new();
    sys.refresh_memory();
    let mem = MemStats {
        total: sys.total_memory(),
        used: sys.used_memory(),
        available: sys.available_memory(),
    };

    // Disco cujo ponto de montagem é o prefixo mais longo do caminho da raiz.
    let disks = Disks::new_with_refreshed_list();
    let root_abs = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut best: Option<DiskStats> = None;
    let mut best_len = 0usize;
    for d in disks.list() {
        let mp = d.mount_point();
        if root_abs.starts_with(mp) {
            let len = mp.as_os_str().len();
            if len >= best_len {
                best_len = len;
                let total = d.total_space();
                let free = d.available_space();
                best = Some(DiskStats {
                    mount: mp.to_string_lossy().into_owned(),
                    total,
                    free,
                    used: total.saturating_sub(free),
                });
            }
        }
    }

    SysStats { mem, disk: best }
}
