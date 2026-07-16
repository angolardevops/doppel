//! Top processos por CPU e por memória, com o serviço (unit systemd) a que
//! pertencem — derivado de /proc/<pid>/cgroup.

use serde::Serialize;
use sysinfo::{ProcessesToUpdate, System};

#[derive(Serialize, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    /// % CPU (100 = um core inteiro; pode exceder 100 em multi-core)
    pub cpu: f32,
    pub mem: u64,
    pub service: String,
}

#[derive(Serialize)]
pub struct ProcSnapshot {
    pub ncpu: usize,
    pub top_cpu: Vec<ProcInfo>,
    pub top_mem: Vec<ProcInfo>,
}

/// Amostra os processos. O `System` é reutilizado entre chamadas: como o CPU%
/// é calculado como delta entre amostras, o polling (~2s) dá valores reais.
pub fn collect(sys: &mut System) -> ProcSnapshot {
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    // Base leve (sem resolver serviço ainda — só para os que entram no top).
    let base: Vec<(u32, String, f32, u64)> = sys
        .processes()
        .values()
        .map(|p| {
            (
                p.pid().as_u32(),
                p.name().to_string_lossy().into_owned(),
                p.cpu_usage(),
                p.memory(),
            )
        })
        .collect();

    let mut by_cpu = base.clone();
    by_cpu.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    by_cpu.truncate(10);

    let mut by_mem = base;
    by_mem.sort_by(|a, b| b.3.cmp(&a.3));
    by_mem.truncate(10);

    let to_info = |(pid, name, cpu, mem): (u32, String, f32, u64)| ProcInfo {
        pid,
        name,
        cpu,
        mem,
        service: service_of(pid),
    };

    ProcSnapshot {
        ncpu,
        top_cpu: by_cpu.into_iter().map(to_info).collect(),
        top_mem: by_mem.into_iter().map(to_info).collect(),
    }
}

/// Deriva a unit systemd de um pid a partir de /proc/<pid>/cgroup.
/// Prefere `*.service`; recorre a `*.scope` (ex.: sessões) se não houver serviço.
fn service_of(pid: u32) -> String {
    let content = match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        Ok(c) => c,
        Err(_) => return "—".into(),
    };
    let mut scope: Option<String> = None;
    for line in content.lines() {
        let path = line.rsplit(':').next().unwrap_or("");
        for comp in path.split('/').rev() {
            if comp.ends_with(".service") {
                return comp.to_string();
            }
            if comp.ends_with(".scope") && scope.is_none() {
                scope = Some(comp.to_string());
            }
        }
    }
    scope.unwrap_or_else(|| "—".into())
}
