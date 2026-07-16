//! Operações sobre duplicados e sobre a quarentena, sempre com verificação
//! **byte-a-byte** onde há risco de perder dados, e com progresso em tempo real.
//!
//! - `operate(Delete)`     — apaga definitivamente (liberta espaço já).
//! - `operate(Quarantine)` — move o duplicado para a quarentena (reversível).
//! - `purge`               — apaga definitivamente ficheiros já em quarentena.
//! - `restore`             — devolve ficheiros da quarentena ao local original.
//!
//! Regra invariante: nunca remove/quarentena o último membro de um grupo.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::Ordering;

use rayon::prelude::*;
use serde::Serialize;

use crate::state::{self, AppState, QEntry};

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Delete,
    Quarantine,
}

#[derive(Serialize, Default)]
pub struct OpReport {
    pub processed: usize,
    /// bytes libertados (só em Delete/Purge)
    pub freed: u64,
    /// bytes movidos para quarentena (só em Quarantine)
    pub quarantined: u64,
    pub skipped: Vec<Skip>,
}

#[derive(Serialize)]
pub struct Skip {
    pub path: String,
    pub reason: String,
}

/// Uma unidade de trabalho: apagar/quarentenar `path` (tamanho `size`, hash
/// conhecido), verificando byte-a-byte contra `keeper` primeiro.
struct PlanItem {
    path: String,
    size: u64,
    hash: String,
    keeper: String,
}

enum Outcome {
    Done { path: String, size: u64, quarantined: bool },
    Skip(Skip),
}

/// Apaga ou põe em quarentena os `paths` indicados (duplicados do último scan).
///
/// Memória O(selecionados) — constrói só o plano dos ficheiros escolhidos e o
/// seu guardião (nunca a matriz N² de membros por ficheiro). O trabalho corre
/// num pool pequeno e dedicado (I/O-bound) para não saturar o sistema.
pub fn operate(state: &AppState, paths: Vec<String>, mode: Mode) -> OpReport {
    let mut report = OpReport::default();
    let sel: HashSet<String> = paths.into_iter().collect();
    if sel.is_empty() {
        return report;
    }

    // Plano: percorre os grupos UMA vez e recolhe só os itens selecionados que
    // têm um guardião seguro. Nunca clona a lista de membros por ficheiro.
    let plan: Vec<PlanItem> = {
        let r = state.result.lock().unwrap();
        let mut plan = Vec::new();
        for g in &r.groups {
            if !g.files.iter().any(|f| sel.contains(&f.path)) {
                continue; // grupo não tocado
            }
            let all_selected = g.files.iter().all(|f| sel.contains(&f.path));
            // guardião: um membro NÃO selecionado; se todos foram, mantém o 1º.
            let keeper = if all_selected {
                g.files.first().map(|f| f.path.clone())
            } else {
                g.files.iter().find(|f| !sel.contains(&f.path)).map(|f| f.path.clone())
            };
            let keeper = match keeper {
                Some(k) => k,
                None => continue,
            };
            for f in &g.files {
                if sel.contains(&f.path) && f.path != keeper {
                    plan.push(PlanItem {
                        path: f.path.clone(),
                        size: g.size,
                        hash: g.hash.clone(),
                        keeper: keeper.clone(),
                    });
                }
            }
        }
        plan
    };

    state.set_phase(if mode == Mode::Delete { state::DELETING } else { state::QUARANTINING });
    state.set_progress(0, plan.len());

    // Pool dedicado e pequeno: paralelo (I/O-bound) mas gentil com a CPU.
    // stack_size explícito: o rayon divide recursivamente e os workers precisam
    // de mais do que os 2 MB por omissão em planos grandes (senão: stack overflow).
    let nthreads = std::thread::available_parallelism().map(|n| n.get().min(4)).unwrap_or(2);
    let run = |it: &PlanItem| -> Outcome {
        state.tick();
        process_item(state, it, mode)
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(nthreads)
        .stack_size(8 * 1024 * 1024)
        .build();
    let outcomes: Vec<Outcome> = match pool {
        Ok(pool) => pool.install(|| plan.par_iter().map(run).collect()),
        Err(_) => plan.iter().map(run).collect(),
    };

    // Agregação serial (contadores e conjunto de removidos).
    let mut done: HashSet<String> = HashSet::new();
    for o in outcomes {
        match o {
            Outcome::Done { path, size, quarantined } => {
                report.processed += 1;
                if quarantined {
                    report.quarantined += size;
                } else {
                    report.freed += size;
                    state.freed.fetch_add(size, Ordering::Relaxed);
                    state.removed.fetch_add(1, Ordering::Relaxed);
                }
                done.insert(path);
            }
            Outcome::Skip(s) => report.skipped.push(s),
        }
    }

    if !done.is_empty() {
        prune_groups(state, &done);
    }
    if mode == Mode::Quarantine {
        state.quarantine.lock().unwrap().save();
    }
    state.set_phase(state::IDLE);
    state.set_progress(0, 0);
    state::release_memory();
    report
}

/// Verifica byte-a-byte e aplica (apagar/mover). Sem estado partilhado além de
/// contadores atómicos e do Mutex da quarentena.
fn process_item(state: &AppState, it: &PlanItem, mode: Mode) -> Outcome {
    match bytes_equal(Path::new(&it.path), Path::new(&it.keeper), it.size) {
        Ok(true) => {}
        Ok(false) => return Outcome::Skip(skip(&it.path, "conteúdo divergente na verificação byte-a-byte — mantido")),
        Err(e) => return Outcome::Skip(skip(&it.path, &format!("falha a verificar: {e}"))),
    }
    match mode {
        Mode::Delete => match std::fs::remove_file(&it.path) {
            Ok(()) => Outcome::Done { path: it.path.clone(), size: it.size, quarantined: false },
            Err(e) => Outcome::Skip(skip(&it.path, &format!("erro ao apagar: {e}"))),
        },
        Mode::Quarantine => match quarantine_move(state, &it.path, it.size, &it.hash) {
            Ok(()) => Outcome::Done { path: it.path.clone(), size: it.size, quarantined: true },
            Err(e) => Outcome::Skip(skip(&it.path, &format!("erro ao mover para quarentena: {e}"))),
        },
    }
}

/// Move um ficheiro para a quarentena e regista-o (hash já conhecido — sem re-hash).
fn quarantine_move(state: &AppState, path: &str, size: u64, hash: &str) -> std::io::Result<()> {
    let (id, dest) = {
        let mut q = state.quarantine.lock().unwrap();
        let id = q.alloc_id();
        (id, q.store_path(id))
    };
    // rename rápido; se for cross-device, copia (em streaming) + remove.
    match std::fs::rename(path, &dest) {
        Ok(()) => {}
        Err(_) => {
            std::fs::copy(path, &dest)?;
            std::fs::remove_file(path)?;
        }
    }
    let mut q = state.quarantine.lock().unwrap();
    q.entries.push(QEntry {
        id,
        original: path.to_string(),
        size,
        hash: hash.to_string(),
        ts: state::now(),
    });
    Ok(())
}

/// Remove ficheiros da estrutura de grupos em memória e recalcula o recuperável.
fn prune_groups(state: &AppState, removed: &HashSet<String>) {
    let mut r = state.result.lock().unwrap();
    for g in &mut r.groups {
        g.files.retain(|f| !removed.contains(&f.path));
        g.count = g.files.len();
        g.wasted = if g.count > 1 { g.size * (g.count as u64 - 1) } else { 0 };
    }
    r.groups.retain(|g| g.count > 1);
    r.reclaimable = r.groups.iter().map(|g| g.wasted).sum();
    drop(r);
    // Invalida a cache de análise da pasta atual — o disco mudou.
    state.scan_cache.lock().unwrap().remove(&state.root().to_string_lossy().into_owned());
    state.bump_version();
}

// ---- Operações sobre a quarentena ----------------------------------------

/// Apaga definitivamente entradas da quarentena — liberta espaço.
pub fn purge(state: &AppState, ids: Vec<u64>) -> OpReport {
    let mut report = OpReport::default();
    let idset: HashSet<u64> = ids.into_iter().collect();
    state.set_phase(state::PURGING);

    let targets: Vec<QEntry> = {
        let q = state.quarantine.lock().unwrap();
        q.entries.iter().filter(|e| idset.contains(&e.id)).cloned().collect()
    };
    state.set_progress(0, targets.len());

    let mut removed_ids: HashSet<u64> = HashSet::new();
    for e in &targets {
        state.tick();
        let sp = state.quarantine.lock().unwrap().store_path(e.id);
        match std::fs::remove_file(&sp) {
            Ok(()) => {
                removed_ids.insert(e.id);
                report.processed += 1;
                report.freed += e.size;
                state.freed.fetch_add(e.size, Ordering::Relaxed);
                state.removed.fetch_add(1, Ordering::Relaxed);
            }
            Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => {
                // ficheiro já não existe: limpa a entrada na mesma
                removed_ids.insert(e.id);
                report.processed += 1;
            }
            Err(e2) => report.skipped.push(skip(&e.original, &format!("erro ao apagar da quarentena: {e2}"))),
        }
    }

    finalize_quarantine(state, &removed_ids);
    report
}

/// Devolve entradas da quarentena ao seu local original.
pub fn restore(state: &AppState, ids: Vec<u64>) -> OpReport {
    let mut report = OpReport::default();
    let idset: HashSet<u64> = ids.into_iter().collect();
    state.set_phase(state::RESTORING);

    let targets: Vec<QEntry> = {
        let q = state.quarantine.lock().unwrap();
        q.entries.iter().filter(|e| idset.contains(&e.id)).cloned().collect()
    };
    state.set_progress(0, targets.len());

    let mut removed_ids: HashSet<u64> = HashSet::new();
    for e in &targets {
        state.tick();
        let sp = state.quarantine.lock().unwrap().store_path(e.id);
        let orig = Path::new(&e.original);
        if orig.exists() {
            report.skipped.push(skip(&e.original, "o caminho original já existe — não sobreposto"));
            continue;
        }
        if let Some(parent) = orig.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::rename(&sp, orig).or_else(|_| {
            std::fs::copy(&sp, orig).and_then(|_| std::fs::remove_file(&sp))
        }) {
            Ok(_) => {
                removed_ids.insert(e.id);
                report.processed += 1;
            }
            Err(e2) => report.skipped.push(skip(&e.original, &format!("erro ao restaurar: {e2}"))),
        }
    }

    finalize_quarantine(state, &removed_ids);
    report
}

fn finalize_quarantine(state: &AppState, removed_ids: &HashSet<u64>) {
    if !removed_ids.is_empty() {
        let mut q = state.quarantine.lock().unwrap();
        q.entries.retain(|e| !removed_ids.contains(&e.id));
        q.save();
        drop(q);
        state.bump_version();
    }
    state.set_phase(state::IDLE);
    state.set_progress(0, 0);
    state::release_memory();
}

// ---- utilitários ----------------------------------------------------------

fn skip(path: &str, reason: &str) -> Skip {
    Skip { path: path.to_string(), reason: reason.to_string() }
}

/// Compara dois ficheiros byte-a-byte; exige ambos com tamanho `expected`.
fn bytes_equal(a: &Path, b: &Path, expected: u64) -> std::io::Result<bool> {
    let fa = std::fs::File::open(a)?;
    let fb = std::fs::File::open(b)?;
    if fa.metadata()?.len() != expected || fb.metadata()?.len() != expected {
        return Ok(false);
    }
    let mut ra = std::io::BufReader::with_capacity(64 * 1024, fa);
    let mut rb = std::io::BufReader::with_capacity(64 * 1024, fb);
    // buffers no HEAP (não na stack) — seguro sob paralelismo do rayon.
    let mut ba = vec![0u8; 64 * 1024];
    let mut bb = vec![0u8; 64 * 1024];
    loop {
        let na = read_full(&mut ra, &mut ba)?;
        let nb = read_full(&mut rb, &mut bb)?;
        if na != nb {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
        if ba[..na] != bb[..nb] {
            return Ok(false);
        }
    }
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

// ---- testes de integração -------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{quarantine_dir, AppState};
    use std::fs;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        p.push(format!("doppel-test-{pid}-{name}"));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn mkstate(root: PathBuf, home: PathBuf) -> AppState {
        let q = quarantine_dir(&home);
        AppState::new("tester".into(), home, root, q)
    }

    #[test]
    fn scan_quarantine_restore_purge_and_byteverify() {
        let home = tmp("home");
        let root = tmp("scan");
        // grupo A: 3 iguais; grupo B: 2 iguais; impostor: mesmo tamanho, conteúdo diferente
        fs::write(root.join("a1.txt"), b"AAAAAAAAAAAA content").unwrap();
        fs::write(root.join("a2.txt"), b"AAAAAAAAAAAA content").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/a3.txt"), b"AAAAAAAAAAAA content").unwrap();
        fs::write(root.join("b1.bin"), vec![7u8; 5000]).unwrap();
        fs::write(root.join("b2.bin"), vec![7u8; 5000]).unwrap();
        fs::write(root.join("impostor.txt"), b"BBBBBBBBBBBB content").unwrap(); // = tamanho de aN

        let st = mkstate(root.clone(), home.clone());
        crate::scan::run_with(&st, false);
        assert_eq!(st.result.lock().unwrap().groups.len(), 2, "deve achar 2 grupos");
        let reclaim = st.result.lock().unwrap().reclaimable;
        assert_eq!(reclaim, 20 * 2 + 5000, "recuperável = 2*20 (A) + 5000 (B)");

        // Quarentena dos extras do grupo A (mantém a1).
        let a2 = root.join("a2.txt").to_string_lossy().into_owned();
        let a3 = root.join("sub/a3.txt").to_string_lossy().into_owned();
        let rep = operate(&st, vec![a2.clone(), a3.clone()], Mode::Quarantine);
        assert_eq!(rep.processed, 2);
        assert!(!root.join("a2.txt").exists(), "a2 movido");
        assert!(!root.join("sub/a3.txt").exists(), "a3 movido");
        assert!(root.join("a1.txt").exists(), "a1 mantido");
        assert_eq!(st.quarantine.lock().unwrap().entries.len(), 2);
        assert_eq!(st.freed.load(std::sync::atomic::Ordering::Relaxed), 0, "quarentena não liberta");

        // Restaura a3.
        let id_a3 = st.quarantine.lock().unwrap().entries.iter()
            .find(|e| e.original == a3).unwrap().id;
        let rep = restore(&st, vec![id_a3]);
        assert_eq!(rep.processed, 1);
        assert!(root.join("sub/a3.txt").exists(), "a3 restaurado");
        assert_eq!(st.quarantine.lock().unwrap().entries.len(), 1);

        // Purga a2 definitivamente → liberta 20 bytes.
        let id_a2 = st.quarantine.lock().unwrap().entries[0].id;
        let rep = purge(&st, vec![id_a2]);
        assert_eq!(rep.processed, 1);
        assert_eq!(rep.freed, 20);
        assert_eq!(st.quarantine.lock().unwrap().entries.len(), 0);
        assert_eq!(st.freed.load(std::sync::atomic::Ordering::Relaxed), 20);

        // Byte-verify: adultera b2 (mesmo tamanho) e tenta apagar → tem de ser ignorado.
        let mut data = vec![7u8; 5000]; data[100] = 9;
        fs::write(root.join("b2.bin"), &data).unwrap();
        let b2 = root.join("b2.bin").to_string_lossy().into_owned();
        let rep = operate(&st, vec![b2], Mode::Delete);
        assert_eq!(rep.processed, 0, "adulterado não deve ser apagado");
        assert_eq!(rep.skipped.len(), 1);
        assert!(root.join("b2.bin").exists(), "b2 preservado");

        // Nunca apaga o último: seleciona ambos de B (b1 já não casa com b2 adulterado,
        // mas b1 sozinho seria o último) — via grupo, força manter 1.
        let _ = fs::remove_dir_all(&home);
        let _ = fs::remove_dir_all(&root);
    }

    fn rss_kb(field: &str) -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find(|l| l.starts_with(field))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|x| x.parse().ok())
            .unwrap_or(0)
    }

    /// Medição manual (ignorada por omissão):
    ///   DOPPEL_TEST_DIR=/caminho cargo test --release -- --ignored --nocapture mem_scan_big
    #[test]
    #[ignore]
    fn mem_scan_big() {
        let dir = std::env::var("DOPPEL_TEST_DIR").unwrap_or_else(|_| "/home/walter/.cargo".into());
        let home = tmp("home3");
        let st = mkstate(std::path::PathBuf::from(&dir), home.clone());
        println!("\n[mem] pasta={dir}\n[mem] antes:  RSS={} MB", rss_kb("VmRSS:") / 1024);
        crate::scan::run_with(&st, true);
        let (tf, ng) = {
            let r = st.result.lock().unwrap();
            (r.total_files, r.groups.len())
        };
        println!(
            "[mem] depois: RSS={} MB · pico(VmHWM)={} MB · ficheiros={tf} · grupos={ng}",
            rss_kb("VmRSS:") / 1024,
            rss_kb("VmHWM:") / 1024,
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// Medição de memória da remoção (ignorada): grupo enorme de idênticos.
    ///   cargo test --release -- --ignored --nocapture mem_operate_big
    #[test]
    #[ignore]
    fn mem_operate_big() {
        let home = tmp("home5");
        let root = tmp("scan5");
        let n = 30_000usize;
        for i in 0..n {
            fs::write(root.join(format!("d{i:05}")), b"x").unwrap();
        }
        let st = mkstate(root.clone(), home.clone());
        crate::scan::run_with(&st, false);
        let all: Vec<String> = (0..n).map(|i| root.join(format!("d{i:05}")).to_string_lossy().into_owned()).collect();
        println!("\n[memop] scan OK. antes RSS={} MB", rss_kb("VmRSS:") / 1024);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let rep = operate(&st, all, Mode::Delete);
        println!(
            "[memop] {} ficheiros apagados · RSS={} MB · pico(VmHWM)={} MB",
            rep.processed,
            rss_kb("VmRSS:") / 1024,
            rss_kb("VmHWM:") / 1024
        );
        let _ = fs::remove_dir_all(&home);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn operate_large_group_all_selected_keeps_one() {
        let home = tmp("home4");
        let root = tmp("scan4");
        // 500 ficheiros idênticos — antes gerava 500*500 clones de paths (O(N²)).
        let n = 500usize;
        for i in 0..n {
            fs::write(root.join(format!("dup{i:04}.bin")), b"payload identico xyz").unwrap();
        }
        let st = mkstate(root.clone(), home.clone());
        crate::scan::run_with(&st, false);
        assert_eq!(st.result.lock().unwrap().groups.len(), 1);

        // Seleciona TODOS → tem de quarentenar n-1 e manter exatamente 1.
        let all: Vec<String> = (0..n)
            .map(|i| root.join(format!("dup{i:04}.bin")).to_string_lossy().into_owned())
            .collect();
        let rep = operate(&st, all, Mode::Quarantine);
        assert_eq!(rep.processed, n - 1, "deve mover n-1");
        let remaining = fs::read_dir(&root).unwrap().count();
        assert_eq!(remaining, 1, "deve sobrar exatamente 1 ficheiro");
        assert_eq!(st.quarantine.lock().unwrap().entries.len(), n - 1);

        let _ = fs::remove_dir_all(&home);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn net_disks_logs_timers() {
        // rede: deve haver pelo menos o loopback
        let n = crate::netinfo::info();
        assert!(n.ifaces.iter().any(|i| i.name == "lo"), "deve listar loopback");
        // discos: lsblk devolve uma árvore com blockdevices
        let d = crate::disks::blocks();
        assert!(d.get("tree").and_then(|t| t.get("blockdevices")).is_some());
        // du numa pasta temporária
        let dir = tmp("du1");
        std::fs::write(dir.join("f"), b"conteudo").unwrap();
        let du = crate::disks::du(&dir.to_string_lossy()).unwrap();
        assert!(!du.is_empty());
        // logs: journalctl (pode falhar sem grupo, mas não deve entrar em pânico)
        let _ = crate::logs::recent("", 5, "", "");
        // smart validação: dispositivo inválido rejeitado sem sudo
        assert!(crate::disks::smart("walter", "", "sda").is_err());
        assert!(crate::disks::smart("walter", "", "/dev/x; rm").is_err());
        // timers não entra em pânico
        let _ = crate::services::timers();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn services_list_e_validacao() {
        let s = crate::services::list();
        assert!(!s.is_empty(), "deve listar serviços systemd");
        assert!(s.iter().all(|x| x.unit.ends_with(".service")));
        // ação desconhecida e unit inválida → erro sem correr sudo
        assert!(crate::services::action("walter", "", "cron.service", "hack").is_err());
        assert!(crate::services::action("walter", "", "a b;service", "start").is_err());
    }

    #[test]
    fn users_list_e_validacao() {
        let l = crate::users::list();
        assert!(!l.users.is_empty(), "deve listar utilizadores");
        assert!(l.users.iter().any(|u| u.name == "root" && u.uid == 0), "deve conter root");
        assert!(!l.groups.is_empty(), "deve listar grupos");
        // validação: username inválido → erro sem correr sudo
        assert!(crate::users::create("walter", "", "Bad Name", "", "", true, "", "").is_err());
        assert!(crate::users::set_password("walter", "", "0bad", "x").is_err());
        assert!(crate::users::modify("walter", "", "walter", "shell", "relativo/sh").is_err());
    }

    #[test]
    fn elevate_valida_input_sem_correr_sudo() {
        // password vazia → erro imediato (antes de PAM/sudo)
        assert!(crate::elevate::mkdir("walter", "", "/tmp", "x").is_err());
        // nome com '/' → rejeitado na validação
        assert!(crate::elevate::mkdir("walter", "pw", "/tmp", "a/b").is_err());
        // modo octal inválido → rejeitado antes de tudo
        assert!(crate::elevate::chmod("walter", "pw", "/tmp/x", "9z9").is_err());
        // dono com caracteres inválidos → rejeitado
        assert!(crate::elevate::chown("walter", "pw", "/tmp/x", "mau dono!", false).is_err());
    }

    #[test]
    fn terminal_pty_roundtrip() {
        std::env::set_var("SHELL", "/bin/sh");
        let home = tmp("home6");
        let st = mkstate(tmp("scan6"), home.clone());
        let id = crate::term::new_term(&st, 24, 80).expect("abrir pty");
        crate::term::input(&st, &id, b"echo DOPPEL_OK_123\nexit\n").expect("input");
        let mut reader = crate::term::take_reader(&st, &id).expect("reader");
        let mut out = String::new();
        let mut buf = [0u8; 4096];
        for _ in 0..500 {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if out.contains("DOPPEL_OK_123") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        crate::term::close(&st, &id);
        assert!(out.contains("DOPPEL_OK_123"), "o PTY deve devolver a saída do shell; obtido: {out:?}");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn cache_and_procs() {
        let home = tmp("home2");
        let root = tmp("scan2");
        fs::write(root.join("x1"), b"mesma coisa aqui").unwrap();
        fs::write(root.join("x2"), b"mesma coisa aqui").unwrap();

        let st = mkstate(root.clone(), home.clone());
        crate::scan::run_with(&st, false);
        assert_eq!(st.cache_count(), 1, "resultado deve ficar em cache");
        assert!(st.cache_age(&root.to_string_lossy()).is_some());
        assert_eq!(st.result.lock().unwrap().groups.len(), 1);
        assert!(st.hash_cache.lock().unwrap().len() >= 2, "hashes devem ficar em cache");

        // segunda análise sem forçar → serve da cache, mesmos grupos
        crate::scan::run_with(&st, false);
        assert_eq!(st.result.lock().unwrap().groups.len(), 1);

        // limpar cache esvazia ambas
        st.clear_caches();
        assert_eq!(st.cache_count(), 0);
        assert_eq!(st.hash_cache.lock().unwrap().len(), 0);

        // top processos
        let mut sys = st.proc_sys.lock().unwrap();
        let snap = crate::procs::collect(&mut sys);
        assert!(snap.ncpu >= 1);
        assert!(!snap.top_mem.is_empty(), "deve listar processos");
        assert!(snap.top_cpu.len() <= 10 && snap.top_mem.len() <= 10);

        // monitorização do host
        sys.refresh_cpu_all();
        sys.refresh_memory();
        let mon = crate::sysmon::snapshot(&sys);
        assert!(!mon.cores.is_empty(), "deve haver cores");
        assert!(mon.cores_total >= mon.cores_online && mon.cores_online >= 1);
        assert!(mon.mem_total > 0);
        assert!(!mon.parts.is_empty(), "deve listar partições");
        drop(sys);

        let _ = fs::remove_dir_all(&home);
        let _ = fs::remove_dir_all(&root);
    }
}
