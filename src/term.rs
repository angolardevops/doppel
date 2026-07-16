//! Terminal embebido: um PTY real por sessão, a correr o shell do utilizador.
//! ⚠️ É acesso shell completo (como o próprio utilizador) — protegido pelo login
//! PAM e por escutar só em 127.0.0.1.

use std::collections::HashMap;
use std::io::{Read, Write};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::auth;
use crate::state::AppState;

pub struct TermSession {
    master: Box<dyn portable_pty::MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    /// leitor do master — retirado (uma vez) pelo endpoint de streaming
    reader: Option<Box<dyn Read + Send>>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

/// Cria uma sessão de terminal e devolve o seu id.
pub fn new_term(state: &AppState, rows: u16, cols: u16) -> Result<String, String> {
    let sys = native_pty_system();
    let pair = sys
        .openpty(PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
    let mut cmd = CommandBuilder::new(&shell);
    cmd.env("TERM", "xterm-256color");
    cmd.cwd(&state.run_home);

    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);

    let reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.take_writer().map_err(|e| e.to_string())?;

    let id = auth::new_token()[..16].to_string();
    state.terms.lock().unwrap().insert(
        id.clone(),
        TermSession { master: pair.master, writer, reader: Some(reader), child },
    );
    Ok(id)
}

/// Retira o leitor da sessão (só a 1ª chamada devolve — para o streaming).
pub fn take_reader(state: &AppState, id: &str) -> Option<Box<dyn Read + Send>> {
    state.terms.lock().unwrap().get_mut(id).and_then(|s| s.reader.take())
}

pub fn input(state: &AppState, id: &str, data: &[u8]) -> Result<(), String> {
    let mut t = state.terms.lock().unwrap();
    let s = t.get_mut(id).ok_or("sessão inexistente")?;
    s.writer.write_all(data).map_err(|e| e.to_string())?;
    let _ = s.writer.flush();
    Ok(())
}

pub fn resize(state: &AppState, id: &str, rows: u16, cols: u16) -> Result<(), String> {
    let t = state.terms.lock().unwrap();
    let s = t.get(id).ok_or("sessão inexistente")?;
    s.master
        .resize(PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())
}

/// Fecha e mata a sessão.
pub fn close(state: &AppState, id: &str) {
    if let Some(mut s) = state.terms.lock().unwrap().remove(id) {
        let _ = s.child.kill();
    }
}

/// Remove sessões cujo shell já terminou (limpeza preguiçosa).
pub fn reap(terms: &mut HashMap<String, TermSession>) {
    terms.retain(|_, s| matches!(s.child.try_wait(), Ok(None)));
}
