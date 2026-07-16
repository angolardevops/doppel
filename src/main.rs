//! Doppel — encontra e remove ficheiros duplicados com verificação byte-a-byte,
//! login PAM, quarentena reversível e UI web em tempo real.
//!
//! Uso:  doppel [PASTA]
//! Sobe um servidor web numa porta alta atribuída pelo SO e abre o browser.
//! Por omissão analisa o home do utilizador autenticado.

mod auth;
mod browse;
mod remove;
mod scan;
mod server;
mod state;
mod stats;

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use state::AppState;
use tiny_http::Server;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("Doppel — detector/removedor de ficheiros duplicados\n");
        eprintln!("  uso: doppel [PASTA]");
        eprintln!("  (sem PASTA usa o home do utilizador que faz login)\n");
        eprintln!("Abre uma UI web numa porta alta aleatória, protegida por login do");
        eprintln!("sistema (PAM). Duplicados podem ir para quarentena (reversível) ou ser");
        eprintln!("apagados; a remoção é sempre verificada byte-a-byte (certeza 100%).\n");
        eprintln!("Env: DOPPEL_PAM_SERVICE (serviço PAM, por omissão 'login').");
        return;
    }

    let (run_user, run_home) = auth::current_user();

    // Raiz inicial: argumento > home do utilizador.
    let root = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .and_then(|p| std::fs::canonicalize(&p).ok())
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| run_home.clone());

    let q_dir = state::quarantine_dir(&run_home);

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("não foi possível abrir um socket local");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/");

    let server = Server::from_listener(listener, None).expect("falha ao iniciar o servidor HTTP");
    let state = Arc::new(AppState::new(run_user.clone(), run_home, root, q_dir));

    println!("\n  ✦ Doppel");
    println!("  utilizador: {run_user}");
    println!("  raiz:       {}", state.root().display());
    println!("  UI:         {url}");
    println!("  (faz login com a tua password do sistema · Ctrl+C para sair)\n");
    open_browser(&url);

    server::serve(server, state);
}

/// Tenta abrir o browser no ambiente de desktop (best-effort, silencioso).
fn open_browser(url: &str) {
    let candidates = ["xdg-open", "gio", "gnome-open", "kde-open", "open"];
    for cmd in candidates {
        let ok = if cmd == "gio" {
            std::process::Command::new(cmd).arg("open").arg(url).spawn().is_ok()
        } else {
            std::process::Command::new(cmd).arg(url).spawn().is_ok()
        };
        if ok {
            return;
        }
    }
}
