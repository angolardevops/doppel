//! Doppel — encontra e remove ficheiros duplicados com verificação byte-a-byte,
//! login PAM, quarentena reversível e UI web em tempo real.
//!
//! Uso:  doppel [PASTA]
//! Sobe um servidor web numa porta alta atribuída pelo SO e abre o browser.
//! Por omissão analisa o home do utilizador autenticado.

mod auth;
mod browse;
mod elevate;
mod fsops;
mod procs;
mod remove;
mod scan;
mod server;
mod services;
mod state;
mod stats;
mod sysmon;
mod term;
mod users;

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use state::AppState;
use tiny_http::Server;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("Doppel — detector/removedor de ficheiros duplicados\n");
        eprintln!("  uso: doppel [OPÇÕES] [PASTA]");
        eprintln!("  (sem PASTA usa o home do utilizador que faz login)\n");
        eprintln!("Opções:");
        eprintln!("  --port <N>     porta fixa (por omissão: alta e aleatória)");
        eprintln!("  --no-browser   não abrir o browser (útil para serviço/systemd)");
        eprintln!("  -h, --help     esta ajuda\n");
        eprintln!("Abre uma UI web protegida por login do sistema (PAM). Duplicados podem");
        eprintln!("ir para quarentena (reversível) ou ser apagados; a remoção é sempre");
        eprintln!("verificada byte-a-byte (certeza 100%).\n");
        eprintln!("Env: DOPPEL_PAM_SERVICE (serviço PAM, por omissão 'login').");
        return;
    }

    // Parsing simples de argumentos: --port <N>, --no-browser e PASTA posicional.
    let mut cli_port: Option<u16> = None;
    let mut no_browser = false;
    let mut folder: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--no-browser" => no_browser = true,
            "--port" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u16>().ok()) {
                    Some(p) => cli_port = Some(p),
                    None => {
                        eprintln!("erro: --port precisa de um número de porta (1-65535)");
                        std::process::exit(1);
                    }
                }
            }
            s if s.starts_with("--port=") => {
                match s["--port=".len()..].parse::<u16>() {
                    Ok(p) => cli_port = Some(p),
                    Err(_) => {
                        eprintln!("erro: --port precisa de um número de porta (1-65535)");
                        std::process::exit(1);
                    }
                }
            }
            s if !s.starts_with('-') && folder.is_none() => folder = Some(s.to_string()),
            _ => {}
        }
        i += 1;
    }
    // Env como alternativa às flags (útil na unit systemd).
    if cli_port.is_none() {
        if let Some(p) = std::env::var("DOPPEL_PORT").ok().and_then(|v| v.parse().ok()) {
            cli_port = Some(p);
        }
    }
    if std::env::var("DOPPEL_NO_BROWSER").is_ok() {
        no_browser = true;
    }

    // Limita o pool do rayon: menos threads = menos arenas de malloc e menor
    // pico de memória ao hashear árvores enormes (o ganho de velocidade acima
    // de ~8 threads em I/O de disco é marginal).
    let threads = std::thread::available_parallelism().map(|n| n.get().min(8)).unwrap_or(4);
    let _ = rayon::ThreadPoolBuilder::new().num_threads(threads).build_global();

    let (run_user, run_home) = auth::current_user();

    // Raiz inicial: argumento > home do utilizador.
    let root = folder
        .map(PathBuf::from)
        .and_then(|p| std::fs::canonicalize(&p).ok())
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| run_home.clone());

    let q_dir = state::quarantine_dir(&run_home);

    let bind_port = cli_port.unwrap_or(0); // 0 = porta alta aleatória do SO
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, bind_port)))
        .unwrap_or_else(|e| {
            eprintln!("erro: não foi possível abrir 127.0.0.1:{bind_port}: {e}");
            std::process::exit(1);
        });
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/");

    let server = Server::from_listener(listener, None).expect("falha ao iniciar o servidor HTTP");
    let state = Arc::new(AppState::new(run_user.clone(), run_home, root, q_dir));

    // Amostrador de KPIs em background (para os gráficos históricos).
    {
        let st = Arc::clone(&state);
        std::thread::spawn(move || sysmon::sample_loop(&st));
    }

    println!("\n  ✦ Doppel");
    println!("  utilizador: {run_user}");
    println!("  raiz:       {}", state.root().display());
    println!("  UI:         {url}");
    println!("  (faz login com a tua password do sistema · Ctrl+C para sair)\n");
    if !no_browser {
        open_browser(&url);
    }

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
