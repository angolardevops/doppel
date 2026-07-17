//! Terminal por WebSocket (mesma técnica do delonix-paas): uma ligação
//! full-duplex faz a ponte entre o browser e o PTY.
//!
//! * frame **binário** = bytes crus (teclado → PTY, e PTY → ecrã);
//! * frame de **texto** = controlo JSON `{"cols":N,"rows":M}` (redimensionar).
//!
//! Corre num listener próprio (127.0.0.1, porta alta) porque o `tiny_http`
//! entrega o socket como `Box<dyn ReadWrite>` — sem `try_clone` nem acesso ao
//! fd — e sem dois handles independentes não há full-duplex. Aqui somos donos
//! do `TcpStream`, logo `try_clone()` dá-nos leitura e escrita em paralelo.
//!
//! Segurança: exige o mesmo cookie de sessão PAM (os cookies não são por-porta,
//! por isso o browser envia-o na mesma) e só escuta em 127.0.0.1.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::state::AppState;
use crate::ws;

/// Abre o listener do terminal e devolve a porta escolhida pelo SO.
pub fn listen(state: Arc<AppState>) -> std::io::Result<u16> {
    let l = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let port = l.local_addr()?.port();
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let st = Arc::clone(&state);
            std::thread::spawn(move || {
                let _ = handle(conn, st);
            });
        }
    });
    Ok(port)
}

/// Lê os cabeçalhos HTTP do upgrade, valida a sessão e faz o handshake.
fn handle(stream: TcpStream, state: Arc<AppState>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?; // pedido (GET /… HTTP/1.1)

    let (mut key, mut cookie) = (String::new(), String::new());
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        // O nome do cabeçalho é insensível a maiúsculas, mas o VALOR não pode ser
        // alterado: o Sec-WebSocket-Key é base64 (e o cookie é um token) — por
        // isso comparamos em minúsculas mas extraímos sempre da linha original.
        let low = h.to_ascii_lowercase();
        const K: &str = "sec-websocket-key:";
        const C: &str = "cookie:";
        if low.starts_with(K) {
            key = h[K.len()..].trim().to_string();
        } else if low.starts_with(C) {
            cookie = h[C.len()..].trim().to_string();
        }
    }

    let mut out = stream.try_clone()?;
    // sessão: mesmo cookie do resto da app (cookies ignoram a porta)
    let token = cookie
        .split(';')
        .filter_map(|p| p.trim().strip_prefix("doppel_sess=").map(str::to_string))
        .next()
        .unwrap_or_default();
    if key.is_empty() || !state.sessions.valid(&token) {
        let _ = out.write_all(b"HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
        return Ok(());
    }

    let accept = ws::accept_key(&key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    out.write_all(resp.as_bytes())?;
    out.flush()?;

    bridge(reader, out, &state)
}

/// Ponte bidirecional entre o WebSocket e o PTY.
fn bridge(mut reader: BufReader<TcpStream>, out: TcpStream, state: &AppState) -> std::io::Result<()> {
    let sys = native_pty_system();
    let pair = sys
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .map_err(std::io::Error::other)?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
    let mut cmd = CommandBuilder::new(&shell);
    cmd.arg("-i");
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");
    cmd.cwd(&state.run_home);
    let mut child = pair.slave.spawn_command(cmd).map_err(std::io::Error::other)?;
    drop(pair.slave);

    let mut pty_reader = pair.master.try_clone_reader().map_err(std::io::Error::other)?;
    let mut pty_writer = pair.master.take_writer().map_err(std::io::Error::other)?;

    // PTY → WebSocket (frames binários)
    let mut ws_out = out.try_clone()?;
    let pump = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws::write_frame(&mut ws_out, ws::OP_BINARY, &buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        // shell terminou → fecha o WebSocket
        let _ = ws::write_frame(&mut ws_out, ws::OP_CLOSE, &[]);
    });

    // WebSocket → PTY (binário = teclas; texto = controlo/resize)
    let mut ws_ping = out.try_clone()?;
    loop {
        match ws::read_frame(&mut reader) {
            Ok(Some((ws::OP_BINARY, data))) | Ok(Some((ws::OP_TEXT, data))) if !data.is_empty() => {
                // controlo de redimensionamento vem como JSON de texto
                if data.starts_with(b"{") {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&data) {
                        let rows = v.get("rows").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
                        let cols = v.get("cols").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
                        if rows > 0 && cols > 0 {
                            let _ = pair.master.resize(PtySize {
                                rows,
                                cols,
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                            continue;
                        }
                    }
                }
                if pty_writer.write_all(&data).is_err() {
                    break;
                }
                let _ = pty_writer.flush();
            }
            Ok(Some((ws::OP_PING, data))) => {
                let _ = ws::write_frame(&mut ws_ping, ws::OP_PONG, &data);
            }
            Ok(Some((ws::OP_CLOSE, _))) | Ok(None) | Err(_) => break,
            Ok(Some(_)) => {}
        }
    }

    let _ = child.kill();
    let _ = out.shutdown(std::net::Shutdown::Both);
    let _ = pump.join();
    Ok(())
}
