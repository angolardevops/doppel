//! Servidor HTTP: serve a UI embebida e a API JSON, com gate de sessão (PAM).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::remove::Mode;
use crate::state::AppState;
use crate::{auth, browse, fsops, procs, remove, scan, stats, sysmon};

const INDEX_HTML: &str = include_str!("../assets/index.html");
const COOKIE: &str = "doppel_sess";

pub fn serve(server: Server, state: Arc<AppState>) {
    let server = Arc::new(server);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let server = Arc::clone(&server);
        let state = Arc::clone(&state);
        handles.push(thread::spawn(move || {
            while let Ok(req) = server.recv() {
                handle(req, &state);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn handle(mut req: Request, state: &Arc<AppState>) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let query = url.splitn(2, '?').nth(1).unwrap_or("").to_string();

    // Rotas públicas (não exigem sessão).
    match (&method, path.as_str()) {
        (Method::Get, "/") => {
            let mut resp = Response::from_string(INDEX_HTML);
            resp.add_header(html_header());
            let _ = req.respond(resp);
            return;
        }
        (Method::Get, "/api/session") => {
            let authed = session_token(&req).map(|t| state.sessions.valid(&t)).unwrap_or(false);
            respond_json(req, 200, &json!({
                "authed": authed,
                "run_user": state.run_user,
                "run_home": state.run_home.to_string_lossy(),
            }));
            return;
        }
        (Method::Post, "/api/login") => {
            let body = read_body(&mut req);
            let user = body.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if user.is_empty() || password.is_empty() {
                respond_json(req, 400, &json!({"error": "utilizador e password obrigatórios"}));
                return;
            }
            if auth::authenticate(&user, &password) {
                let token = state.sessions.create();
                // define a raiz por omissão = home do utilizador autenticado
                if let Some(home) = auth::home_of(&user) {
                    if home.is_dir() {
                        *state.root.write().unwrap() = home;
                    }
                }
                let mut resp = Response::from_string(json!({
                    "ok": true, "user": user,
                    "root": state.root().to_string_lossy(),
                }).to_string()).with_status_code(200);
                resp.add_header(json_header());
                resp.add_header(set_cookie(&token));
                let _ = req.respond(resp);
            } else {
                respond_json(req, 401, &json!({"error": "autenticação falhou"}));
            }
            return;
        }
        (Method::Post, "/api/logout") => {
            if let Some(t) = session_token(&req) {
                state.sessions.revoke(&t);
            }
            respond_json(req, 200, &json!({"ok": true}));
            return;
        }
        _ => {}
    }

    // A partir daqui exige sessão válida.
    let authed = session_token(&req).map(|t| state.sessions.valid(&t)).unwrap_or(false);
    if !authed {
        respond_json(req, 401, &json!({"error": "não autenticado"}));
        return;
    }

    match (&method, path.as_str()) {
        (Method::Get, "/api/status") => {
            let body = status_json(state);
            respond_json(req, 200, &body);
        }
        (Method::Get, "/api/groups") => {
            let r = state.result.lock().unwrap();
            respond_json(req, 200, &json!({
                "version": state.version.load(Ordering::Relaxed),
                "groups": &r.groups,
            }));
        }
        (Method::Get, "/api/quarantine") => {
            let q = state.quarantine.lock().unwrap();
            respond_json(req, 200, &json!({
                "version": state.version.load(Ordering::Relaxed),
                "dir": q.dir.to_string_lossy(),
                "total_bytes": q.total_bytes(),
                "entries": &q.entries,
            }));
        }
        (Method::Get, "/api/browse") => {
            let p = query_param(&query, "path")
                .unwrap_or_else(|| state.root().to_string_lossy().into_owned());
            respond_json(req, 200, &json!(browse::list(std::path::Path::new(&p))));
        }
        (Method::Post, "/api/scan") => {
            let body = read_body(&mut req);
            if let Some(p) = body.get("path").and_then(|v| v.as_str()) {
                match browse::valid_dir(p) {
                    Some(dir) => *state.root.write().unwrap() = dir,
                    None => {
                        respond_json(req, 400, &json!({"error": "pasta inválida"}));
                        return;
                    }
                }
            }
            let force = body.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            spawn_op(state, req, 202, move |st| {
                scan::run_with(&st, force);
            });
        }
        (Method::Get, "/api/processes") => {
            let mut sys = state.proc_sys.lock().unwrap();
            respond_json(req, 200, &json!(procs::collect(&mut sys)));
        }
        (Method::Get, "/api/monitor") => {
            let mut sys = state.proc_sys.lock().unwrap();
            sys.refresh_cpu_all();
            sys.refresh_memory();
            let procs = procs::collect(&mut sys); // faz refresh_processes
            let mon = sysmon::snapshot(&sys);
            respond_json(req, 200, &json!({ "mon": mon, "procs": procs }));
        }
        (Method::Get, "/api/history") => {
            let h = state.history.lock().unwrap();
            let series: Vec<_> = h.iter().collect();
            respond_json(req, 200, &json!({ "samples": series }));
        }
        // ---- gestor de ficheiros (opera como o utilizador) ----
        (Method::Get, "/api/fs/list") => {
            let p = query_param(&query, "path")
                .unwrap_or_else(|| state.run_home.to_string_lossy().into_owned());
            respond_json(req, 200, &json!(fsops::list(std::path::Path::new(&p))));
        }
        (Method::Post, "/api/fs/mkdir") => {
            let b = read_body(&mut req);
            fs_result(req, fsops::mkdir(str_of(&b, "path"), str_of(&b, "name")));
        }
        (Method::Post, "/api/fs/mkfile") => {
            let b = read_body(&mut req);
            fs_result(req, fsops::mkfile(str_of(&b, "path"), str_of(&b, "name")));
        }
        (Method::Post, "/api/fs/rename") => {
            let b = read_body(&mut req);
            fs_result(req, fsops::rename(str_of(&b, "path"), str_of(&b, "name")));
        }
        (Method::Post, "/api/fs/chmod") => {
            let b = read_body(&mut req);
            fs_result(req, fsops::chmod(str_of(&b, "path"), str_of(&b, "mode")));
        }
        (Method::Post, "/api/fs/delete") => {
            let b = read_body(&mut req);
            let rec = b.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
            fs_result(req, fsops::delete(str_of(&b, "path"), rec));
        }
        (Method::Post, "/api/cache/clear") => {
            state.clear_caches();
            respond_json(req, 200, &json!({"ok": true}));
        }
        (Method::Post, "/api/clean") => {
            let paths = string_list(&read_body(&mut req), "paths");
            if paths.is_empty() {
                respond_json(req, 400, &json!({"error": "nada selecionado"}));
                return;
            }
            run_op(state, req, move |st| json!(remove::operate(&st, paths, Mode::Delete)));
        }
        (Method::Post, "/api/quarantine/add") => {
            let paths = string_list(&read_body(&mut req), "paths");
            if paths.is_empty() {
                respond_json(req, 400, &json!({"error": "nada selecionado"}));
                return;
            }
            run_op(state, req, move |st| json!(remove::operate(&st, paths, Mode::Quarantine)));
        }
        (Method::Post, "/api/quarantine/purge") => {
            let ids = u64_list(&read_body(&mut req), "ids");
            if ids.is_empty() {
                respond_json(req, 400, &json!({"error": "nada selecionado"}));
                return;
            }
            run_op(state, req, move |st| json!(remove::purge(&st, ids)));
        }
        (Method::Post, "/api/quarantine/restore") => {
            let ids = u64_list(&read_body(&mut req), "ids");
            if ids.is_empty() {
                respond_json(req, 400, &json!({"error": "nada selecionado"}));
                return;
            }
            run_op(state, req, move |st| json!(remove::restore(&st, ids)));
        }
        _ => respond_json(req, 404, &json!({"error": "não encontrado"})),
    }
}

/// Arranca uma operação em background (só reserva `busy`), responde já.
fn spawn_op<F>(state: &Arc<AppState>, req: Request, code: u16, f: F)
where
    F: FnOnce(Arc<AppState>) + Send + 'static,
{
    if state.busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        respond_json(req, 409, &json!({"error": "ocupado — operação em curso"}));
        return;
    }
    let st = Arc::clone(state);
    thread::spawn(move || {
        f(Arc::clone(&st));
        st.busy.store(false, Ordering::SeqCst);
    });
    respond_json(req, code, &json!({"ok": true}));
}

/// Corre uma operação em background e responde com o relatório quando termina;
/// o progresso vai subindo em /api/status entretanto.
fn run_op<F>(state: &Arc<AppState>, req: Request, f: F)
where
    F: FnOnce(Arc<AppState>) -> Value + Send + 'static,
{
    if state.busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        respond_json(req, 409, &json!({"error": "ocupado — operação em curso"}));
        return;
    }
    let st = Arc::clone(state);
    let handle = thread::spawn(move || {
        let out = f(Arc::clone(&st));
        st.busy.store(false, Ordering::SeqCst);
        out
    });
    match handle.join() {
        Ok(v) => respond_json(req, 200, &v),
        Err(_) => respond_json(req, 500, &json!({"error": "falha na operação"})),
    }
}

fn status_json(state: &Arc<AppState>) -> Value {
    let (total_files, root_size, reclaimable, group_count) = {
        let r = state.result.lock().unwrap();
        (r.total_files, r.root_size, r.reclaimable, r.groups.len())
    };
    let q_total = {
        let q = state.quarantine.lock().unwrap();
        (q.total_bytes(), q.entries.len())
    };
    let sys = stats::collect(&state.root());
    json!({
        "phase": state.phase(),
        "busy": state.busy.load(Ordering::Relaxed),
        "op_done": state.op_done.load(Ordering::Relaxed),
        "op_total": state.op_total.load(Ordering::Relaxed),
        "total_files": total_files,
        "root_size": root_size,
        "reclaimable": reclaimable,
        "group_count": group_count,
        "freed": state.freed.load(Ordering::Relaxed),
        "removed": state.removed.load(Ordering::Relaxed),
        "quarantine_bytes": q_total.0,
        "quarantine_count": q_total.1,
        "version": state.version.load(Ordering::Relaxed),
        "root": state.root().to_string_lossy(),
        "mem": sys.mem,
        "disk": sys.disk,
        "cache_count": state.cache_count(),
        "cache_age": state.cache_age(&state.root().to_string_lossy()),
    })
}

// ---- helpers HTTP ---------------------------------------------------------

fn read_body(req: &mut Request) -> Value {
    let mut buf = String::new();
    let _ = std::io::Read::read_to_string(req.as_reader(), &mut buf);
    serde_json::from_str(&buf).unwrap_or(Value::Null)
}

fn str_of<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// Responde a uma operação de ficheiros: 200 {ok} ou 400 {error}.
fn fs_result(req: Request, r: Result<(), String>) {
    match r {
        Ok(()) => respond_json(req, 200, &json!({"ok": true})),
        Err(e) => respond_json(req, 400, &json!({"error": e})),
    }
}

fn string_list(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn u64_list(body: &Value, key: &str) -> Vec<u64> {
    body.get(key)
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
        .unwrap_or_default()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some(key) {
            return it.next().map(url_decode);
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = hex(bytes[i + 1]);
                let l = hex(bytes[i + 2]);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push(h * 16 + l);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn session_token(req: &Request) -> Option<String> {
    for h in req.headers() {
        if h.field.equiv("Cookie") {
            let val = h.value.as_str();
            for pair in val.split(';') {
                let pair = pair.trim();
                if let Some(rest) = pair.strip_prefix(&format!("{COOKIE}=")) {
                    return Some(rest.to_string());
                }
            }
        }
    }
    None
}

fn set_cookie(token: &str) -> Header {
    Header::from_bytes(
        &b"Set-Cookie"[..],
        format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict").as_bytes(),
    )
    .unwrap()
}

fn respond_json(req: Request, code: u16, body: &Value) {
    let mut resp = Response::from_string(body.to_string()).with_status_code(code);
    resp.add_header(json_header());
    let _ = req.respond(resp);
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..]).unwrap()
}
fn html_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap()
}
