//! Servidor HTTP: serve a UI embebida e a API JSON, com gate de sessão (PAM).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::remove::Mode;
use crate::state::AppState;
use crate::{
    apt, auth, browse, cron, disks, elevate, fsops, logs, netinfo, procs, remove, scan, services, stats, sysmon, term,
    users,
};

const INDEX_HTML: &str = include_str!("../assets/index.html");
const XTERM_JS: &str = include_str!("../assets/vendor/xterm.js");
const XTERM_CSS: &str = include_str!("../assets/vendor/xterm.css");
const ADDON_FIT: &str = include_str!("../assets/vendor/addon-fit.js");
const ADDON_WEBGL: &str = include_str!("../assets/vendor/addon-webgl.js");
const COOKIE: &str = "doppel_sess";

pub fn serve(server: Server, state: Arc<AppState>) {
    let server = Arc::new(server);
    let mut handles = Vec::new();
    // 8 workers: um streaming de terminal ocupa um worker durante a sessão.
    for _ in 0..8 {
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
        (Method::Get, "/vendor/xterm.js") => return serve_asset(req, XTERM_JS, "application/javascript"),
        (Method::Get, "/vendor/xterm.css") => return serve_asset(req, XTERM_CSS, "text/css"),
        (Method::Get, "/vendor/addon-fit.js") => return serve_asset(req, ADDON_FIT, "application/javascript"),
        (Method::Get, "/vendor/addon-webgl.js") => return serve_asset(req, ADDON_WEBGL, "application/javascript"),
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
            let (u, pw) = (state.run_user.as_str(), str_of(&b, "password"));
            fs_result(req, if elevated(&b) {
                elevate::mkdir(u, pw, str_of(&b, "path"), str_of(&b, "name"))
            } else {
                fsops::mkdir(str_of(&b, "path"), str_of(&b, "name"))
            });
        }
        (Method::Post, "/api/fs/mkfile") => {
            let b = read_body(&mut req);
            let (u, pw) = (state.run_user.as_str(), str_of(&b, "password"));
            fs_result(req, if elevated(&b) {
                elevate::mkfile(u, pw, str_of(&b, "path"), str_of(&b, "name"))
            } else {
                fsops::mkfile(str_of(&b, "path"), str_of(&b, "name"))
            });
        }
        (Method::Post, "/api/fs/rename") => {
            let b = read_body(&mut req);
            let (u, pw) = (state.run_user.as_str(), str_of(&b, "password"));
            fs_result(req, if elevated(&b) {
                elevate::rename(u, pw, str_of(&b, "path"), str_of(&b, "name"))
            } else {
                fsops::rename(str_of(&b, "path"), str_of(&b, "name"))
            });
        }
        (Method::Post, "/api/fs/chmod") => {
            let b = read_body(&mut req);
            let (u, pw) = (state.run_user.as_str(), str_of(&b, "password"));
            fs_result(req, if elevated(&b) {
                elevate::chmod(u, pw, str_of(&b, "path"), str_of(&b, "mode"))
            } else {
                fsops::chmod(str_of(&b, "path"), str_of(&b, "mode"))
            });
        }
        (Method::Post, "/api/fs/chown") => {
            // chown exige sempre root.
            let b = read_body(&mut req);
            let rec = b.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
            fs_result(req, elevate::chown(state.run_user.as_str(), str_of(&b, "password"), str_of(&b, "path"), str_of(&b, "owner"), rec));
        }
        (Method::Post, "/api/fs/delete") => {
            let b = read_body(&mut req);
            let rec = b.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
            let (u, pw) = (state.run_user.as_str(), str_of(&b, "password"));
            fs_result(req, if elevated(&b) {
                elevate::delete(u, pw, str_of(&b, "path"), rec)
            } else {
                fsops::delete(str_of(&b, "path"), rec)
            });
        }
        // ---- terminal embebido (PTY) ----
        (Method::Post, "/api/term/new") => {
            let b = read_body(&mut req);
            let rows = b.get("rows").and_then(|v| v.as_u64()).unwrap_or(24) as u16;
            let cols = b.get("cols").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
            term::reap(&mut state.terms.lock().unwrap());
            match term::new_term(state, rows, cols) {
                Ok(id) => respond_json(req, 200, &json!({"id": id})),
                Err(e) => respond_json(req, 500, &json!({"error": e})),
            }
        }
        (Method::Get, "/api/term/stream") => {
            let id = query_param(&query, "id").unwrap_or_default();
            match term::take_reader(state, &id) {
                Some(reader) => {
                    let hdr = Header::from_bytes(&b"Content-Type"[..], &b"application/octet-stream"[..]).unwrap();
                    let resp = Response::new(tiny_http::StatusCode(200), vec![hdr], reader, None, None);
                    let _ = req.respond(resp);
                }
                None => respond_json(req, 409, &json!({"error": "stream indisponível"})),
            }
        }
        (Method::Post, "/api/term/input") => {
            let id = query_param(&query, "id").unwrap_or_default();
            let b = read_body(&mut req);
            fs_result(req, term::input(state, &id, str_of(&b, "data").as_bytes()));
        }
        (Method::Post, "/api/term/resize") => {
            let id = query_param(&query, "id").unwrap_or_default();
            let b = read_body(&mut req);
            let rows = b.get("rows").and_then(|v| v.as_u64()).unwrap_or(24) as u16;
            let cols = b.get("cols").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
            fs_result(req, term::resize(state, &id, rows, cols));
        }
        (Method::Post, "/api/term/close") => {
            let id = query_param(&query, "id").unwrap_or_default();
            term::close(state, &id);
            respond_json(req, 200, &json!({"ok": true}));
        }
        // ---- gestão de utilizadores do sistema (mutações via sudo) ----
        (Method::Get, "/api/users") => {
            respond_json(req, 200, &json!(users::list()));
        }
        (Method::Post, "/api/users/create") => {
            let b = read_body(&mut req);
            let (u, pw) = (state.run_user.as_str(), str_of(&b, "password"));
            fs_result(req, users::create(
                u, pw,
                str_of(&b, "username"), str_of(&b, "fullname"), str_of(&b, "shell"),
                b.get("create_home").and_then(|v| v.as_bool()).unwrap_or(true),
                str_of(&b, "groups"), str_of(&b, "newpass"),
            ));
        }
        (Method::Post, "/api/users/passwd") => {
            let b = read_body(&mut req);
            fs_result(req, users::set_password(state.run_user.as_str(), str_of(&b, "password"), str_of(&b, "username"), str_of(&b, "newpass")));
        }
        (Method::Post, "/api/users/modify") => {
            let b = read_body(&mut req);
            fs_result(req, users::modify(state.run_user.as_str(), str_of(&b, "password"), str_of(&b, "username"), str_of(&b, "action"), str_of(&b, "value")));
        }
        (Method::Post, "/api/users/delete") => {
            let b = read_body(&mut req);
            let rh = b.get("remove_home").and_then(|v| v.as_bool()).unwrap_or(false);
            fs_result(req, users::delete(state.run_user.as_str(), str_of(&b, "password"), str_of(&b, "username"), rh));
        }
        // ---- serviços systemd (ações via sudo) ----
        (Method::Get, "/api/services") => {
            respond_json(req, 200, &json!({ "services": services::list() }));
        }
        (Method::Post, "/api/services/action") => {
            let b = read_body(&mut req);
            fs_result(req, services::action(state.run_user.as_str(), str_of(&b, "password"), str_of(&b, "unit"), str_of(&b, "action")));
        }
        (Method::Get, "/api/timers") => {
            respond_json(req, 200, &json!({ "timers": services::timers() }));
        }
        // ---- logs (journalctl) ----
        (Method::Get, "/api/logs") => {
            let unit = query_param(&query, "unit").unwrap_or_default();
            let lines = query_param(&query, "lines").and_then(|s| s.parse().ok()).unwrap_or(200);
            let prio = query_param(&query, "priority").unwrap_or_default();
            let grep = query_param(&query, "grep").unwrap_or_default();
            respond_json(req, 200, &json!(logs::recent(&unit, lines, &prio, &grep)));
        }
        // ---- rede (só leitura) ----
        (Method::Get, "/api/net") => {
            respond_json(req, 200, &json!(netinfo::info()));
        }
        // ---- discos ----
        (Method::Get, "/api/disks") => {
            respond_json(req, 200, &disks::blocks());
        }
        (Method::Get, "/api/disks/du") => {
            let p = query_param(&query, "path").unwrap_or_else(|| state.run_home.to_string_lossy().into_owned());
            match disks::du(&p) {
                Ok(e) => respond_json(req, 200, &json!({ "entries": e })),
                Err(e) => respond_json(req, 400, &json!({ "error": e })),
            }
        }
        (Method::Post, "/api/disks/smart") => {
            let b = read_body(&mut req);
            match disks::smart(state.run_user.as_str(), str_of(&b, "password"), str_of(&b, "dev")) {
                Ok(text) => respond_json(req, 200, &json!({ "output": text })),
                Err(e) => respond_json(req, 400, &json!({ "error": e })),
            }
        }
        // ---- pacotes APT ----
        (Method::Get, "/api/pkg/upgradable") => {
            respond_json(req, 200, &json!({ "packages": apt::upgradable() }));
        }
        (Method::Get, "/api/pkg/search") => {
            let q = query_param(&query, "q").unwrap_or_default();
            respond_json(req, 200, &json!({ "results": apt::search(&q) }));
        }
        (Method::Post, "/api/pkg/action") => {
            let b = read_body(&mut req);
            let (u, pw) = (state.run_user.as_str(), str_of(&b, "password"));
            let name = str_of(&b, "name");
            let r = match str_of(&b, "action") {
                "update" => apt::update(u, pw),
                "upgrade" => apt::upgrade(u, pw),
                "install" => apt::install(u, pw, name),
                "remove" => apt::remove(u, pw, name),
                _ => Err("ação desconhecida".into()),
            };
            match r {
                Ok(text) => respond_json(req, 200, &json!({ "output": text })),
                Err(e) => respond_json(req, 400, &json!({ "error": e })),
            }
        }
        // ---- cron do utilizador ----
        (Method::Get, "/api/cron") => {
            respond_json(req, 200, &json!({ "content": cron::get() }));
        }
        (Method::Post, "/api/cron") => {
            let b = read_body(&mut req);
            fs_result(req, cron::set(str_of(&b, "content")));
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

fn elevated(body: &Value) -> bool {
    body.get("elevated").and_then(|v| v.as_bool()).unwrap_or(false)
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

fn serve_asset(req: Request, body: &str, ctype: &str) {
    let mut resp = Response::from_string(body);
    resp.add_header(Header::from_bytes(&b"Content-Type"[..], ctype.as_bytes()).unwrap());
    resp.add_header(Header::from_bytes(&b"Cache-Control"[..], &b"max-age=86400"[..]).unwrap());
    let _ = req.respond(resp);
}
