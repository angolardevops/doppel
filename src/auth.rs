//! Autenticação PAM (o utilizador prova a sua própria password do sistema),
//! sessões por cookie e resolução de utilizador/home a partir de /etc/passwd.

use std::collections::HashSet;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::sync::Mutex;

// ---- FFI mínimo para libpam ----------------------------------------------

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}
#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}
#[repr(C)]
struct PamConv {
    conv: ConvFn,
    appdata_ptr: *mut c_void,
}
type ConvFn = extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int;

extern "C" {
    fn pam_start(service: *const c_char, user: *const c_char, conv: *const PamConv, handle: *mut *mut c_void) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
}

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;

/// Conversa PAM: responde a qualquer prompt de password com a password fornecida.
extern "C" fn conversation(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    unsafe {
        if num_msg <= 0 || msg.is_null() {
            return 19; // PAM_CONV_ERR
        }
        let n = num_msg as usize;
        let arr = libc::calloc(n, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if arr.is_null() {
            return 5; // PAM_BUF_ERR
        }
        let password = appdata as *const c_char; // C string (não nula)
        for i in 0..n {
            let m = *msg.add(i);
            let r = arr.add(i);
            (*r).resp_retcode = 0;
            let style = (*m).msg_style;
            if style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON {
                (*r).resp = libc::strdup(password);
            } else {
                (*r).resp = std::ptr::null_mut();
            }
        }
        *resp = arr;
        PAM_SUCCESS
    }
}

/// Nome do serviço PAM a usar (`login` por omissão, alterável por env).
fn service_name() -> String {
    std::env::var("DOPPEL_PAM_SERVICE").unwrap_or_else(|_| "login".into())
}

/// Autentica `user` com `password` via PAM. `true` = credenciais válidas.
pub fn authenticate(user: &str, password: &str) -> bool {
    authenticate_with(&service_name(), user, password)
}

/// Como `authenticate`, mas escolhendo o serviço PAM (usado no diagnóstico).
pub fn authenticate_with(service: &str, user: &str, password: &str) -> bool {
    let service = match CString::new(service) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let c_user = match CString::new(user) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let c_pass = match CString::new(password) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let conv = PamConv {
        conv: conversation,
        appdata_ptr: c_pass.as_ptr() as *mut c_void,
    };
    let mut handle: *mut c_void = std::ptr::null_mut();

    unsafe {
        if pam_start(service.as_ptr(), c_user.as_ptr(), &conv, &mut handle) != PAM_SUCCESS {
            return false;
        }
        let auth = pam_authenticate(handle, 0);
        let acct = if auth == PAM_SUCCESS { pam_acct_mgmt(handle, 0) } else { auth };
        pam_end(handle, auth);
        // mantém a password viva até aqui
        let _keep = &c_pass;
        auth == PAM_SUCCESS && acct == PAM_SUCCESS
    }
}

// ---- Sessões --------------------------------------------------------------

/// Token de sessão aleatório (32 bytes de /dev/urandom em hex).
pub fn new_token() -> String {
    use std::io::Read;
    let mut b = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub struct Sessions {
    inner: Mutex<HashSet<String>>,
}
impl Sessions {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashSet::new()) }
    }
    pub fn create(&self) -> String {
        let t = new_token();
        self.inner.lock().unwrap().insert(t.clone());
        t
    }
    pub fn valid(&self, token: &str) -> bool {
        !token.is_empty() && self.inner.lock().unwrap().contains(token)
    }
    pub fn revoke(&self, token: &str) {
        self.inner.lock().unwrap().remove(token);
    }
}

// ---- Utilizador / home ----------------------------------------------------

/// Utilizador efetivo que corre o processo e o seu home (via /etc/passwd).
pub fn current_user() -> (String, PathBuf) {
    let uid = unsafe { libc::geteuid() };
    if let Some((name, home)) = lookup_by_uid(uid) {
        return (name, home);
    }
    // fallback: variáveis de ambiente
    let name = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "user".into());
    let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/"));
    (name, home)
}

/// Home de um utilizador arbitrário pelo nome (para o default após login).
pub fn home_of(user: &str) -> Option<PathBuf> {
    for line in read_passwd()?.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 6 && f[0] == user {
            return Some(PathBuf::from(f[5]));
        }
    }
    None
}

fn lookup_by_uid(uid: u32) -> Option<(String, PathBuf)> {
    for line in read_passwd()?.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 6 {
            if let Ok(u) = f[2].parse::<u32>() {
                if u == uid {
                    return Some((f[0].to_string(), PathBuf::from(f[5])));
                }
            }
        }
    }
    None
}

fn read_passwd() -> Option<String> {
    std::fs::read_to_string("/etc/passwd").ok()
}
