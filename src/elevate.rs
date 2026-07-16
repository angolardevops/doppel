//! Operações privilegiadas via `sudo -S`: a password é reintroduzida no wizard,
//! verificada por PAM (como no login) e passada ao sudo por stdin. Comandos e
//! argumentos são construídos por nós (sem shell → sem injeção); só caminhos,
//! modo e dono vêm do cliente, e são validados.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::auth;

/// Verifica a password por PAM e corre `argv` como root via sudo.
fn sudo_exec(user: &str, password: &str, argv: &[&str]) -> Result<(), String> {
    if password.is_empty() {
        return Err("password obrigatória".into());
    }
    // Defesa: confirma que a password é mesmo do utilizador (mesma via do login).
    if !auth::authenticate(user, password) {
        return Err("password incorreta".into());
    }

    let mut child = Command::new("sudo")
        .args(["-S", "-k", "-p", ""])
        .arg("--")
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("sudo indisponível: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(format!("{password}\n").as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
        Err(if err.contains("incorrect password") || err.contains("try again") {
            "password incorreta (sudo)".into()
        } else if err.contains("not in the sudoers") || err.contains("not allowed") {
            "o utilizador não tem permissões sudo".into()
        } else if err.contains("a terminal is required") || err.contains("askpass") {
            "sudo exige tty/askpass (política requiretty ativa)".into()
        } else {
            let msg = String::from_utf8_lossy(&out.stderr);
            format!("falhou: {}", msg.trim())
        })
    }
}

// ---- validações -----------------------------------------------------------

fn valid_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        Err("nome inválido".into())
    } else {
        Ok(())
    }
}

fn valid_mode(mode: &str) -> Result<String, String> {
    let m = mode.trim();
    u32::from_str_radix(m, 8).map_err(|_| "modo octal inválido (ex.: 755)".to_string())?;
    Ok(m.to_string())
}

fn valid_owner(owner: &str) -> Result<String, String> {
    let o = owner.trim();
    if o.is_empty() || !o.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | ':')) {
        Err("dono inválido (ex.: user ou user:group)".into())
    } else {
        Ok(o.to_string())
    }
}

fn join(parent: &str, name: &str) -> Result<String, String> {
    valid_name(name)?;
    Ok(PathBuf::from(parent).join(name).to_string_lossy().into_owned())
}

// ---- operações elevadas ---------------------------------------------------

pub fn mkdir(user: &str, pw: &str, parent: &str, name: &str) -> Result<(), String> {
    let p = join(parent, name)?;
    sudo_exec(user, pw, &["mkdir", "--", &p])
}
pub fn mkfile(user: &str, pw: &str, parent: &str, name: &str) -> Result<(), String> {
    let p = join(parent, name)?;
    sudo_exec(user, pw, &["touch", "--", &p])
}
pub fn rename(user: &str, pw: &str, path: &str, newname: &str) -> Result<(), String> {
    valid_name(newname)?;
    let parent = PathBuf::from(path).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let dst = join(&parent, newname)?;
    sudo_exec(user, pw, &["mv", "--", path, &dst])
}
pub fn chmod(user: &str, pw: &str, path: &str, mode: &str) -> Result<(), String> {
    let m = valid_mode(mode)?;
    sudo_exec(user, pw, &["chmod", &m, "--", path])
}
pub fn chown(user: &str, pw: &str, path: &str, owner: &str, recursive: bool) -> Result<(), String> {
    let o = valid_owner(owner)?;
    if recursive {
        sudo_exec(user, pw, &["chown", "-R", &o, "--", path])
    } else {
        sudo_exec(user, pw, &["chown", &o, "--", path])
    }
}
pub fn delete(user: &str, pw: &str, path: &str, recursive: bool) -> Result<(), String> {
    if recursive {
        sudo_exec(user, pw, &["rm", "-rf", "--", path])
    } else {
        sudo_exec(user, pw, &["rm", "-f", "--", path])
    }
}
