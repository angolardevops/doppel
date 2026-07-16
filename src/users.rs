//! Gestão de utilizadores do sistema. Listagem lê /etc/passwd e /etc/group
//! (world-readable). Operações mutantes correm via `sudo` (wizard de elevação):
//! useradd/usermod/userdel/chpasswd/gpasswd, com argumentos validados.

use std::collections::HashMap;

use serde::Serialize;

use crate::elevate;

#[derive(Serialize)]
pub struct UserInfo {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
    pub is_system: bool,
    pub groups: Vec<String>,
}

#[derive(Serialize)]
pub struct GroupInfo {
    pub name: String,
    pub gid: u32,
    pub members: usize,
}

#[derive(Serialize)]
pub struct Listing {
    pub users: Vec<UserInfo>,
    pub groups: Vec<GroupInfo>,
}

pub fn list() -> Listing {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let group = std::fs::read_to_string("/etc/group").unwrap_or_default();

    // grupo por gid e membros por grupo
    let mut gid_name: HashMap<u32, String> = HashMap::new();
    let mut memberships: HashMap<String, Vec<String>> = HashMap::new(); // user -> grupos secundários
    let mut groups: Vec<GroupInfo> = Vec::new();
    for line in group.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 {
            continue;
        }
        let name = f[0].to_string();
        if let Ok(gid) = f[2].parse::<u32>() {
            gid_name.insert(gid, name.clone());
        }
        let members: Vec<&str> = f[3].split(',').filter(|m| !m.is_empty()).collect();
        for m in &members {
            memberships.entry(m.to_string()).or_default().push(name.clone());
        }
        groups.push(GroupInfo {
            name,
            gid: f[2].parse().unwrap_or(0),
            members: members.len(),
        });
    }
    groups.sort_by(|a, b| a.gid.cmp(&b.gid));

    let mut users = Vec::new();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let uid: u32 = f[2].parse().unwrap_or(0);
        let gid: u32 = f[3].parse().unwrap_or(0);
        let name = f[0].to_string();
        let mut groups_of: Vec<String> = Vec::new();
        if let Some(g) = gid_name.get(&gid) {
            groups_of.push(g.clone()); // grupo primário
        }
        if let Some(sec) = memberships.get(&name) {
            for g in sec {
                if !groups_of.contains(g) {
                    groups_of.push(g.clone());
                }
            }
        }
        users.push(UserInfo {
            name,
            uid,
            gid,
            gecos: f[4].split(',').next().unwrap_or("").to_string(),
            home: f[5].to_string(),
            shell: f[6].to_string(),
            is_system: uid < 1000 || uid == 65534,
            groups: groups_of,
        });
    }
    users.sort_by(|a, b| a.uid.cmp(&b.uid));

    Listing { users, groups }
}

// ---- validações -----------------------------------------------------------

fn valid_username(u: &str) -> Result<(), String> {
    let ok = !u.is_empty()
        && u.len() <= 32
        && u.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err("nome de utilizador inválido (minúsculas, dígitos, _ e -)".into())
    }
}

fn valid_group(g: &str) -> Result<(), String> {
    valid_username(g).map_err(|_| "nome de grupo inválido".to_string())
}

fn valid_shell(s: &str) -> Result<(), String> {
    if s.starts_with('/') && !s.contains(['\n', ' ', ';']) {
        Ok(())
    } else {
        Err("shell deve ser um caminho absoluto".into())
    }
}

fn valid_password(p: &str) -> Result<(), String> {
    if p.is_empty() {
        Err("password vazia".into())
    } else if p.contains(['\n', '\r']) {
        Err("password não pode conter quebras de linha".into())
    } else {
        Ok(())
    }
}

// ---- operações (elevadas) --------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn create(
    admin: &str,
    admin_pw: &str,
    username: &str,
    fullname: &str,
    shell: &str,
    create_home: bool,
    groups: &str,
    newpass: &str,
) -> Result<(), String> {
    valid_username(username)?;
    let mut argv: Vec<String> = vec!["useradd".into()];
    if create_home {
        argv.push("-m".into());
    }
    if !fullname.trim().is_empty() {
        if fullname.contains([':', '\n']) {
            return Err("nome completo inválido".into());
        }
        argv.push("-c".into());
        argv.push(fullname.trim().to_string());
    }
    if !shell.trim().is_empty() {
        valid_shell(shell.trim())?;
        argv.push("-s".into());
        argv.push(shell.trim().to_string());
    }
    let glist: Vec<&str> = groups.split(',').map(|g| g.trim()).filter(|g| !g.is_empty()).collect();
    for g in &glist {
        valid_group(g)?;
    }
    if !glist.is_empty() {
        argv.push("-G".into());
        argv.push(glist.join(","));
    }
    argv.push(username.to_string());

    let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    elevate::sudo_exec(admin, admin_pw, &refs)?;

    // Define a password, se fornecida (via chpasswd por stdin).
    if !newpass.is_empty() {
        set_password(admin, admin_pw, username, newpass)?;
    }
    Ok(())
}

pub fn set_password(admin: &str, admin_pw: &str, username: &str, newpass: &str) -> Result<(), String> {
    valid_username(username)?;
    valid_password(newpass)?;
    let line = format!("{username}:{newpass}\n");
    elevate::sudo_exec_stdin(admin, admin_pw, &["chpasswd"], line.as_bytes())
}

pub fn modify(admin: &str, admin_pw: &str, username: &str, action: &str, value: &str) -> Result<(), String> {
    valid_username(username)?;
    match action {
        "shell" => {
            valid_shell(value)?;
            elevate::sudo_exec(admin, admin_pw, &["usermod", "-s", value, username])
        }
        "addgroup" => {
            valid_group(value)?;
            elevate::sudo_exec(admin, admin_pw, &["usermod", "-aG", value, username])
        }
        "delgroup" => {
            valid_group(value)?;
            elevate::sudo_exec(admin, admin_pw, &["gpasswd", "-d", username, value])
        }
        "lock" => elevate::sudo_exec(admin, admin_pw, &["usermod", "-L", username]),
        "unlock" => elevate::sudo_exec(admin, admin_pw, &["usermod", "-U", username]),
        _ => Err("ação desconhecida".into()),
    }
}

pub fn delete(admin: &str, admin_pw: &str, username: &str, remove_home: bool) -> Result<(), String> {
    valid_username(username)?;
    if remove_home {
        elevate::sudo_exec(admin, admin_pw, &["userdel", "-r", username])
    } else {
        elevate::sudo_exec(admin, admin_pw, &["userdel", username])
    }
}
