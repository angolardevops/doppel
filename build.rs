//! Liga ao libpam em runtime sem precisar do pacote -dev: cria um symlink
//! `libpam.so` em OUT_DIR a apontar para o `libpam.so.0` do sistema, para que
//! `-lpam` resolva na linkagem. Se já houver um `libpam.so` de dev, usa-o.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = std::env::var("OUT_DIR").unwrap();
    let link = format!("{out}/libpam.so");

    let candidates = [
        "/usr/lib/x86_64-linux-gnu/libpam.so",
        "/lib/x86_64-linux-gnu/libpam.so",
        "/usr/lib/x86_64-linux-gnu/libpam.so.0",
        "/lib/x86_64-linux-gnu/libpam.so.0",
        "/lib64/libpam.so.0",
        "/usr/lib/libpam.so.0",
        "/usr/lib/libpam.so",
    ];

    if let Some(target) = candidates.iter().find(|p| Path::new(p).exists()) {
        // remove um symlink antigo, se existir, e recria
        let _ = std::fs::remove_file(&link);
        if std::os::unix::fs::symlink(target, &link).is_ok() {
            println!("cargo:rustc-link-search=native={out}");
        }
    }
    println!("cargo:rustc-link-lib=dylib=pam");
}
