//! Liga ao libpam em runtime sem exigir o pacote -dev: se existir o symlink de
//! dev `libpam.so` (nativo ou cross), usa-o; caso contrário cria um symlink em
//! OUT_DIR a apontar para o `libpam.so.0` do sistema, para que `-lpam` resolva.
//! É consciente da arquitetura (TARGET_ARCH), para funcionar em cross-compile.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = std::env::var("OUT_DIR").unwrap();
    let link = format!("{out}/libpam.so");

    // Diretório multiarch do alvo (ex.: x86_64-linux-gnu, aarch64-linux-gnu).
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
    let ma = format!("{arch}-linux-gnu");

    // Preferir o symlink de dev (libpam.so); só depois o runtime (libpam.so.0).
    let dev = [
        format!("/usr/lib/{ma}/libpam.so"),
        format!("/lib/{ma}/libpam.so"),
        "/usr/lib/libpam.so".into(),
    ];
    let runtime = [
        format!("/usr/lib/{ma}/libpam.so.0"),
        format!("/lib/{ma}/libpam.so.0"),
        "/lib64/libpam.so.0".into(),
        "/usr/lib/libpam.so.0".into(),
    ];

    if dev.iter().any(|p| Path::new(p).exists()) {
        // Symlink de dev presente — o linker resolve `-lpam` sozinho.
    } else if let Some(target) = runtime.iter().find(|p| Path::new(p).exists()) {
        // Só há o .so.0 — cria um symlink de dev em OUT_DIR.
        let _ = std::fs::remove_file(&link);
        if std::os::unix::fs::symlink(target, &link).is_ok() {
            println!("cargo:rustc-link-search=native={out}");
        }
    }

    println!("cargo:rustc-link-lib=dylib=pam");
}
