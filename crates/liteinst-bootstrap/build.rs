//! This build consumes a finalized catalog; it never invokes a producer or planner.
use std::{env, fs, io::Read, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=LITEINST_BOOTSTRAP_CATALOG");
    let path = PathBuf::from(
        env::var_os("LITEINST_BOOTSTRAP_CATALOG")
            .expect("explicit frozen per-product catalog required"),
    );
    assert!(path.is_absolute(), "catalog pathname must be absolute");
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .expect("catalog open")
        .take(liteinst_artifact::startup::MAX_CATALOG as u64 + 1)
        .read_to_end(&mut bytes)
        .expect("catalog read");
    let checked = liteinst_artifact::startup::Catalog::decode(&bytes)
        .expect("complete canonical catalog required");
    assert!(
        checked.encode().expect("catalog encoding") == bytes,
        "canonical catalog bytes"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    fs::write(out.join("main.li2boot"), &bytes).expect("embed catalog");
    // First profile admits a pinned GNU-compatible system loader/linker. Eager
    // binding and process lifetime are mandatory, not environment preferences.
    for option in ["now", "relro", "noexecstack", "nodelete", "nodlopen"] {
        println!("cargo:rustc-link-arg=-Wl,-z,{option}");
    }
}
