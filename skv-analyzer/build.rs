use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SKV_ATTESTATION_IMPL");
    println!("cargo:rerun-if-changed=src/c/attestation_bridge.c");
    println!("cargo:rerun-if-changed=src/c/attestation_bridge.h");
    println!("cargo:rerun-if-changed=src/zig/attestation_bridge.zig");

    let backend = env::var("SKV_ATTESTATION_IMPL").unwrap_or_else(|_| "c".to_string());
    if backend.eq_ignore_ascii_case("zig") {
        if has_zig() {
            compile_zig();
            return;
        }
        println!(
            "cargo:warning=SKV_ATTESTATION_IMPL=zig requested, but `zig` not found; falling back to C backend"
        );
    }

    compile_c();
}

fn has_zig() -> bool {
    Command::new("zig")
        .arg("version")
        .status()
        .is_ok_and(|s| s.success())
}

fn compile_c() {
    cc::Build::new()
        .file("src/c/attestation_bridge.c")
        .include("src/c")
        .warnings(true)
        .compile("attestation_bridge");
}

fn compile_zig() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is required"));
    let lib_path = out_dir.join("libattestation_bridge.a");

    let status = Command::new("zig")
        .args(["build-lib", "-static", "-O", "ReleaseSafe", "-femit-bin"])
        .arg(&lib_path)
        .arg("src/zig/attestation_bridge.zig")
        .status()
        .expect("failed to invoke zig");

    if !status.success() {
        panic!("zig backend compilation failed");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=attestation_bridge");
}
