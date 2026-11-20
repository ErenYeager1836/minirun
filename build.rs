use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let skel = out_dir.join("minirun_guard.skel.rs");

    SkeletonBuilder::new()
        .source("bpf/minirun_guard.bpf.c")
        .build_and_generate(&skel)
        .expect("Failed to build BPF skeleton");

    println!("cargo:rerun-if-changed=bpf/minirun_guard.bpf.c");
    println!("cargo:rerun-if-changed=bpf/guard_event.h");
    println!("cargo:rerun-if-changed=bpf/vmlinux.h");
}
