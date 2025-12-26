//! Build script for XOmB
//!
//! Assembles the multiboot2 boot stub when building for bare metal target.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Only build assembly for multiboot2 target
    if (target.contains("none") || target.contains("xomb")) && env::var("CARGO_FEATURE_MULTIBOOT2").is_ok() {
        println!("cargo:rerun-if-changed=src/boot/multiboot2_header.asm");
        println!("cargo:rerun-if-changed=linker-multiboot2.ld");

        // Assemble with NASM (handles 32/64-bit mixing correctly)
        let obj_path = out_dir.join("multiboot2_header.o");
        let status = Command::new("nasm")
            .args([
                "-f", "elf64",
                "-o", obj_path.to_str().unwrap(),
                "src/boot/multiboot2_header.asm",
            ])
            .status()
            .expect("Failed to run NASM. Install nasm package.");

        if !status.success() {
            panic!("Failed to assemble multiboot2_header.asm");
        }

        // Create static library
        let lib_path = out_dir.join("libboot_asm.a");
        let status = Command::new("ar")
            .args([
                "crus",
                lib_path.to_str().unwrap(),
                obj_path.to_str().unwrap(),
            ])
            .status()
            .expect("Failed to run ar");

        if !status.success() {
            panic!("Failed to create libboot_asm.a");
        }

        // Link the assembly library
        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static=boot_asm");

        // Use custom linker script
        println!("cargo:rustc-link-arg=-Tlinker-multiboot2.ld");
        println!("cargo:rustc-link-arg=--gc-sections");
    }
}
