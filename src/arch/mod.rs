//! Architecture-specific code
//!
//! Currently only x86_64 is supported.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
