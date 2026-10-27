// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Isolated CPUID probe for the experimental legacy WHP compatibility path.

#[cfg(all(windows, target_arch = "x86_64"))]
fn main() -> std::io::Result<()> {
    whp::run_legacy_cpuid_probe()
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn main() {
    eprintln!("The legacy WHP CPUID probe requires x86-64 Windows.");
    std::process::exit(1);
}
