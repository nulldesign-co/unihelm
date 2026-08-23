//! Verify every pinned repository fingerprint against the key the vendor is
//! actually serving today.
//!
//!     cargo run -p ferrum-distro --example verify-pins
//!
//! This is the check that turns a researched fingerprint into a confirmed one.
//! It is an example rather than a test because it needs the network, and a test
//! suite that fails when a vendor's CDN hiccups is a test suite people learn to
//! ignore.

use ferrum_distro::detect::{Arch, DistroInfo, Family};
use ferrum_distro::pgp;

#[tokio::main]
async fn main() {
    let targets = [
        ("Debian 13", debian("trixie", "debian", "13")),
        ("Ubuntu 24.04", debian("noble", "ubuntu", "24.04")),
        ("AlmaLinux 9", rhel("9")),
        ("AlmaLinux 10", rhel("10")),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("ferrum-pin-check")
        .https_only(true)
        .build()
        .expect("client");

    let mut checked = std::collections::BTreeSet::new();
    let mut failures = 0;

    for (label, info) in targets {
        println!("\n=== {label} ===");
        for repo in ferrum_distro::repos::catalogue(&info) {
            let url = repo.definition.gpg_key_url.clone();
            let key = (repo.definition.id.clone(), url.clone());
            if checked.contains(&key) {
                continue;
            }
            checked.insert(key);

            println!("  {:<10} {url}", repo.definition.id);
            let bytes = match client.get(&url).send().await {
                Ok(r) if r.status().is_success() => r.bytes().await.expect("body").to_vec(),
                Ok(r) => {
                    println!("    HTTP {}", r.status());
                    failures += 1;
                    continue;
                }
                Err(e) => {
                    println!("    fetch failed: {e}");
                    failures += 1;
                    continue;
                }
            };

            match pgp::fingerprints(&bytes) {
                Ok(found) => {
                    for k in &found {
                        println!(
                            "    {} v{} {}",
                            k.fingerprint,
                            k.version,
                            if k.is_primary { "primary" } else { "subkey" }
                        );
                    }
                }
                Err(e) => {
                    println!("    could not parse: {e}");
                    failures += 1;
                    continue;
                }
            }

            match pgp::verify_pinned(&bytes, &repo.definition.accepted_fingerprints) {
                Ok(matched) => println!("    PIN OK -> {}", matched.fingerprint),
                Err(e) => {
                    println!("    PIN MISMATCH: {e}");
                    failures += 1;
                }
            }
        }
    }

    println!(
        "\n{} key source(s) checked, {failures} problem(s)",
        checked.len()
    );
    if failures > 0 {
        std::process::exit(1);
    }
}

fn debian(codename: &str, id: &str, version: &str) -> DistroInfo {
    DistroInfo {
        id: id.into(),
        version_id: version.into(),
        codename: codename.into(),
        pretty_name: format!("{id} {version}"),
        family: Family::Debian,
        arch: Arch::X86_64,
        has_systemd: true,
        has_cgroups_v2: true,
    }
}

fn rhel(major: &str) -> DistroInfo {
    DistroInfo {
        id: "almalinux".into(),
        version_id: format!("{major}.0"),
        codename: String::new(),
        pretty_name: format!("AlmaLinux {major}"),
        family: Family::Rhel,
        arch: Arch::X86_64,
        has_systemd: true,
        has_cgroups_v2: true,
    }
}
