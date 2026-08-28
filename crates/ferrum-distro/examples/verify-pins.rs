//! Verify every pinned repository fingerprint — and every repository URL —
//! against what the vendor is actually serving today.
//!
//!     cargo run -p ferrum-distro --example verify-pins
//!
//! This is the check that turns a researched fingerprint into a confirmed one.
//! It also fetches the metadata index each repository would be added with,
//! because a correct key on an unreachable URL is still a broken install: the
//! panel once shipped a MariaDB repository whose host answers package managers
//! with 403, the key verified perfectly, and the unit test asserted the broken
//! host by name and passed for as long as the feature was broken. A URL test
//! that never leaves the process cannot catch that; this one can.
//! It is an example rather than a test because it needs the network, and a test
//! suite that fails when a vendor's CDN hiccups is a test suite people learn to
//! ignore. That is not hypothetical: two consecutive runs of this file
//! disagreed by two failures purely on transient fetch errors, and the second
//! run was clean. Read a non-zero count as "look at these", not "the pin is
//! wrong" — the line above each failure says which it was.

use ferrum_distro::detect::{Arch, DistroInfo, Family};
use ferrum_distro::pgp;

#[tokio::main]
async fn main() {
    let targets = [
        ("Debian 13", debian("trixie", "debian", "13")),
        ("Ubuntu 24.04", debian("noble", "ubuntu", "24.04")),
        ("AlmaLinux 9", rhel("9", Arch::X86_64)),
        ("AlmaLinux 10", rhel("10", Arch::X86_64)),
        // PGDG signs each RPM architecture with its own key, so the aarch64
        // pin is only exercised by an aarch64 target.
        ("AlmaLinux 9 (aarch64)", rhel("9", Arch::Aarch64)),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("ferrum-pin-check")
        .https_only(true)
        .build()
        .expect("client");

    let mut checked = std::collections::BTreeSet::new();
    let mut failures = 0;

    for (label, info) in &targets {
        println!("\n=== {label} ===");
        for repo in ferrum_distro::repos::catalogue(info) {
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

    // The metadata index each repository would actually be fetched from.
    //
    // Debian and RHEL address a repository differently, so the URL a package
    // manager would request is built here the same way the sources entry or the
    // .repo file builds it — anything else would verify a URL nothing uses.
    println!("\n=== repository metadata ===");
    let mut seen_urls = std::collections::BTreeSet::new();
    for (label, info) in &targets {
        for repo in ferrum_distro::repos::catalogue(info) {
            let d = &repo.definition;
            let url = match (&d.suite, info.family) {
                (Some(suite), Family::Debian) => {
                    format!("{}/dists/{suite}/Release", d.base_url.trim_end_matches('/'))
                }
                _ => format!("{}/repodata/repomd.xml", d.base_url.trim_end_matches('/')),
            };
            if !seen_urls.insert(url.clone()) {
                continue;
            }
            match client.get(&url).send().await {
                Ok(r) if r.status().is_success() => {
                    println!("  {:<10} {:<22} 200  {url}", d.id, label);

                    // The second, independent route (see pgp::signature_issuers):
                    // the key that really signs the metadata a machine installs
                    // from, published on a different path from the key file.
                    let sig_url = if d.suite.is_some() {
                        url.replace("/Release", "/Release.gpg")
                    } else {
                        format!("{url}.asc")
                    };
                    match client.get(&sig_url).send().await {
                        Ok(sr) if sr.status().is_success() => {
                            let body = sr.bytes().await.unwrap_or_default().to_vec();
                            match pgp::signature_issuers(&body) {
                                Ok(issuers) => {
                                    let pinned: Vec<String> = d
                                        .accepted_fingerprints
                                        .iter()
                                        .map(|f| pgp::normalise(f))
                                        .collect();
                                    // A subkey may sign on the primary's behalf,
                                    // so a non-match is reported, not failed:
                                    // the primary is what we pin.
                                    let hit = issuers.iter().any(|i| pinned.contains(i));
                                    println!(
                                        "             signed by {} {}",
                                        issuers.join(", "),
                                        if hit {
                                            "== PINNED PRIMARY (corroborated)"
                                        } else {
                                            "(a subkey of the pinned primary, or a rotation to check)"
                                        }
                                    );
                                }
                                Err(e) => println!("             signature unreadable: {e}"),
                            }
                        }
                        Ok(sr) => println!("             no detached signature: HTTP {}", sr.status()),
                        Err(e) => println!("             signature fetch failed: {e}"),
                    }
                }
                Ok(r) => {
                    println!("  {:<10} {:<22} HTTP {}  {url}", d.id, label, r.status());
                    failures += 1;
                }
                Err(e) => {
                    println!("  {:<10} {:<22} unreachable: {e}  {url}", d.id, label);
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

fn rhel(major: &str, arch: Arch) -> DistroInfo {
    DistroInfo {
        id: "almalinux".into(),
        version_id: format!("{major}.0"),
        codename: String::new(),
        pretty_name: format!("AlmaLinux {major}"),
        family: Family::Rhel,
        arch,
        has_systemd: true,
        has_cgroups_v2: true,
    }
}
