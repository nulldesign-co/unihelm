//! Computing OpenPGP key fingerprints, so a repository's signing key can be
//! pinned (spec §7.3, §12 rule 9).
//!
//! We parse the key ourselves rather than shelling out to `gpg` for three
//! reasons: `gpg` is not installed on a minimal server and pulling it in as a
//! dependency to check one hash is absurd; its output format is not a stable
//! interface; and calling it would mean executing a program with attacker-
//! influenced input at exactly the moment we are trying to establish trust.
//!
//! A fingerprint is a hash over the *public key packet*, which is a fixed,
//! well-specified byte layout:
//!
//! - **v4** (RFC 4880 §12.2): `SHA-1(0x99 || uint16(len) || packet_body)`
//! - **v6** (RFC 9580 §5.5.4): `SHA-256(0x9B || uint32(len) || packet_body)`
//!
//! Nothing here verifies a *signature*. That is `apt`'s and `dnf`'s job, and
//! they do it on every fetch. What this module does is answer "is the key I just
//! downloaded the key I was told to expect", which is the part a package manager
//! cannot do for us.

use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{DistroError, Result};

/// A parsed public key: its fingerprint and whether it is a primary key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFingerprint {
    /// Uppercase hex, no spaces.
    pub fingerprint: String,
    /// v4 keys are 40 hex characters, v6 keys are 64.
    pub version: u8,
    /// Subkeys sign the metadata, but vendors publish the *primary* fingerprint.
    pub is_primary: bool,
}

/// Every public key in a keyring or armored block.
///
/// Vendors ship bundles: nginx serves three keys in one file (the active signer,
/// a legacy one, and one staged for a future rotation), so a pin has to be able
/// to match any of them.
pub fn fingerprints(key_material: &[u8]) -> Result<Vec<KeyFingerprint>> {
    let binary = if looks_armored(key_material) {
        dearmor(key_material)?
    } else {
        key_material.to_vec()
    };

    let packets = parse_packets(&binary)?;
    let mut out = Vec::new();

    for packet in packets {
        // Tag 6 = public key, tag 14 = public subkey. Tags 5 and 7 are the
        // secret equivalents, which have the same public prefix — a vendor
        // should never publish one, but if they do, the fingerprint is still
        // computed over the public portion, so treat them the same.
        let is_primary = match packet.tag {
            6 | 5 => true,
            14 | 7 => false,
            _ => continue,
        };
        if let Some(fp) = fingerprint_of(&packet.body) {
            out.push(KeyFingerprint { is_primary, ..fp });
        }
    }

    if out.is_empty() {
        return Err(DistroError::InvalidName(
            "the downloaded key material contains no OpenPGP public key".into(),
        ));
    }
    Ok(out)
}

/// Normalise a published fingerprint: vendors print them spaced and in either
/// case, and a pin that fails because of a space is a pin nobody keeps.
pub fn normalise(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase()
}

/// Does `key_material` contain a key matching one of `accepted`?
///
/// Comparison is over the whole fingerprint. Short key ids are deliberately not
/// accepted: they are forgeable, and a pin you can collide is not a pin.
pub fn verify_pinned(key_material: &[u8], accepted: &[String]) -> Result<KeyFingerprint> {
    let accepted: Vec<String> = accepted.iter().map(|f| normalise(f)).collect();
    for pin in &accepted {
        if pin.len() != 40 && pin.len() != 64 {
            return Err(DistroError::InvalidName(format!(
                "`{pin}` is not a full fingerprint (40 or 64 hex characters)"
            )));
        }
    }

    let found = fingerprints(key_material)?;
    if let Some(hit) = found.iter().find(|k| accepted.contains(&k.fingerprint)) {
        return Ok(hit.clone());
    }

    Err(DistroError::PackageFailed(format!(
        "the downloaded signing key does not match any pinned fingerprint.\n  \
         expected one of: {}\n  \
         key material contains: {}\n  \
         Refusing to add this repository. If the vendor rotated their key, the new \
         fingerprint must be verified out of band and pinned in Ferrum before this \
         repository can be used.",
        accepted.join(", "),
        found
            .iter()
            .map(|k| k.fingerprint.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

/// The key that actually signed something, read out of a detached signature.
///
/// This is the *second, independent route* the module docs say most pins are
/// missing. Fetching a vendor's key file and checking its fingerprint proves
/// only that the pin matches what that URL serves — a compromised mirror would
/// serve its own key and we would faithfully pin it. A signature on live
/// repository metadata is different evidence: it names the key that is really
/// signing the packages a machine would install, and it is published on a
/// different path (often a different host) from the key file.
///
/// Reads the issuer-fingerprint subpacket (type 33) from the hashed and then
/// the unhashed area of every signature packet (tag 2). Deliberately not the
/// 8-byte issuer key ID (type 16): a key ID is a truncation, and a truncation
/// is not an identity — colliding key IDs are cheap to manufacture.
pub fn signature_issuers(signature: &[u8]) -> Result<Vec<String>> {
    let data = dearmor(signature)?;
    let mut out = Vec::new();

    for packet in parse_packets(&data)? {
        if packet.tag != 2 {
            continue;
        }
        let b = &packet.body;
        // v4 and v6 both start with the version byte; only v4/v6 carry
        // subpackets at all, and v3 signatures have no fingerprint to give.
        if b.len() < 6 || (b[0] != 4 && b[0] != 6) {
            continue;
        }
        // v4: version, sig type, pk algo, hash algo, then two subpacket areas
        // each prefixed with a two-byte length.
        let mut i = 4usize;
        for _ in 0..2 {
            if i + 2 > b.len() {
                break;
            }
            let area_len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
            i += 2;
            let end = match i.checked_add(area_len) {
                Some(e) if e <= b.len() => e,
                _ => break,
            };
            collect_issuer_fingerprints(&b[i..end], &mut out);
            i = end;
        }
    }

    if out.is_empty() {
        return Err(DistroError::InvalidName(
            "the signature names no issuer fingerprint (only v4 and v6 signatures carry one)"
                .into(),
        ));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Walk one subpacket area, pulling out every issuer-fingerprint subpacket.
///
/// Bounded and non-recursive, like the packet walker: this is untrusted input
/// fetched over the network.
fn collect_issuer_fingerprints(area: &[u8], out: &mut Vec<String>) {
    let mut i = 0usize;
    // A subpacket area with more entries than this is not a signature.
    for _ in 0..1024 {
        if i >= area.len() {
            return;
        }
        // Subpacket length uses the same three-form encoding as old packet
        // lengths, and the length counts the type byte that follows it.
        let (len, consumed) = match area[i] {
            l if l < 192 => (l as usize, 1),
            l if l < 255 => {
                if i + 1 >= area.len() {
                    return;
                }
                (((l as usize - 192) << 8) + area[i + 1] as usize + 192, 2)
            }
            _ => {
                if i + 5 > area.len() {
                    return;
                }
                (
                    u32::from_be_bytes([area[i + 1], area[i + 2], area[i + 3], area[i + 4]])
                        as usize,
                    5,
                )
            }
        };
        i += consumed;
        if len == 0 || i + len > area.len() {
            return;
        }
        let sub_type = area[i] & 0x7F;
        let body = &area[i + 1..i + len];
        // Type 33: one version byte, then the fingerprint. Version 4 gives 20
        // bytes, version 6 gives 32.
        if sub_type == 33 && !body.is_empty() {
            let expected = match body[0] {
                4 => 20,
                6 => 32,
                _ => 0,
            };
            if expected > 0 && body.len() >= 1 + expected {
                out.push(hex_upper(&body[1..1 + expected]));
            }
        }
        i += len;
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

// ---------------------------------------------------------------------------
// packet parsing
// ---------------------------------------------------------------------------

struct Packet {
    tag: u8,
    body: Vec<u8>,
}

/// Walk the packet stream. Bounded and non-recursive: this parses data we do not
/// yet trust.
fn parse_packets(data: &[u8]) -> Result<Vec<Packet>> {
    // A keyring larger than this is not a keyring.
    const MAX_INPUT: usize = 4 * 1024 * 1024;
    const MAX_PACKETS: usize = 4096;

    if data.len() > MAX_INPUT {
        return Err(DistroError::InvalidName(
            "key material is implausibly large".into(),
        ));
    }

    let mut packets = Vec::new();
    let mut i = 0usize;

    while i < data.len() {
        if packets.len() >= MAX_PACKETS {
            return Err(DistroError::InvalidName(
                "key material has too many packets".into(),
            ));
        }

        let header = data[i];
        // Bit 7 must be set on every packet header.
        if header & 0x80 == 0 {
            return Err(DistroError::InvalidName(
                "not an OpenPGP packet stream".into(),
            ));
        }
        i += 1;

        let (tag, length) = if header & 0x40 != 0 {
            // New format: tag is the low 6 bits, length is self-describing.
            let tag = header & 0x3F;
            let (len, consumed) = new_format_length(&data[i..])?;
            i += consumed;
            (tag, len)
        } else {
            // Old format: tag is bits 2-5, length type is the low 2 bits.
            let tag = (header & 0x3C) >> 2;
            let len_type = header & 0x03;
            let (len, consumed) = old_format_length(&data[i..], len_type)?;
            i += consumed;
            (tag, len)
        };

        let end = i
            .checked_add(length)
            .ok_or_else(|| DistroError::InvalidName("packet length overflows the input".into()))?;
        if end > data.len() {
            return Err(DistroError::InvalidName(
                "packet extends past the end of the input".into(),
            ));
        }

        packets.push(Packet {
            tag,
            body: data[i..end].to_vec(),
        });
        i = end;
    }

    Ok(packets)
}

fn new_format_length(rest: &[u8]) -> Result<(usize, usize)> {
    let first = *rest
        .first()
        .ok_or_else(|| DistroError::InvalidName("truncated length".into()))?;
    match first {
        0..=191 => Ok((first as usize, 1)),
        192..=223 => {
            let second = *rest
                .get(1)
                .ok_or_else(|| DistroError::InvalidName("truncated length".into()))?;
            Ok(((((first as usize) - 192) << 8) + second as usize + 192, 2))
        }
        224..=254 => {
            // A partial body length only appears in literal/compressed data, not
            // in a key. Refusing is safer than trying to reassemble.
            Err(DistroError::InvalidName(
                "partial packet lengths are not supported".into(),
            ))
        }
        255 => {
            let bytes: [u8; 4] = rest
                .get(1..5)
                .ok_or_else(|| DistroError::InvalidName("truncated length".into()))?
                .try_into()
                .expect("checked slice of exactly 4 bytes");
            Ok((u32::from_be_bytes(bytes) as usize, 5))
        }
    }
}

fn old_format_length(rest: &[u8], len_type: u8) -> Result<(usize, usize)> {
    let need = match len_type {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => {
            return Err(DistroError::InvalidName(
                "indeterminate packet length is not supported in key material".into(),
            ));
        }
    };
    let bytes = rest
        .get(..need)
        .ok_or_else(|| DistroError::InvalidName("truncated length".into()))?;
    let len = bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
    Ok((len, need))
}

/// The fingerprint of one public key packet body.
fn fingerprint_of(body: &[u8]) -> Option<KeyFingerprint> {
    let version = *body.first()?;
    match version {
        4 => {
            let len = u16::try_from(body.len()).ok()?;
            let mut hasher = Sha1::new();
            hasher.update([0x99]);
            hasher.update(len.to_be_bytes());
            hasher.update(body);
            Some(KeyFingerprint {
                fingerprint: hex::encode_upper(hasher.finalize()),
                version: 4,
                is_primary: true,
            })
        }
        6 => {
            let len = u32::try_from(body.len()).ok()?;
            let mut hasher = Sha256::new();
            hasher.update([0x9B]);
            hasher.update(len.to_be_bytes());
            hasher.update(body);
            Some(KeyFingerprint {
                fingerprint: hex::encode_upper(hasher.finalize()),
                version: 6,
                is_primary: true,
            })
        }
        // v3 keys have been unsafe for two decades and no vendor we support
        // ships one.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// ASCII armor
// ---------------------------------------------------------------------------

fn looks_armored(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN PGP")
        || data.windows(14).take(4096).any(|w| w == b"-----BEGIN PGP")
}

/// Strip ASCII armor, concatenating every block in the file.
///
/// Vendors publish bundles as several armored blocks back to back, so this must
/// not stop at the first `-----END-----`.
pub fn dearmor(data: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine;

    // Binary OpenPGP is already what the parser wants; only armor needs undoing.
    //
    // Detecting it by "is this UTF-8" rather than refusing non-UTF-8 outright:
    // apt repositories publish `Release.gpg` as a raw binary signature, and
    // demanding text meant the panel could read nginx's RPM signature but not
    // its Debian one — a gap in verification created purely by an input format.
    let Ok(text) = std::str::from_utf8(data) else {
        return Ok(data.to_vec());
    };
    if !text.contains("-----BEGIN PGP") {
        return Ok(data.to_vec());
    }

    let mut out = Vec::new();
    let mut in_block = false;
    let mut past_headers = false;
    let mut buffer = String::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');

        if line.starts_with("-----BEGIN PGP") {
            in_block = true;
            past_headers = false;
            buffer.clear();
            continue;
        }
        if line.starts_with("-----END PGP") {
            if in_block && !buffer.is_empty() {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&buffer)
                    .map_err(|e| DistroError::InvalidName(format!("bad base64 in armor: {e}")))?;
                out.extend_from_slice(&decoded);
            }
            in_block = false;
            buffer.clear();
            continue;
        }
        if !in_block {
            continue;
        }
        if !past_headers {
            // Armor headers (`Version:`, `Comment:`) run until a blank line.
            if line.trim().is_empty() {
                past_headers = true;
            } else if !line.contains(':') {
                // No headers at all — this line is already payload.
                past_headers = true;
                buffer.push_str(line.trim());
            }
            continue;
        }
        // The CRC24 line starts with '=' and is not part of the payload. We do
        // not check it: the fingerprint comparison is a far stronger check than
        // a 24-bit checksum.
        if line.starts_with('=') {
            continue;
        }
        buffer.push_str(line.trim());
    }

    if out.is_empty() {
        return Err(DistroError::InvalidName(
            "armored block contained no data".into(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid v4 public key packet body.
    ///
    /// The key material is not a real RSA key — the fingerprint is a hash over
    /// the bytes, and the bytes are what we are testing.
    fn v4_key_body(timestamp: u32, filler: u8) -> Vec<u8> {
        let mut body = vec![4];
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.push(1); // algorithm: RSA
        // MPI: 16-bit bit-count, then the big-endian integer.
        body.extend_from_slice(&2048u16.to_be_bytes());
        body.extend(std::iter::repeat_n(filler, 256));
        body.extend_from_slice(&17u16.to_be_bytes());
        body.extend_from_slice(&[0x01, 0x00, 0x01]);
        body
    }

    /// Wrap a body in a new-format packet header.
    fn new_format_packet(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0xC0 | tag];
        // Always use the 5-byte form so the test does not depend on the length.
        out.push(255);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn old_format_packet(tag: u8, body: &[u8]) -> Vec<u8> {
        // Length type 2 = four-byte length.
        let mut out = vec![0x80 | (tag << 2) | 0x02];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn the_v4_fingerprint_is_sha1_over_the_specified_prefix() {
        // Spelled out here rather than by calling the function, so this test
        // actually checks the formula from RFC 4880 §12.2.
        use sha1::Digest as _;
        let body = v4_key_body(0x5C33_1234, 0xAB);
        let mut expected = Sha1::new();
        expected.update([0x99]);
        expected.update((body.len() as u16).to_be_bytes());
        expected.update(&body);
        let expected = hex::encode_upper(expected.finalize());

        let found = fingerprints(&new_format_packet(6, &body)).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].fingerprint, expected);
        assert_eq!(found[0].fingerprint.len(), 40);
        assert_eq!(found[0].version, 4);
        assert!(found[0].is_primary);
    }

    #[test]
    fn old_and_new_packet_formats_give_the_same_fingerprint() {
        // Vendors ship both; a fingerprint that depended on the framing would be
        // a fingerprint that sometimes fails.
        let body = v4_key_body(1, 0x11);
        let new = fingerprints(&new_format_packet(6, &body)).unwrap();
        let old = fingerprints(&old_format_packet(6, &body)).unwrap();
        assert_eq!(new[0].fingerprint, old[0].fingerprint);
    }

    #[test]
    fn a_bundle_yields_every_key_and_marks_subkeys() {
        // nginx publishes three keys in one file; Docker publishes a primary
        // with a signing subkey.
        let mut bundle = Vec::new();
        bundle.extend(new_format_packet(6, &v4_key_body(1, 0xA1)));
        bundle.extend(new_format_packet(14, &v4_key_body(2, 0xA2)));
        bundle.extend(new_format_packet(6, &v4_key_body(3, 0xA3)));

        let found = fingerprints(&bundle).unwrap();
        assert_eq!(found.len(), 3);
        assert_eq!(found.iter().filter(|k| k.is_primary).count(), 2);
        assert!(!found[1].is_primary, "the middle key is a subkey");

        let unique: std::collections::HashSet<_> = found.iter().map(|k| &k.fingerprint).collect();
        assert_eq!(unique.len(), 3, "different keys must not collide");
    }

    #[test]
    fn non_key_packets_are_skipped_not_hashed() {
        let mut data = Vec::new();
        // A user-id packet (tag 13) and a signature packet (tag 2) sit between
        // the keys in every real keyring.
        data.extend(new_format_packet(
            13,
            b"nginx signing key <signing-key@nginx.com>",
        ));
        data.extend(new_format_packet(6, &v4_key_body(1, 0x55)));
        data.extend(new_format_packet(2, &[0u8; 64]));

        let found = fingerprints(&data).unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn armored_input_is_decoded() {
        use base64::Engine;
        let body = v4_key_body(7, 0x33);
        let binary = new_format_packet(6, &body);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&binary);

        let armored = format!(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2\nComment: hi\n\n{}\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n",
            encoded
                .as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );

        let from_armor = fingerprints(armored.as_bytes()).unwrap();
        let from_binary = fingerprints(&binary).unwrap();
        assert_eq!(from_armor[0].fingerprint, from_binary[0].fingerprint);
    }

    #[test]
    fn several_armored_blocks_in_one_file_are_all_read() {
        use base64::Engine;
        let mut armored = String::new();
        let mut expected = Vec::new();
        for filler in [0x01u8, 0x02, 0x03] {
            let packet = new_format_packet(6, &v4_key_body(filler as u32, filler));
            expected.push(fingerprints(&packet).unwrap()[0].fingerprint.clone());
            armored.push_str("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n");
            armored.push_str(&base64::engine::general_purpose::STANDARD.encode(&packet));
            armored.push_str("\n-----END PGP PUBLIC KEY BLOCK-----\n");
        }

        let found: Vec<String> = fingerprints(armored.as_bytes())
            .unwrap()
            .into_iter()
            .map(|k| k.fingerprint)
            .collect();
        assert_eq!(
            found, expected,
            "a three-key bundle must yield three fingerprints"
        );
    }

    #[test]
    fn pinning_accepts_any_key_in_the_bundle() {
        let mut bundle = Vec::new();
        let mut fps = Vec::new();
        for filler in [0x10u8, 0x20] {
            let packet = new_format_packet(6, &v4_key_body(filler as u32, filler));
            fps.push(fingerprints(&packet).unwrap()[0].fingerprint.clone());
            bundle.extend(packet);
        }

        // Pinning only the second key still verifies, because the bundle
        // contains it — this is the nginx rotation case.
        let matched = verify_pinned(&bundle, &[fps[1].clone()]).unwrap();
        assert_eq!(matched.fingerprint, fps[1]);
    }

    #[test]
    fn pinning_is_tolerant_of_how_a_vendor_prints_it() {
        let packet = new_format_packet(6, &v4_key_body(1, 0x77));
        let fp = fingerprints(&packet).unwrap()[0].fingerprint.clone();

        let spaced = fp
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(verify_pinned(&packet, &[spaced]).is_ok());
        assert!(verify_pinned(&packet, &[fp.to_lowercase()]).is_ok());
    }

    #[test]
    fn a_wrong_key_is_refused_with_an_explanation() {
        let packet = new_format_packet(6, &v4_key_body(1, 0x99));
        let err = verify_pinned(&packet, &["0".repeat(40)]).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("does not match any pinned fingerprint"),
            "{message}"
        );
        // The operator needs to see what was actually served to decide whether
        // this is a rotation or an attack.
        assert!(message.contains("key material contains"));
    }

    #[test]
    fn a_short_key_id_is_never_accepted_as_a_pin() {
        // 32-bit and 64-bit key ids are forgeable; accepting one would make the
        // pin decorative.
        let packet = new_format_packet(6, &v4_key_body(1, 0x99));
        let full = fingerprints(&packet).unwrap()[0].fingerprint.clone();
        for short in [&full[24..], &full[32..]] {
            let err = verify_pinned(&packet, &[short.to_string()]).unwrap_err();
            assert!(
                err.to_string().contains("not a full fingerprint"),
                "accepted `{short}`"
            );
        }
    }

    #[test]
    fn malformed_input_is_rejected_rather_than_misparsed() {
        for (name, data) in [
            ("empty", vec![]),
            ("not a packet stream", b"hello world".to_vec()),
            ("truncated length", vec![0xC6, 255, 0x00]),
            (
                "length past the end",
                vec![0xC6, 255, 0xFF, 0xFF, 0xFF, 0xFF, 0x04],
            ),
            ("partial lengths", vec![0xC6, 224, 0x00]),
        ] {
            assert!(
                fingerprints(&data).is_err(),
                "`{name}` should have been rejected"
            );
        }
    }

    #[test]
    fn a_keyring_with_no_public_key_is_an_error_not_an_empty_pass() {
        // The dangerous failure: returning Ok(vec![]) and letting a caller
        // conclude "nothing mismatched".
        let only_a_user_id = new_format_packet(13, b"somebody");
        assert!(fingerprints(&only_a_user_id).is_err());
        assert!(verify_pinned(&only_a_user_id, &["A".repeat(40)]).is_err());
    }

    #[test]
    fn a_v6_key_hashes_with_sha256() {
        let mut body = vec![6];
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(27); // Ed25519
        body.extend_from_slice(&32u32.to_be_bytes());
        body.extend(std::iter::repeat_n(0x42u8, 32));

        let found = fingerprints(&new_format_packet(6, &body)).unwrap();
        assert_eq!(found[0].version, 6);
        assert_eq!(
            found[0].fingerprint.len(),
            64,
            "a v6 fingerprint is SHA-256"
        );
    }

    #[test]
    fn normalise_strips_formatting_only() {
        assert_eq!(normalise("8540 A6F1 8833 A80E"), "8540A6F18833A80E");
        assert_eq!(normalise("8540a6f1"), "8540A6F1");
        assert_eq!(normalise(""), "");
    }
}
