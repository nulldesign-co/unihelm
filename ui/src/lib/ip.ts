/**
 * Address parsing for the firewall page (spec §11.9).
 *
 * This is a second copy of a rule the agent already enforces
 * (`refusal_reason` in `crates/ferrum-ops/src/fwops.rs`), and it exists for one
 * reason: so the ban form can say *which* rule an address breaks, in words,
 * before the round trip — rather than letting a red "conflict" toast be the
 * first thing an operator learns.
 *
 * The agent stays the authority. It re-checks every address against loopback,
 * the address the request arrived from, **every address bound to a local
 * interface**, and the operator's allowlist. The last two are invisible to a
 * browser, so this file deliberately checks a subset and the page shows the
 * server's own sentence whenever the server is the one that refuses. A check
 * here that disagreed with the agent would be worse than no check at all.
 */

/** A parsed address: four bytes for v4, sixteen for v6. */
export interface Ip {
  family: 4 | 6;
  bytes: number[];
}

/**
 * Dotted-quad only, and strict about it.
 *
 * `01` is rejected because parsers disagree about it — glibc reads a leading
 * zero as octal, Rust's `Ipv4Addr` refuses it outright. An address that means
 * two different hosts depending on who reads it is exactly the shape an
 * allowlist bypass takes, so anything Rust would refuse is refused here.
 */
function parseIpv4(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const bytes: number[] = [];
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes.push(value);
  }
  return bytes;
}

function parseIpv6(text: string): number[] | null {
  // A scope id (`fe80::1%eth0`) names an interface, not a host, and Rust's
  // parser refuses it. Accepting it here would offer a ban the agent rejects.
  if (text.includes("%")) return null;

  const halves = text.split("::");
  if (halves.length > 2) return null;

  const groups = (chunk: string, allowV4Tail: boolean): number[] | null => {
    if (chunk === "") return [];
    const bytes: number[] = [];
    const pieces = chunk.split(":");
    for (let index = 0; index < pieces.length; index += 1) {
      const piece = pieces[index]!;
      // `::ffff:127.0.0.1` — the trailing group may be written in v4 form, and
      // that is precisely the spelling an SSH log hands an operator.
      if (index === pieces.length - 1 && allowV4Tail && piece.includes(".")) {
        const v4 = parseIpv4(piece);
        if (!v4) return null;
        bytes.push(...v4);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
      const value = parseInt(piece, 16);
      bytes.push(value >> 8, value & 0xff);
    }
    return bytes;
  };

  if (halves.length === 1) {
    const bytes = groups(text, true);
    return bytes && bytes.length === 16 ? bytes : null;
  }

  const head = groups(halves[0]!, false);
  const tail = groups(halves[1]!, true);
  if (!head || !tail) return null;
  // `::` has to stand for at least one omitted group; `1:2:3:4:5:6:7::8` is
  // a full address with a redundant `::` and Rust refuses it.
  const gap = 16 - head.length - tail.length;
  if (gap < 1) return null;
  return [...head, ...new Array<number>(gap).fill(0), ...tail];
}

/** Parse an address, or `null` if it is not literally one. Hostnames never parse. */
export function parseIp(raw: string): Ip | null {
  const text = raw.trim();
  if (text === "") return null;
  if (!text.includes(":")) {
    const v4 = parseIpv4(text);
    return v4 ? { family: 4, bytes: v4 } : null;
  }
  const v6 = parseIpv6(text);
  return v6 ? { family: 6, bytes: v6 } : null;
}

/**
 * Fold an IPv4-mapped v6 address into its v4 form.
 *
 * `::ffff:127.0.0.1` is the same host as `127.0.0.1`, and without this the
 * loopback check below would wave it straight through — which is the exact
 * spelling a dual-stack sshd writes into the journal.
 */
export function canonicalIp(ip: Ip): Ip {
  if (ip.family === 4) return ip;
  const b = ip.bytes;
  const mapped = b.slice(0, 10).every((byte) => byte === 0) && b[10] === 0xff && b[11] === 0xff;
  return mapped ? { family: 4, bytes: b.slice(12) } : ip;
}

export function sameIp(a: Ip, b: Ip): boolean {
  const left = canonicalIp(a);
  const right = canonicalIp(b);
  return (
    left.family === right.family && left.bytes.every((byte, index) => byte === right.bytes[index])
  );
}

function isLoopback(ip: Ip): boolean {
  if (ip.family === 4) return ip.bytes[0] === 127;
  return ip.bytes.slice(0, 15).every((byte) => byte === 0) && ip.bytes[15] === 1;
}

/** Addresses that are not one host: unspecified, multicast, v4 broadcast. */
function isNotAHost(ip: Ip): boolean {
  if (ip.bytes.every((byte) => byte === 0)) return true;
  if (ip.family === 4) {
    if (ip.bytes[0]! >= 224 && ip.bytes[0]! <= 239) return true;
    return ip.bytes.every((byte) => byte === 255);
  }
  return ip.bytes[0] === 0xff;
}

/**
 * Why this address must not be banned from this browser, or `null`.
 *
 * The order matches the agent's, so the reason an operator sees here is the
 * reason they would have seen from the server.
 */
export type BanRefusal = "malformed" | "loopback" | "self" | "not_a_host";

export function banRefusal(raw: string, yourIp: string | null | undefined): BanRefusal | null {
  const parsed = parseIp(raw);
  if (!parsed) return "malformed";
  const ip = canonicalIp(parsed);

  if (isLoopback(ip)) return "loopback";

  // `yourIp` comes from the server, which is the only party that knows which
  // address this connection actually arrived from — a browser cannot see past
  // its own NAT. When the server does not say, the agent still refuses; the
  // form just cannot explain it in advance.
  const yours = yourIp ? parseIp(yourIp) : null;
  if (yours && sameIp(ip, yours)) return "self";

  if (isNotAHost(ip)) return "not_a_host";
  return null;
}

/**
 * `addr` or `addr/len`, the shape Sentinel's allowlist takes.
 *
 * A malformed entry is refused rather than ignored: the agent's `cidr_contains`
 * treats an unparseable entry as covering nothing, so a typo in the allowlist
 * would silently stop protecting the address the operator meant to protect.
 */
export function isCidr(raw: string): boolean {
  const text = raw.trim();
  const slash = text.indexOf("/");
  if (slash === -1) return parseIp(text) !== null;

  const ip = parseIp(text.slice(0, slash));
  if (!ip) return false;
  const prefix = text.slice(slash + 1).trim();
  if (!/^(0|[1-9][0-9]{0,2})$/.test(prefix)) return false;
  return Number(prefix) <= (ip.family === 6 ? 128 : 32);
}
