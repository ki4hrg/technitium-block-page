import { isIPv4, isIPv6 } from "node:net";

export interface Cidr {
  version: 4 | 6;
  network: bigint;
  prefix: number;
}

/** Strip IPv4-mapped IPv6 ("::ffff:10.0.0.5") and zone ids so sockets and policy compare cleanly. */
export function normalizeIp(ip: string): string {
  let out = ip.trim();
  const zone = out.indexOf("%");
  if (zone !== -1) out = out.slice(0, zone);
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(out);
  if (mapped) return mapped[1]!;
  return out;
}

function ipv4ToBigInt(ip: string): bigint {
  return ip.split(".").reduce((acc, part) => (acc << 8n) | BigInt(Number(part)), 0n);
}

function ipv6ToBigInt(ip: string): bigint {
  let addr = ip;
  // Embedded IPv4 tail, e.g. 64:ff9b::10.0.0.1
  const v4Tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(addr);
  if (v4Tail) {
    const n = ipv4ToBigInt(v4Tail[1]!);
    addr = addr.slice(0, -v4Tail[1]!.length) + ((n >> 16n) & 0xffffn).toString(16) + ":" + (n & 0xffffn).toString(16);
  }
  const [head, tail] = addr.includes("::") ? addr.split("::") : [addr, undefined];
  const headParts = head ? head.split(":").filter(Boolean) : [];
  const tailParts = tail !== undefined ? tail.split(":").filter(Boolean) : [];
  const missing = 8 - headParts.length - tailParts.length;
  const parts = [...headParts, ...Array(tail !== undefined ? missing : 0).fill("0"), ...tailParts];
  if (parts.length !== 8) throw new Error(`Invalid IPv6 address: ${ip}`);
  return parts.reduce((acc, p) => (acc << 16n) | BigInt(parseInt(p, 16)), 0n);
}

function toBigInt(ip: string): { version: 4 | 6; value: bigint } | null {
  const n = normalizeIp(ip);
  if (isIPv4(n)) return { version: 4, value: ipv4ToBigInt(n) };
  if (isIPv6(n)) return { version: 6, value: ipv6ToBigInt(n) };
  return null;
}

export function parseCidr(cidr: string): Cidr {
  const [addr, prefixStr] = cidr.split("/");
  const parsed = toBigInt(addr ?? "");
  if (!parsed) throw new Error(`Invalid CIDR address: ${cidr}`);
  const bits = parsed.version === 4 ? 32 : 128;
  const prefix = prefixStr === undefined ? bits : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) throw new Error(`Invalid CIDR prefix: ${cidr}`);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
  return { version: parsed.version, network: parsed.value & mask, prefix };
}

export function cidrContains(cidr: Cidr, ip: string): boolean {
  const parsed = toBigInt(ip);
  if (!parsed || parsed.version !== cidr.version) return false;
  const bits = cidr.version === 4 ? 32 : 128;
  const mask = cidr.prefix === 0 ? 0n : ((1n << BigInt(cidr.prefix)) - 1n) << BigInt(bits - cidr.prefix);
  return (parsed.value & mask) === cidr.network;
}

export function isValidCidr(cidr: string): boolean {
  try {
    parseCidr(cidr);
    return true;
  } catch {
    return false;
  }
}
