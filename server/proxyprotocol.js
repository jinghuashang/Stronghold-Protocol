// server/proxyprotocol.js — the HAProxy PROXY protocol (v1 / v2) on the game's own TCP listener.
//
// Why it exists: the remake already honours the HTTP forwarding headers (net.js clientAddress: CF-Connecting-IP /
// X-Real-IP / rightmost X-Forwarded-For) — but only from a peer that is a local/private address (TRUST_PROXY 'auto'),
// and those headers can be forged by whoever can reach the port. An operator who terminates the connection on a
// load balancer (HAProxy, a frp/nginx stream listener, Cloudflare Spectrum, …) can instead have the balancer prepend
// the PROXY protocol header: the real client address arrives before any HTTP byte, on the same socket, and the header
// has no way to travel past the balancer (nobody else can inject it without being the balancer's own TCP peer).
//
// Wiring: when `PROXY_PROTOCOL` is on (see parseProxyProtocol), startServer listens on a net.Server created here
// instead of on the http.Server directly. For each socket this module reads the (optional) header, attaches
// `socket.proxyProtocol = { sourceIp, sourcePort, destinationIp, destinationPort, family, version }` and hands the
// *rest* of the stream to the http server (`httpServer.emit('connection', socket)`), which serves HTTP and the /ws
// upgrade from there as usual. net.js clientAddress prefers `socket.proxyProtocol.sourceIp` over every header.
//
// Header shapes (spec: haproxy.org/download/1.8/doc/proxy-protocol.txt):
//   v1: `PROXY TCP4 <src> <dst> <sport> <dport>\r\n` (or TCP6 / UNKNOWN), at most 107 bytes, ASCII, once.
//   v2: 12-byte signature `\r\n\r\n\0\r\nQUIT\n`, then ver/cmd, fam/proto, a 16-bit length, then 12 (IPv4) /
//       36 (IPv6) address bytes and optional TLVs (skipped by length).
// `UNKNOWN` (v1) and the LOCAL command (v2) carry no usable address: the connection keeps its own peer address
// (net.js), which is the balancer — exactly what the spec means by "no information".
//
// Failure policy: a connection that fails the header peek (garbage, an over-long v1 line, a truncated header that
// never arrives) is closed. With mode 'required' a connection without a header is closed too; with 'on' it is served
// as a direct client (handy when the port is reachable both through the balancer and directly).

import net from 'node:net';
import { isIP } from 'node:net';

/** Longest legal v1 line (`PROXY TCP6 <45> <45> <5> <5>\r\n` is 107 bytes; the spec caps it at 107). */
const V1_MAX = 107;
/** v2 signature, then 4 header bytes (ver/cmd, fam/proto, 2-byte length). */
const V2_SIGNATURE = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);
const V2_HEADER_LEN = 16;
/** The 5-byte ASCII prefix a v1 header starts with. */
const V1_PREFIX = Buffer.from('PROXY');

/** `PROXY_PROTOCOL` env / option → 'off' | 'on' | 'required' (anything unknown is off, the safe default). */
export function parseProxyProtocol(value) {
  const v = String(value ?? '').trim().toLowerCase();
  if (v === 'required' || v === 'require' || v === 'always') return 'required';
  if (v === 'on' || v === '1' || v === 'true' || v === 'yes' || v === 'auto') return 'on';
  return 'off';
}

/**
 * Where a PROXY header may come from. The protocol itself has no authentication: any client that can reach the port
 * can send one, so a public port would let anyone claim any source address (and dodge the per-network limits). The
 * header is therefore only honoured when the TCP peer is in this list — by default loopback, which covers the usual
 * deployment (the frp client / reverse proxy runs on the same machine). A balancer on another host: list its address
 * in `PROXY_PROTOCOL_TRUST` (e.g. `10.0.0.5,192.168.0.0/16`).
 */
export const PROXY_TRUST_DEFAULT = '127.0.0.1/8,::1/128';

/** `::ffff:1.2.3.4` → `1.2.3.4`; otherwise the input, trimmed and lower-cased. */
function plainIp(ip) {
  const s = String(ip || '').trim();
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(s);
  return (m ? m[1] : s).toLowerCase();
}

/** `a.b.c.d` or an IPv6 text form → a byte array (4 or 16), or null. */
function ipBytes(ip) {
  const s = plainIp(ip);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
    const parts = s.split('.').map(Number);
    if (parts.some((n) => n > 255)) return null;
    return Buffer.from(parts);
  }
  if (!s.includes(':')) return null;
  const [head, tail = ''] = s.split('::');
  const groups = (x) => (x ? x.split(':') : []);
  const h = groups(head), t = groups(tail);
  if (s.split('::').length > 2) return null;
  const filled = t.length ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : [...h, ...Array(8 - h.length).fill('0')];
  if (filled.length !== 8) return null;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(filled[i])) return null;
    out.writeUInt16BE(parseInt(filled[i], 16), i * 2);
  }
  return out;
}

/** One list entry (`1.2.3.4`, `10.0.0.0/8`, `::1`, `fd00::/8`) → `{ bytes, bits }` or null when malformed. */
function parseTrustEntry(raw) {
  const s = plainIp(raw);
  if (!s) return null;
  const [addr, prefix] = s.split('/');
  const bytes = ipBytes(addr);
  if (!bytes) return null;
  const max = bytes.length * 8;
  const bits = prefix === undefined ? max : Number(prefix);
  if (!Number.isInteger(bits) || bits < 0 || bits > max) return null;
  return { bytes, bits };
}

/**
 * Parse `PROXY_PROTOCOL_TRUST` (comma/space separated) into a list; entries that do not parse are ignored.
 * @param {string} [spec] @returns {{ entries: Array<{ bytes: Buffer, bits: number }>, valid: boolean }}
 */
export function parseTrustList(spec = PROXY_TRUST_DEFAULT) {
  const raw = String(spec ?? '').split(/[\s,]+/).filter(Boolean);
  const entries = [];
  let valid = raw.length > 0;
  for (const r of raw) {
    const e = parseTrustEntry(r);
    if (e) entries.push(e); else valid = false;
  }
  return { entries, valid };
}

/** Is `ip` (a socket peer address) inside the parsed trust list? */
export function ipInTrustList(ip, list) {
  const bytes = ipBytes(ip);
  if (!bytes) return false;
  for (const e of list.entries) {
    if (e.bytes.length !== bytes.length) continue;
    let ok = true;
    for (let i = 0; i < e.bits; i++) {
      const mask = 0x80 >> (i % 8);
      if ((bytes[i >> 3] & mask) !== (e.bytes[i >> 3] & mask)) { ok = false; break; }
    }
    if (ok) return true;
  }
  return false;
}

/** Parse one v1 line (`TCP4` / `TCP6` / `UNKNOWN`); returns matchProxyHeader's result shape. */
function parseV1(buf) {
  const nl = buf.indexOf(0x0a);
  if (nl < 0) return buf.length > V1_MAX ? { status: 'bad', reason: 'over-long' } : { status: 'need-more' };
  if (nl > V1_MAX) return { status: 'bad', reason: 'over-long' };
  let line = buf.subarray(0, nl).toString('latin1');
  if (line.endsWith('\r')) line = line.slice(0, -1);
  const parts = line.split(' ');
  if (parts[0] !== 'PROXY') return { status: 'bad', reason: 'bad-prefix' };
  const proto = parts[1] || '';
  if (proto === 'UNKNOWN') return { status: 'ok', info: null, length: nl + 1 };
  if (proto !== 'TCP4' && proto !== 'TCP6') return { status: 'bad', reason: 'bad-proto' };
  if (parts.length !== 6) return { status: 'bad', reason: 'bad-arity' };
  const [, , src, dst, sport, dport] = parts;
  const want = proto === 'TCP4' ? 4 : 6;
  if (isIP(src) !== want || isIP(dst) !== want) return { status: 'bad', reason: 'bad-address' };
  const p1 = Number(sport), p2 = Number(dport);
  if (!Number.isInteger(p1) || p1 < 0 || p1 > 65535 || !Number.isInteger(p2) || p2 < 0 || p2 > 65535) return { status: 'bad', reason: 'bad-port' };
  return {
    status: 'ok', length: nl + 1,
    info: { sourceIp: src, sourcePort: p1, destinationIp: dst, destinationPort: p2, family: want, version: 1 },
  };
}

/** Parse a v2 header (the signature must already match); `LOCAL`/`UNSPEC` carry no address. */
function parseV2(buf) {
  if (buf.length < V2_HEADER_LEN) return { status: 'need-more' };
  const verCmd = buf[12];
  const famProto = buf[13];
  const len = buf.readUInt16BE(14);
  if ((verCmd >> 4) !== 2) return { status: 'bad', reason: 'bad-version' };
  const cmd = verCmd & 0x0f;
  if (buf.length < V2_HEADER_LEN + len) return { status: 'need-more' };
  const body = buf.subarray(V2_HEADER_LEN, V2_HEADER_LEN + len);
  const length = V2_HEADER_LEN + len;
  if (cmd === 0) return { status: 'ok', info: null, length };            // LOCAL: a health check / the balancer itself
  if (cmd !== 1) return { status: 'bad', reason: 'bad-command' };
  const family = famProto >> 4;
  if (family === 0) return { status: 'ok', info: null, length };         // UNSPEC: no address information
  if (family === 1) {
    if (body.length < 12) return { status: 'bad', reason: 'short-ipv4' };
    const sourceIp = `${body[0]}.${body[1]}.${body[2]}.${body[3]}`;
    return {
      status: 'ok', length,
      info: { sourceIp, sourcePort: body.readUInt16BE(8), destinationIp: `${body[4]}.${body[5]}.${body[6]}.${body[7]}`, destinationPort: body.readUInt16BE(10), family: 4, version: 2 },
    };
  }
  if (family === 2) {
    if (body.length < 36) return { status: 'bad', reason: 'short-ipv6' };
    const ipOf = (b, o) => Array.from({ length: 8 }, (_, i) => b.readUInt16BE(o + i * 2).toString(16)).join(':');
    return {
      status: 'ok', length,
      info: { sourceIp: ipOf(body, 0), sourcePort: body.readUInt16BE(32), destinationIp: ipOf(body, 16), destinationPort: body.readUInt16BE(34), family: 6, version: 2 },
    };
  }
  return { status: 'bad', reason: 'bad-family' };
}

/**
 * Look at the first bytes of a connection that has not been read from yet.
 * @param {Buffer} buf bytes received so far
 * @returns {{ status: 'none' } | { status: 'need-more' } | { status: 'ok', info: object | null, length: number } | { status: 'bad', reason: string }}
 *   `ok` with `info: null` = a legal header that names no address (v1 UNKNOWN, v2 LOCAL/UNSPEC). `length` = header bytes.
 */
export function matchProxyHeader(buf) {
  if (!buf || buf.length === 0) return { status: 'need-more' };
  const n = buf.length;
  if (buf.subarray(0, Math.min(n, V1_PREFIX.length)).equals(V1_PREFIX.subarray(0, Math.min(n, V1_PREFIX.length))) && n < V1_PREFIX.length) return { status: 'need-more' };
  if (buf.subarray(0, V1_PREFIX.length).equals(V1_PREFIX)) return parseV1(buf);
  const sig = buf.subarray(0, Math.min(n, V2_SIGNATURE.length));
  if (sig.equals(V2_SIGNATURE.subarray(0, sig.length))) return parseV2(buf);      // a full or partial signature
  return { status: 'none' };                                        // a plain HTTP request (GET/POST/…) or a TLS record
}

/** How long a socket may stay silent in 'on' before it is treated as a plain client (see readProxyHeader). */
const PLAIN_GRACE_MS = 750;

/**
 * Read the optional header from a freshly accepted (paused) socket and hand the rest of the stream to `onReady`.
 * The leftover bytes are pushed back with `socket.unshift`, so the http server parses exactly the original stream.
 *
 * 'required' waits `timeoutMs` for the header and closes a socket that never produces one. 'on' is forgiving: the
 * first byte decides (a PROXY header is parsed, anything else is a plain client), and a socket that sends *nothing*
 * within `graceMs` (a tunnel's health check, a browser's pre-connect, a client that waits for the server to speak) is
 * handed to the http server as a direct client — the server's own idle/header timeouts own it from there. Killing
 * those silent sockets (the old behaviour) broke pre-connected clients and flooded the log.
 * @param {net.Socket} socket @param {'on' | 'required'} mode
 * @param {{ timeoutMs?: number, graceMs?: number, onHeader?: (info: object | null, socket: net.Socket) => void, log?: object }} [opts]
 * @returns {Promise<object | null>} resolves with the parsed info (or null) once the socket may be consumed
 */
export function readProxyHeader(socket, mode, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const graceMs = Math.min(opts.graceMs ?? (mode === 'required' ? timeoutMs : PLAIN_GRACE_MS), timeoutMs);
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    let settled = false;
    const cleanup = () => {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
      clearTimeout(timer);
      clearTimeout(hardTimer);
    };
    const finish = (info, leftover) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (leftover && leftover.length) socket.unshift(leftover);
      if (opts.onHeader) { try { opts.onHeader(info, socket); } catch (e) { opts.log?.warn?.('[proxy] onHeader failed', e); } }
      resolve(info);
    };
    const fail = (reason) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error(reason));
    };
    const onData = (chunk) => {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      const m = matchProxyHeader(buf);
      if (m.status === 'need-more') {
        if (buf.length > V1_MAX + V2_HEADER_LEN + 65535) fail('header too long');
        return;
      }
      if (m.status === 'ok') {
        if (opts.trusted === false) { fail('proxy protocol header from an untrusted peer'); return; }
        // stop reading before the http server takes over: further chunks wait in the kernel, so the leftover bytes
        // unshifted below are the first thing the parser sees (order preserved)
        socket.pause();
        finish(m.info, buf.subarray(m.length));
        return;
      }
      if (m.status === 'none') {
        if (mode === 'required') { fail('missing proxy protocol header'); return; }
        socket.pause();
        finish(null, buf);
        return;
      }
      fail(`malformed proxy protocol header (${m.reason})`);
    };
    const onError = (e) => fail(`socket error: ${e?.code || e?.message || 'error'}`);
    const onClose = () => fail('socket closed before the proxy protocol header');
    const onGrace = () => {
      if (mode !== 'required' && buf.length === 0) {
        opts.log?.debug?.(`[proxy] no header within ${graceMs} ms: serving the socket as a direct client`);
        socket.pause();
        finish(null, null);
        return;
      }
      fail('proxy protocol header timeout');       // 'required' silence, or a header that never completes
    };
    const timer = setTimeout(onGrace, graceMs);
    const hardTimer = graceMs < timeoutMs ? setTimeout(() => fail('proxy protocol header timeout'), timeoutMs) : null;
    timer.unref?.();
    hardTimer?.unref?.();
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
    socket.resume();
  });
}

/**
 * A net.Server that peeks the PROXY protocol header and then feeds the socket to `httpServer` (HTTP + /ws upgrade
 * both travel through it). Listen on the returned server instead of the http server; everything else is unchanged —
 * the http server keeps its request listener, `clientError` handler, `upgrade` handling and admission checks.
 * The header is only honoured from a peer inside `trust` (see PROXY_TRUST_DEFAULT): elsewhere it is refused, because
 * anyone who can reach the port could otherwise claim a source address.
 * @param {import('node:http').Server} httpServer
 * @param {{ mode?: 'on' | 'required', log?: object, timeoutMs?: number, graceMs?: number,
 *           trust?: ReturnType<typeof parseTrustList> }} [opts]
 */
export function createProxyProtocolListener(httpServer, opts = {}) {
  const mode = opts.mode === 'required' ? 'required' : 'on';
  const log = opts.log || null;
  const trust = opts.trust ?? parseTrustList(PROXY_TRUST_DEFAULT);
  // allowHalfOpen like the http server's own listener: a client that sends its request and half-closes (FIN) must
  // still get the answer — with the net.Server default (false) the socket would be ended before the response.
  const listener = net.createServer({ pauseOnConnect: true, allowHalfOpen: true }, (socket) => {
    socket.on('error', () => {});                       // a client that vanishes mid-header must not crash the server
    readProxyHeader(socket, mode, {
      timeoutMs: opts.timeoutMs,
      graceMs: opts.graceMs,
      trusted: ipInTrustList(socket.remoteAddress, trust),
      log,
      onHeader: (info, s) => { if (info) s.proxyProtocol = info; },
    }).then(() => {
      httpServer.emit('connection', socket);
      socket.resume();                                  // the http parser pulls what it needs; resume so it can
    }).catch((e) => {
      // a probe that connects and closes (tunnel health checks) is normal: keep the log quiet for it
      if (log) {
        if (/closed before the proxy protocol header/.test(e.message)) log.debug?.(`[proxy] ${e.message}`);
        else log.warn(`[proxy] ${e.message}`);
      }
      socket.destroy();
    });
  });
  listener.on('error', (e) => { if (log) log.error('[proxy] listener error', e); });
  return listener;
}
