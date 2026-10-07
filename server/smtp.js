// server/smtp.js — the minimal SMTP client the account mails need (the e-mail verification code), on node:net /
// node:tls only (the project may not add npm dependencies, DESIGN §1).
//
// Why hand-rolled: the two things accounts.js needs are "is the relay usable right now?" (`verify`) and "deliver one
// line of text" (`send`), which is ~200 lines of a protocol that has not changed since 1982 and that we only ever use
// in one shape: connect → EHLO → (STARTTLS) → (AUTH) → MAIL FROM → RCPT TO → DATA → QUIT. Every send opens its own
// connection — no pool: a code is sent once per registration attempt, so a pool would be dead weight, and a fresh
// connection always sees the relay's current state (a stale pooled connection is the classic way to lose a mail).
//
// TLS: `secure: true` (port 465) connects with TLS straight away; otherwise the link starts plain and is upgraded via
// STARTTLS whenever the relay advertises it (port 587 — the default here). A relay that offers no STARTTLS is used in
// the clear, but **AUTH over a cleartext link is refused** unless `allowInsecureAuth` is set: it would put the SMTP
// password on the wire for anyone on the path (the test suite's fake relay uses that flag on purpose, DESIGN §25).
// `rejectUnauthorized: false` is for a relay with a self-signed certificate on a private network; it is off by default.
//
// Errors: a failure rejects with an Error whose message names the stage and quotes the relay
// (`smtp: RCPT TO rejected: 550 5.1.1 no such user`). That message is what the account log shows and what the player
// sees as 「邮件发送失败，请稍后再试」. `verify()` never throws: it answers `{ ok: true }` or `{ ok: false, error }`,
// so a boot check can print it.
//
// Reply reading is line-based: a reply is complete at a `NNN ` / `NNN` line (multi-line replies use `NNN-…`), and DATA
// is written whole — a base64 body (7-bit safe, and 8-bit relays are then irrelevant) — followed by CRLF.CRLF.

import net from 'node:net';
import tls from 'node:tls';
import { randomBytes } from 'node:crypto';

const CRLF = '\r\n';
/** Connect/greeting/EHLO/… deadline: one value for the whole conversation (a code mail must not hang a request). */
export const SMTP_TIMEOUT_MS = 12_000;
/** The host name we introduce ourselves with when the caller names none. */
const DEFAULT_CLIENT_NAME = 'stronghold-protocol.local';
/** SMTP_* environment keys, in the order the config error lists them. */
export const SMTP_ENV_KEYS = Object.freeze(['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM']);

/** `SMTP_SECURE`/`secure` as a boolean: 1/true/yes/on ⇒ true (implicit TLS), 0/false/no/off/starttls ⇒ false. */
const asBool = (v) => /^(1|true|yes|on)$/i.test(String(v ?? '').trim());
const unset = (v) => typeof v !== 'string' || v.trim() === '';

/**
 * Read the SMTP configuration out of an environment (default `process.env`).
 *
 * `missing` lists the settings that are absent while *something* else is set (the "half configured" case the account
 * feature must refuse), `invalid` the ones whose value cannot be used, and `anySet` whether any SMTP_* key is present
 * at all — the difference between "SMTP is simply not configured here" and "SMTP is misconfigured".
 * `options` is ready for {@link createSmtp} once `missing` and `invalid` are empty.
 *
 * @param {Record<string, string | undefined>} [env]
 * @returns {{ options: object, host: string, port: number, secure: boolean, user: string, pass: string, from: string,
 *   missing: string[], invalid: string[], anySet: boolean }}
 */
export function smtpOptionsFromEnv(env = process.env) {
  const get = (k) => (unset(env?.[k]) ? '' : String(env[k]).trim());
  const host = get('SMTP_HOST');
  const from = get('SMTP_FROM');
  const user = get('SMTP_USER');
  const pass = get('SMTP_PASS');
  const portRaw = get('SMTP_PORT');
  const secureRaw = get('SMTP_SECURE');
  const anySet = SMTP_ENV_KEYS.some((k) => get(k) !== '');

  const missing = [];
  if (!host) missing.push('SMTP_HOST');
  if (!from) missing.push('SMTP_FROM');
  if (user && !pass) missing.push('SMTP_PASS');
  if (pass && !user) missing.push('SMTP_USER');

  const invalid = [];
  let port = portRaw ? Number(portRaw) : 0;
  if (portRaw && (!Number.isInteger(port) || port < 1 || port > 65535)) { invalid.push('SMTP_PORT'); port = 0; }
  // Default port by transport: implicit TLS is 465, STARTTLS 587.
  const secure = secureRaw ? asBool(secureRaw) : port === 465;
  if (!port) port = secure ? 465 : 587;
  if (from && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(from)) invalid.push('SMTP_FROM');

  return {
    options: { host, port, secure, user, pass, from, rejectUnauthorized: true },
    host, port, secure, user, pass, from, missing, invalid, anySet,
  };
}

/** One line of an SMTP reply that ends a reply (`250 …`); `250-…` continues it. */
const REPLY_END = /^\d{3}(?:[ ]|$)/;
const REPLY_CODE = /^(\d{3})/;
/** One encoded word carries this many UTF-8 bytes: enough that every subject we send stays a single word (§25.3). */
const HEADER_WORD_MAX_BYTES = 150;

/**
 * An RFC 5322 header value, RFC 2047 encoded when it cannot travel as plain ASCII. A long value is split into several
 * encoded words **at character boundaries**: a word that cuts a multi-byte character in half decodes to mojibake in
 * every mail client, which is exactly what a naive base64 slice does (each word is ≤ 45 chars of base64 = 60 encoded
 * characters, comfortably under the 75-character limit, and every word decodes on its own).
 */
function encodeHeader(value) {
  const s = String(value ?? '');
  if (/^[\x20-\x7e]*$/.test(s) && s.length <= 75) return s;
  const words = [];
  let buf = '';
  for (const ch of s) {
    // UTF-8 bytes of the *whole* characters of the current word: never cut a character in half.
    if (Buffer.byteLength(buf + ch, 'utf8') > HEADER_WORD_MAX_BYTES) { words.push(buf); buf = ch; } else buf += ch;
  }
  if (buf) words.push(buf);
  return words.map((w) => `=?UTF-8?B?${Buffer.from(w, 'utf8').toString('base64')}?=`).join(`${CRLF} `);
}

/** `Name <addr@host>` with the display name encoded when it is not plain ASCII (an address alone passes through). */
function encodeFrom(value) {
  const s = String(value ?? '');
  const m = /^(.*?)\s*<([^>]*)>$/.exec(s);
  if (!m) return s;
  const name = m[1].trim().replace(/^"|"$/g, '');
  return name ? `${encodeHeader(name)} <${m[2]}>` : `<${m[2]}>`;
}

/** base64 body, wrapped at 76 chars. */
function base64Body(text) {
  const b64 = Buffer.from(String(text ?? ''), 'utf8').toString('base64');
  const lines = [];
  for (let i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76));
  return lines.join(CRLF);
}

/** The RFC 5322 message one verification code needs (headers + a base64 body, so 8-bit relays cannot bite). */
export function buildMail({ from, to, subject, text }) {
  const domain = String(from).split('@')[1] || 'stronghold-protocol.local';
  const headers = [
    `From: ${encodeFrom(from)}`,
    `To: ${to}`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${randomBytes(12).toString('hex')}@${domain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
  ];
  return `${headers.join(CRLF)}${CRLF}${CRLF}${base64Body(text)}`;
}

/** A socket that speaks SMTP replies: it buffers the inbound half and hands out whole replies one at a time. */
class SmtpSession {
  constructor(socket, { timeoutMs, label }) {
    this.socket = socket;
    this.label = label;
    this.buf = '';
    this.lines = [];
    this.waiting = null;   // { resolve, reject } of the reply we are waiting for
    this.closed = null;    // the error a close/error left behind
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => this.feed(chunk));
    socket.on('error', (err) => this.fail(new Error(`${label}: ${err.message}`)));
    socket.on('close', () => this.fail(new Error(`${label}: connection closed`)));
    socket.on('timeout', () => {
      socket.destroy();
      this.fail(new Error(`${label}: timeout after ${timeoutMs} ms`));
    });
    socket.setTimeout(timeoutMs);
  }

  feed(chunk) {
    this.buf += chunk;
    let nl;
    while ((nl = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, nl).replace(/\r$/, '');
      this.buf = this.buf.slice(nl + 1);
      this.lines.push(line);
      if (REPLY_END.test(line)) {
        const reply = { code: Number((REPLY_CODE.exec(line) || [0, '0'])[1]), text: this.lines.join('\n') };
        this.lines = [];
        const w = this.waiting;
        this.waiting = null;
        if (w) w.resolve(reply);
      }
    }
  }

  /** Fail every pending and future read with one error (the socket is gone). */
  fail(err) {
    if (this.closed) return;
    this.closed = err;
    const w = this.waiting;
    this.waiting = null;
    if (w) w.reject(err);
  }

  /** The next complete reply. Only one read may be outstanding (the protocol is strictly request/response). */
  read() {
    if (this.waiting) return Promise.reject(new Error(`${this.label}: overlapping reads`));
    if (this.closed) return Promise.reject(this.closed);
    return new Promise((resolve, reject) => { this.waiting = { resolve, reject }; });
  }

  write(text) {
    if (this.closed) throw this.closed;
    this.socket.write(text);
  }

  /** Send one command and read its reply. */
  async cmd(line) {
    this.write(`${line}${CRLF}`);
    return await this.read();
  }

  /** Send a command whose reply code must be `want` (a Set of accepted codes); returns the reply. */
  async expect(line, want, stage) {
    const reply = await this.cmd(line);
    if (!want.includes(reply.code)) throw new Error(`${this.label}: ${stage || line} rejected: ${reply.text.split('\n')[0]}`);
    return reply;
  }

  destroy() {
    try { this.socket.destroy(); } catch { /* already gone */ }
  }
}

/** Open the TCP/TLS link and hand back a session whose first reply (the 220 greeting) is already read. */
async function openSession({ host, port, secure, rejectUnauthorized, timeoutMs, label }) {
  const socket = await new Promise((resolve, reject) => {
    const opts = { host, port, rejectUnauthorized };
    const sock = secure ? tls.connect({ ...opts, servername: host }) : net.connect(opts);
    const timer = setTimeout(() => {
      try { sock.destroy(); } catch { /* ignore */ }
      reject(new Error(`${label}: connect timeout after ${timeoutMs} ms`));
    }, timeoutMs);
    timer.unref?.();
    const ready = () => { clearTimeout(timer); resolve(sock); };
    const fail = (err) => { clearTimeout(timer); reject(new Error(`${label}: connect failed: ${err.message}`)); };
    sock.once(secure ? 'secureConnect' : 'connect', ready);
    sock.once('error', fail);
  });
  // Note: the one-shot 'error' listener stays — it can only fire on an error, and by then the promise is settled.
  const session = new SmtpSession(socket, { timeoutMs, label });
  const greeting = await session.read();
  if (greeting.code !== 220) throw new Error(`${label}: greeting: ${greeting.text.split('\n')[0]}`);
  return session;
}

/** Upgrade a plain session to TLS (STARTTLS): the same socket, wrapped, then EHLO again. */
async function startTls(session, { host, rejectUnauthorized, timeoutMs, label }) {
  await session.expect('STARTTLS', [220], 'STARTTLS');
  const socket = session.socket;
  socket.removeAllListeners('data');
  socket.removeAllListeners('error');
  socket.removeAllListeners('close');
  socket.removeAllListeners('timeout');
  const secured = await new Promise((resolve, reject) => {
    const s = tls.connect({ socket, servername: host, rejectUnauthorized });
    const timer = setTimeout(() => { try { s.destroy(); } catch { /* ignore */ } reject(new Error(`${label}: TLS handshake timeout`)); }, timeoutMs);
    timer.unref?.();
    s.once('secureConnect', () => { clearTimeout(timer); resolve(s); });
    s.once('error', (err) => { clearTimeout(timer); reject(new Error(`${label}: TLS handshake failed: ${err.message}`)); });
  });
  return new SmtpSession(secured, { timeoutMs, label });
}

/** The EHLO greeting, with the extensions the relay advertises (uppercased tokens, e.g. `STARTTLS`, `AUTH PLAIN LOGIN`). */
async function hello(session, clientName) {
  const reply = await session.expect(`EHLO ${clientName}`, [250], 'EHLO');
  return reply.text.split('\n').map((l) => l.replace(/^\d{3}[ -]/, '').trim().toUpperCase());
}

/** AUTH: PLAIN when the relay lists it, else LOGIN. Cleartext AUTH is refused unless `allowInsecureAuth`. */
async function authenticate(session, { user, pass, mechanisms, tls: secured, allowInsecureAuth, label }) {
  if (!user && !pass) return;
  if (!mechanisms.length) throw new Error(`${label}: the relay offers no AUTH`);
  if (!secured && !allowInsecureAuth) {
    throw new Error(`${label}: refusing to send the SMTP credentials over a cleartext connection (STARTTLS unavailable; set allowInsecureAuth for a trusted local relay)`);
  }
  const offers = (mech) => mechanisms.some((m) => m === mech || (m.startsWith('AUTH ') && m.slice(5).split(/[\s=]/).includes(mech)));
  if (offers('PLAIN')) {
    const blob = Buffer.from(`\u0000${user}\u0000${pass}`, 'utf8').toString('base64');
    await session.expect(`AUTH PLAIN ${blob}`, [235], 'AUTH PLAIN');
    return;
  }
  if (offers('LOGIN')) {
    await session.expect('AUTH LOGIN', [334], 'AUTH LOGIN');
    await session.expect(Buffer.from(user, 'utf8').toString('base64'), [334], 'AUTH LOGIN user');
    await session.expect(Buffer.from(pass, 'utf8').toString('base64'), [235], 'AUTH LOGIN password');
    return;
  }
  throw new Error(`${label}: the relay offers no supported AUTH mechanism (${mechanisms.join(', ')})`);
}

/** The extension lines of EHLO that name AUTH (`AUTH PLAIN LOGIN`). */
const authLines = (ext) => ext.filter((e) => e === 'AUTH' || e.startsWith('AUTH '));

/**
 * Create the SMTP client.
 *
 * @param {{ host: string, port?: number, secure?: boolean, user?: string, pass?: string, from?: string,
 *   rejectUnauthorized?: boolean, allowInsecureAuth?: boolean, timeoutMs?: number, clientName?: string,
 *   log?: { warn: Function } }} opts
 * @returns {{
 *   verify: () => Promise<{ ok: true } | { ok: false, error: string }>,
 *   send: (mail: { to: string, subject: string, text: string, from?: string }) => Promise<{ ok: true }>,
 *   config: { host: string, port: number, secure: boolean, user: string, from: string },
 * }}
 */
export function createSmtp({ host, port, secure = false, user = '', pass = '', from = '', rejectUnauthorized = true, allowInsecureAuth = false, timeoutMs = SMTP_TIMEOUT_MS, clientName = DEFAULT_CLIENT_NAME, log = null } = {}) {
  if (typeof host !== 'string' || !host) throw new Error('smtp: host is required');
  const label = `smtp ${host}:${port || (secure ? 465 : 587)}`;

  /** Connect, greet, EHLO, STARTTLS when offered, AUTH. Returns the ready session and what it negotiated. */
  async function open({ needAuth = true } = {}) {
    const opts = { host, port: port || (secure ? 465 : 587), secure: !!secure, rejectUnauthorized, timeoutMs, label };
    let session = await openSession(opts);
    let extended = await hello(session, clientName);
    let secured = !!secure;
    if (!secured && extended.includes('STARTTLS')) {
      session = await startTls(session, { host, rejectUnauthorized, timeoutMs, label });
      secured = true;
      extended = await hello(session, clientName);
    } else if (!secured) {
      log?.warn?.(`[smtp] ${host}: the relay does not advertise STARTTLS`);
    }
    if (needAuth && (user || pass)) {
      await authenticate(session, { user, pass, mechanisms: authLines(extended), tls: secured, allowInsecureAuth, label });
    }
    return { session, extended, secured };
  }

  /** Is the relay usable right now? Never throws. */
  async function verify() {
    let ready = null;
    try {
      ready = await open({ needAuth: false });
      // A real AUTH matters to the startup check: a wrong password must be reported now, not on the first sign-up.
      if (user || pass) {
        await authenticate(ready.session, { user, pass, mechanisms: authLines(ready.extended), tls: ready.secured, allowInsecureAuth, label });
      }
      await ready.session.cmd('QUIT').catch(() => {});
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err?.message || String(err) };
    } finally {
      ready?.session.destroy();
    }
  }

  /** Deliver one message. Throws an Error with the relay's own words on any failure. */
  async function send({ to, subject, text, from: sender } = {}) {
    if (typeof to !== 'string' || !to) throw new Error('smtp: `to` is required');
    const envelopeFrom = sender || from;
    if (!envelopeFrom) throw new Error('smtp: no From address configured');
    const { session } = await open();
    try {
      await session.expect(`MAIL FROM:<${envelopeFrom}>`, [250], 'MAIL FROM');
      await session.expect(`RCPT TO:<${to}>`, [250, 251], 'RCPT TO');
      await session.expect('DATA', [354], 'DATA');
      const mail = buildMail({ from: envelopeFrom, to, subject, text });
      // Dot-stuffing: a body line that is a single '.' would end the DATA block early (base64 never produces one, the
      // guard costs nothing and survives a future plain-text template).
      session.write(`${mail.replace(/\r?\n\./g, `${CRLF}..`)}${CRLF}.${CRLF}`);
      const done = await session.read();
      if (done.code !== 250) throw new Error(`${label}: DATA rejected: ${done.text.split('\n')[0]}`);
      await session.cmd('QUIT').catch(() => {});
      return { ok: true };
    } finally {
      session.destroy();
    }
  }

  return { verify, send, config: { host, port: port || (secure ? 465 : 587), secure: !!secure, user, from } };
}
