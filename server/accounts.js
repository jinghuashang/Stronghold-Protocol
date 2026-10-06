// server/accounts.js — accounts, the stable playerId a seat follows across devices, and the e-mail verification code
// registration is gated on (DESIGN §25).
//
// Why accounts exist: a session's playerId is minted per connection (server/net.js SessionRegistry.create) and a room
// seat is keyed by that playerId (server/lobby.js), so a phone cannot inherit what a desktop holds. An account gives
// the player a playerId that outlives every connection: the server verifies the account token carried by `hello.auth`
// (or issued by `auth.login` / `auth.register`), binds its session to `account.playerId`, and the seat follows — the
// other device's socket is closed with 4001 (the client already says 该身份已在其他页面登录) while this one gets
// `welcome { resumed }` plus the lobby's full resync, so it continues the same 局. Account playerIds are `a_…` while
// session ids are `p_…`, so the two can never collide and a guest session can never be mistaken for an account's.
//
// Identity: the **e-mail address** is the account key (normalized: trimmed + lowercased; `name@domain.tld`).
// `name` (昵称) is the display name on seats and is deliberately NOT unique — two players may be 博士, and registration
// cannot fail on a name somebody else chose. `playerId` is the stable id above, and `hash`/`salt` are the password.
//
// Registration is two steps and the account only exists after the second one:
//   1. `requestCode(email, { ip })` mails a 6-digit code. Only `sha256(code + salt)` is kept, in memory (10 minutes,
//      one use, five wrong tries void it — a code is not worth persisting: a server restart simply means requesting a
//      new one [ASSUMED]). Throttles: one code per address per minute, ≤5 per hour per address, ≤20 per hour per
//      client address. An address that already has an account is refused here (`email_taken`) — the alternative is a
//      user who goes through the whole flow only to be told at the end, and the register step discloses it anyway.
//   2. `register({ email, code, name, password })` consumes the code, hashes the password, and answers a token.
// The same machinery with `purpose: 'reset'` is the way back into an account (`requestResetCode` / `resetPassword`,
// §25.8): codes of the two purposes are stored apart, so a registration code can never reset a password; a reset
// revokes every token the account had — the other devices are signed out — and the reset itself is a login.
// `login({ email, password })` needs no code; an unknown address and a wrong password answer the same
// `bad_credentials`, and an unknown address still derives a key against a throwaway record so the reply time cannot
// tell them apart.
//
// What is stored — `data/accounts.json`, rewritten atomically (temp file + rename in the same directory, so a reader
// sees the old or the new file, never a half-written one):
//   { version: 1, accounts: { [playerId]: {
//       playerId, email, name, createdAt, lastSeenAt, lastLoginAt,   // email = the account key, name = the nickname
//       salt, hash,                                                  // scrypt(password, salt) — never the password
//       tokens: [{ hash, createdAt, lastSeenAt }],                   // sha256(token) — never the token itself
//   } } }
// A leaked file therefore reveals no password and no usable token. Tokens are 32 random bytes, base64url (43 chars,
// ≤ ACCOUNT.tokenMaxLen); an account keeps at most ACCOUNT.tokens = 5 and issuing a 6th evicts the oldest, which is
// the only expiry besides `auth.logout` ([ASSUMED]).
//
// Passwords use scrypt (N=16384, r=8, p=1, 32 bytes; 16 MiB, node's default maxmem) with a per-account 16-byte salt and
// are compared with crypto.timingSafeEqual. Codes are compared with timingSafeEqual too (their hash is sha256).
//
// Concurrency: `requestCode` / `register` / `login` are async (scrypt and SMTP both wait; a sign-in must never stall a
// running match), so an address is reserved synchronously before either wait. `verify` / `verifyCode` / `logout` /
// `stats` are synchronous — a `hello` has to be answered in the tick it arrived. `lastSeenAt` touches are coalesced
// into at most one write per second (`flush()` writes immediately; call it on shutdown).
//
// The SMTP relay is injected (`createAccounts({ file, smtp, log })`): the account feature is off unless the operator
// configured one, and `accountsConfigState(env)` (below) is what server/index.js asks before wiring any of this.

import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes, randomInt, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { ACCOUNT, EMAIL_RE } from '../shared/protocol.js';
import { DATA_DIR } from './data.js';
import { sanitizeName } from './net.js';
import { smtpOptionsFromEnv } from './smtp.js';

/** scrypt parameters (cost; r×N×128 = 16 MiB, under node's default maxmem). */
const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, keylen: 32 });
const scrypt = promisify(scryptCb);
const FILE_VERSION = 1;
/** Coalesce `verify` touches into one write per second (a match must not write a file per hello). */
const TOUCH_WRITE_MS = 1000;
/** The throwaway record an unknown-address login derives against (fixed salt: the timing must not depend on it). */
const DUMMY_SALT = Buffer.from('5e1f0b2c8a7d4319', 'hex');
const DUMMY_HASH = Buffer.alloc(SCRYPT.keylen);
const noopLog = { info() {}, warn() {}, error() {}, debug() {} };

/** Modes of the account feature (`ACCOUNTS` env, DESIGN §25): registration/sign-in are **opt-in**. */
export const ACCOUNTS_MODES = Object.freeze(['off', 'auto', 'on']);

/**
 * `ACCOUNTS` as one of the three modes. Anything that is not an explicit request to enable the feature is `off`: unset,
 * empty, `off`/`0`/`no`/`false` and every unrecognised value (a typo must never switch a password system on).
 * `on` (and its old alias `required`, plus `1`/`true`/`yes`) asks for accounts and refuses to start without SMTP;
 * `auto` enables them only when the SMTP settings are complete. `required` is reported as `on`.
 * @param {unknown} raw
 * @returns {'off' | 'auto' | 'on'}
 */
export function accountsMode(raw) {
  const v = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (v === 'on' || v === 'required' || v === '1' || v === 'true' || v === 'yes') return 'on';
  if (v === 'auto') return 'auto';
  return 'off';
}

/**
 * Resolve the account feature's configuration from an environment (server/index.js calls this before starting).
 *
 * `off` (**the default**) — the feature is off: no store, no mail, and `auth.*` must answer `accounts_disabled` so the
 * browser hides the panel and only offers 游客开始.
 * `on` (alias `required`) — the operator asked for accounts: a complete SMTP configuration enables them, an incomplete
 * one is a startup error the caller must print and exit on (no server players cannot register on).
 * `auto` — the SMTP settings decide: complete ⇒ enabled; none ⇒ off (an operator may log a hint); incomplete ⇒ off with
 * an `error` reported as a warning (a *half* configuration is a mistake, not an unconfigured feature).
 *
 * @param {Record<string, string | undefined>} [env]
 * @returns {{ enabled: boolean, mode: 'off' | 'auto' | 'on', smtp: object | null, smtpConfig: object,
 *   missing: string[], invalid: string[], error: string | null }}
 */
export function accountsConfigState(env = process.env) {
  const mode = accountsMode(env?.ACCOUNTS);
  const smtpConfig = smtpOptionsFromEnv(env);
  const complete = smtpConfig.missing.length === 0 && smtpConfig.invalid.length === 0;
  const why = smtpConfig.invalid.length
    ? `invalid ${smtpConfig.invalid.join(', ')}`
    : `missing ${smtpConfig.missing.join(', ')}`;
  const base = { enabled: false, mode, smtp: null, smtpConfig, missing: smtpConfig.missing, invalid: smtpConfig.invalid, error: null };
  if (mode === 'off') return base;
  if (complete) return { ...base, enabled: true, smtp: smtpConfig.options };
  const way = '（或设 ACCOUNTS=off 关闭账号功能 / set ACCOUNTS=off to disable accounts）';
  if (mode === 'on') {
    return { ...base, error: `accounts require SMTP: ${why}. 账号注册需要 SMTP 配置：${why}。${way}` };
  }
  return smtpConfig.anySet ? { ...base, error: `accounts disabled: incomplete SMTP configuration (${why})` } : base;
}

/** A fresh account token: 32 random bytes, base64url (what the browser stores and sends back as `hello.auth`). */
export const newAccountToken = () => randomBytes(32).toString('base64url');

/** sha256(token), hex — the only form of a token that is ever stored or compared. @param {string} token */
export const accountTokenHash = (token) => createHash('sha256').update(String(token), 'utf8').digest('hex');

/** sha256(code + salt), hex — what a pending verification code is stored as. @param {string} code @param {Buffer} salt */
const codeHash = (code, salt) => createHash('sha256').update(`${code}:`, 'utf8').update(salt).digest('hex');

/**
 * The account key of an address: trimmed and lowercased (mail addresses are case-insensitive in practice), or null
 * when the address cannot be one.
 * @param {unknown} raw
 * @returns {string | null}
 */
export function normalizeEmail(raw) {
  if (typeof raw !== 'string') return null;
  const email = raw.trim().toLowerCase();
  if (!email || email.length > ACCOUNT.emailMax || !EMAIL_RE.test(email)) return null;
  return email;
}

/**
 * The nickname an account registers with: net.js's `sanitizeName` (NFC, control/invisible characters stripped,
 * whitespace collapsed, trimmed) bounded by ACCOUNT.nameMin..nameMax. Returns null when the input cannot be one.
 * @param {unknown} raw
 * @returns {string | null}
 */
export function normalizeNickname(raw) {
  if (typeof raw !== 'string') return null;
  // A raw name longer than the cap would be truncated by sanitizeName — refuse instead of silently renaming.
  if ([...raw.normalize('NFC').trim()].length > ACCOUNT.nameMax) return null;
  const name = sanitizeName(raw);
  if (!name || [...name].length < ACCOUNT.nameMin || [...name].length > ACCOUNT.nameMax) return null;
  return name;
}

/** True for a legal *new* password (see ACCOUNT). @param {unknown} raw */
export const validAccountPassword = (raw) => typeof raw === 'string'
  && [...raw].length >= ACCOUNT.passwordMin && [...raw].length <= ACCOUNT.passwordMax;

/** scrypt a password into a raw key. @param {string} password @param {Buffer} salt @returns {Promise<Buffer>} */
const derive = (password, salt) => scrypt(password.normalize('NFC'), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });


/**
 * Account store.
 *
 * @param {{
 *   file?: string,
 *   smtp?: { send: (mail: { to: string, subject: string, text: string }) => Promise<unknown> } | null,
 *   log?: { info: Function, warn: Function, error: Function, debug?: Function },
 *   now?: () => number,
 * }} [opts] `file` default: `data/accounts.json` (created on the first write); `smtp` is injected (tests, and the
 *   configured relay in server/index.js); `now` is injectable for tests.
 * @returns {{
 *   requestCode: (email: unknown, opts?: { ip?: string | null }) => Promise<{ ok: true, ttlSec: number } | { ok: false, error: string }>,
 *   requestResetCode: (email: unknown, opts?: { ip?: string | null }) => Promise<{ ok: true, ttlSec: number } | { ok: false, error: string }>,
 *   verifyCode: (email: unknown, code: unknown) => { ok: true } | { ok: false, error: 'code_expired' | 'bad_code' | 'bad_email' },
 *   register: (input: { email: unknown, code: unknown, name: unknown, password: unknown }) => Promise<{ ok: true, playerId: string, token: string, name: string, email: string } | { ok: false, error: string }>,
 *   login: (input: { email: unknown, password: unknown }) => Promise<{ ok: true, playerId: string, token: string, name: string, email: string } | { ok: false, error: 'bad_credentials' }>,
 *   resetPassword: (input: { email: unknown, code: unknown, password: unknown }) => Promise<{ ok: true, playerId: string, token: string, name: string, email: string } | { ok: false, error: string }>,
 *   logout: (token: unknown) => boolean,
 *   verify: (token: unknown) => { playerId: string, name: string, email: string } | null,
 *   stats: () => { accounts: number, tokens: number, codes: number },
 *   flush: () => boolean,
 *   file: string,
 *   smtp: object | null,
 * }}
 */
export function createAccounts({ file = path.join(DATA_DIR, 'accounts.json'), smtp = null, log = noopLog, now = Date.now } = {}) {
  /** @type {Map<string, any>} playerId → account record */
  const byId = new Map();
  /** @type {Map<string, string>} normalized email → playerId */
  const byEmail = new Map();
  /** @type {Map<string, { account: any, record: any }>} sha256(token) → the account and token record it belongs to */
  const byToken = new Map();
  /** @type {Map<string, any>} normalized email → the pending verification code (in memory, see the header) */
  const codes = new Map();
  /** emails with a register in flight (scrypt / SMTP running): reserved synchronously so two cannot both win. */
  const pending = new Set();
  /** @type {Map<string, number[]>} normalized email / `ip:…` → the ms timestamps of the codes sent within the hour */
  const sentLog = new Map();
  let touchDirty = false;
  let touchTimer = null;

  // ---- pending codes ---------------------------------------------------------------------------------------

  /** The codes sent in the last hour for a key, pruning what has aged out. */
  function sentWithinHour(key, at) {
    const list = (sentLog.get(key) || []).filter((t) => at - t < 3_600_000);
    if (list.length) sentLog.set(key, list);
    else sentLog.delete(key);
    return list;
  }

  /** Would one more code for this address / client address break a limit? */
  function throttled(email, ip, at) {
    const mine = sentWithinHour(email, at);
    if (mine.length && at - mine[mine.length - 1] < ACCOUNT.resendSec * 1000) return 'wait';
    if (mine.length >= ACCOUNT.codesPerHour) return 'hour';
    if (ip) {
      const fromIp = sentWithinHour(`ip:${ip}`, at);
      if (fromIp.length >= ACCOUNT.codesPerHourPerIp) return 'ip';
    }
    return null;
  }

  /** Record that a code went out (the address and the client address count against their hourly budgets). */
  function noteSent(email, ip, at) {
    sentLog.set(email, [...sentWithinHour(email, at), at]);
    if (ip) sentLog.set(`ip:${ip}`, [...sentWithinHour(`ip:${ip}`, at), at]);
  }

  /** A pending code is keyed by purpose *and* address: a registration code and a reset code never touch each other. */
  const codeKey = (email, purpose) => `${purpose}:${email}`;

  /**
   * Mail one verification code for a purpose ('register' | 'reset') and remember only its hash. The only place the
   * relay is used; a failure is `smtp_failed` and never throws.
   * @param {string} email normalized
   * @param {'register' | 'reset'} purpose
   * @param {string | null} ip
   * @returns {Promise<{ ok: true, ttlSec: number } | { ok: false, error: string }>}
   */
  async function mailCode(email, purpose, ip) {
    const at = now();
    const reason = throttled(email, ip, at);
    if (reason) {
      log.info(`[accounts] ${purpose} code for ${email} throttled (${reason})`);
      return { ok: false, error: 'too_many' };
    }
    const code = String(randomInt(0, 10 ** ACCOUNT.codeLength)).padStart(ACCOUNT.codeLength, '0');
    const salt = randomBytes(16);
    const ttlSec = ACCOUNT.codeTtlSec;
    const minutes = Math.round(ttlSec / 60);
    const mail = purpose === 'reset'
      ? {
        subject: `[卫戍协议：盟约] 密码重置验证码 ${code}`,
        text: `你的密码重置验证码是：${code}（${minutes} 分钟内有效；如果你没有请求重置，请忽略这封邮件）`,
      }
      : {
        subject: `[卫戍协议：盟约] 注册验证码 ${code}`,
        text: `你的注册验证码是：${code}\n\n${minutes} 分钟内有效，请勿泄露给他人。\n如果你没有请求过注册，请忽略这封邮件。\n\n— Stronghold Protocol: Alliance`,
      };
    try {
      await smtp.send({ to: email, ...mail });
    } catch (err) {
      // Nothing was sent and nothing is stored: the player may retry at once (the 60 s window only starts with a mail
      // that actually left), while the attempt still counts against the hourly budget checked above.
      log.error(`[accounts] could not mail a ${purpose} code to ${email}: ${err?.message}`);
      return { ok: false, error: 'smtp_failed' };
    }
    codes.set(codeKey(email, purpose), { hash: codeHash(code, salt), salt, purpose, expiresAt: at + ttlSec * 1000, tries: 0 });
    noteSent(email, ip, at);
    log.info(`[accounts] ${purpose} code sent to ${email}`);
    return { ok: true, ttlSec };
  }

  /**
   * Mail a registration code. An address that already has an account is refused here (`email_taken`): the alternative
   * is a user who goes through the whole flow only to be told at the end, and the register step discloses it anyway.
   * @param {unknown} rawEmail @param {{ ip?: string | null }} [opts]
   * @returns {Promise<{ ok: true, ttlSec: number } | { ok: false, error: string }>}
   */
  async function requestCode(rawEmail, { ip = null } = {}) {
    const email = normalizeEmail(rawEmail);
    if (!email) return { ok: false, error: 'bad_email' };
    if (!smtp) return { ok: false, error: 'accounts_disabled' };
    if (byEmail.has(email)) return { ok: false, error: 'email_taken' };
    return await mailCode(email, 'register', ip);
  }

  /**
   * Mail a password-reset code. An address without an account answers `unknown_email` — [ASSUMED] deliberately, in the
   * same style as registration's `email_taken`: telling somebody they have no account here is the honest answer, and
   * the throttles (`too_many` after one mail a minute) plus the identical successful path keep it from being a useful
   * account-enumeration oracle. A reset code and a registration code never share storage (see `codeKey`).
   * @param {unknown} rawEmail @param {{ ip?: string | null }} [opts]
   * @returns {Promise<{ ok: true, ttlSec: number } | { ok: false, error: string }>}
   */
  async function requestResetCode(rawEmail, { ip = null } = {}) {
    const email = normalizeEmail(rawEmail);
    if (!email) return { ok: false, error: 'bad_email' };
    if (!smtp) return { ok: false, error: 'accounts_disabled' };
    if (!byEmail.has(email)) return { ok: false, error: 'unknown_email' };
    return await mailCode(email, 'reset', ip);
  }

  /**
   * Check and consume a code of one purpose. The code is one-use, expires, and five wrong tries void it (the fifth
   * answer is `code_expired`: nothing is left to try). A code of the other purpose simply cannot match — that is the
   * isolation between registration and reset (a leaked registration code is not a way into an existing account).
   * @param {unknown} rawEmail @param {unknown} rawCode @param {'register' | 'reset'} [purpose]
   * @returns {{ ok: true } | { ok: false, error: 'code_expired' | 'bad_code' | 'bad_email' }}
   */
  function verifyCode(rawEmail, rawCode, purpose = 'register') {
    const email = normalizeEmail(rawEmail);
    if (!email) return { ok: false, error: 'bad_email' };
    const key = codeKey(email, purpose);
    const entry = codes.get(key);
    if (!entry || entry.purpose !== purpose || entry.expiresAt <= now()) {
      if (entry) codes.delete(key);
      return { ok: false, error: 'code_expired' };
    }
    const code = typeof rawCode === 'string' ? rawCode.trim() : '';
    const want = Buffer.from(entry.hash, 'hex');
    const got = Buffer.from(codeHash(code, entry.salt), 'hex');
    if (code.length !== ACCOUNT.codeLength || !timingSafeEqual(got, want)) {
      entry.tries += 1;
      if (entry.tries >= ACCOUNT.codeTries) {
        codes.delete(key);
        log.warn(`[accounts] ${purpose} code for ${email} voided after ${entry.tries} wrong tries`);
        return { ok: false, error: 'code_expired' };
      }
      return { ok: false, error: 'bad_code' };
    }
    codes.delete(key); // one use
    return { ok: true };
  }

  // ---- loading ---------------------------------------------------------------------------------------------

  /** Insert a loaded record (its tokens into the hash index). Rebuilds what the file cannot be trusted to index. */
  function adopt(rec) {
    const account = {
      playerId: rec.playerId,
      email: rec.email,
      name: rec.name,
      createdAt: Number.isFinite(rec.createdAt) ? rec.createdAt : now(),
      lastSeenAt: Number.isFinite(rec.lastSeenAt) ? rec.lastSeenAt : now(),
      lastLoginAt: Number.isFinite(rec.lastLoginAt) ? rec.lastLoginAt : 0,
      salt: rec.salt,
      hash: rec.hash,
      tokens: [],
    };
    for (const t of rec.tokens) {
      if (!t || typeof t.hash !== 'string') continue;
      const record = {
        hash: t.hash,
        createdAt: Number.isFinite(t.createdAt) ? t.createdAt : account.createdAt,
        lastSeenAt: Number.isFinite(t.lastSeenAt) ? t.lastSeenAt : account.lastSeenAt,
      };
      account.tokens.push(record);
      byToken.set(record.hash, { account, record });
    }
    while (account.tokens.length > ACCOUNT.tokens) byToken.delete(account.tokens.shift().hash);
    byId.set(account.playerId, account);
    byEmail.set(account.email, account.playerId);
    return account;
  }

  function load() {
    let raw;
    try { raw = fs.readFileSync(file, 'utf8'); }
    catch (err) {
      if (err?.code !== 'ENOENT') log.warn(`[accounts] could not read ${file}: ${err?.message}`);
      return; // first run: the file appears on the first write
    }
    let doc = null;
    try { doc = JSON.parse(raw); } catch { /* reported below */ }
    const accounts = doc && typeof doc === 'object' && !Array.isArray(doc) ? doc.accounts : null;
    if (!accounts || typeof accounts !== 'object' || Array.isArray(accounts)) {
      // Never overwrite a file we could not read: keep it under a side name (an operator can salvage it, and the
      // store starts empty instead of pretending every account still exists).
      const aside = `${file}.corrupt-${new Date(now()).toISOString().replace(/[:.]/g, '-')}`;
      try { fs.renameSync(file, aside); log.error(`[accounts] ${file} is not an accounts file; kept as ${aside}, starting empty`); }
      catch (err) { log.error(`[accounts] ${file} is not an accounts file (${err?.message}); starting empty`); }
      return;
    }
    let skipped = 0;
    for (const rec of Object.values(accounts)) {
      const ok = rec && typeof rec === 'object'
        && typeof rec.playerId === 'string' && rec.playerId.length > 0
        && typeof rec.email === 'string' && normalizeEmail(rec.email) === rec.email
        && typeof rec.name === 'string' && normalizeNickname(rec.name) === rec.name
        && typeof rec.salt === 'string' && typeof rec.hash === 'string'
        && Array.isArray(rec.tokens);
      if (!ok || byId.has(rec.playerId) || byEmail.has(rec.email)) { skipped++; continue; }
      adopt(rec);
    }
    if (skipped) log.warn(`[accounts] ${skipped} malformed/duplicate record(s) in ${file} ignored`);
    if (byId.size) log.info(`[accounts] loaded ${byId.size} account(s) from ${file}`);
  }

  // ---- writing ---------------------------------------------------------------------------------------------

  /** Write the whole store atomically (temp file + rename). Never throws: a full disk must not kill a login. */
  function persist() {
    touchDirty = false;
    const accounts = {};
    for (const [playerId, a] of byId) accounts[playerId] = a;
    const tmp = `${file}.tmp`;
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(tmp, JSON.stringify({ version: FILE_VERSION, accounts }, null, 2) + '\n');
      fs.renameSync(tmp, file);
    } catch (err) {
      log.error(`[accounts] could not write ${file}: ${err?.message}`);
    }
  }

  /** One coalesced write per second for `verify` touches (see the header). */
  function scheduleTouchWrite() {
    if (touchTimer) return;
    touchTimer = setTimeout(() => { touchTimer = null; if (touchDirty) persist(); }, TOUCH_WRITE_MS);
    touchTimer.unref?.();
  }

  /** Write pending `lastSeenAt` touches now (shutdown). @returns {boolean} whether anything was written */
  function flush() {
    if (touchTimer) { clearTimeout(touchTimer); touchTimer = null; }
    if (!touchDirty) return false;
    persist();
    return true;
  }

  // ---- tokens ---------------------------------------------------------------------------------------------

  /** Mint a token for an account, keeping at most ACCOUNT.tokens (the oldest goes). @param {any} account */
  function issueToken(account) {
    const token = newAccountToken();
    const at = now();
    const record = { hash: accountTokenHash(token), createdAt: at, lastSeenAt: at };
    account.tokens.push(record);
    byToken.set(record.hash, { account, record });
    while (account.tokens.length > ACCOUNT.tokens) byToken.delete(account.tokens.shift().hash);
    return token;
  }

  /** @param {unknown} token @returns {{ account: any, record: any } | null} */
  function lookup(token) {
    if (typeof token !== 'string' || token.length === 0 || token.length > ACCOUNT.tokenMaxLen) return null;
    return byToken.get(accountTokenHash(token)) || null;
  }

  // ---- API -----------------------------------------------------------------------------------------------

  async function register(input = {}) {
    const { email: rawEmail, code, name: rawName, password } = input || {};
    const email = normalizeEmail(rawEmail);
    if (!email) return { ok: false, error: 'bad_email' };
    if (!validAccountPassword(password)) return { ok: false, error: 'bad_password' };
    // Proof of the address comes first: an address the caller cannot receive mail at must not learn anything about
    // the accounts (an existing address included), and a code is burnt by a registration attempt either way.
    const checked = verifyCode(email, code);
    if (!checked.ok) return { ok: false, error: checked.error };
    if (byEmail.has(email) || pending.has(email)) return { ok: false, error: 'email_taken' };
    const name = normalizeNickname(rawName);
    if (!name) return { ok: false, error: 'bad_name' };
    pending.add(email); // reserved before the await: a second register of the same address queues behind it
    try {
      const salt = randomBytes(16);
      const hash = await derive(password, salt);
      if (byEmail.has(email)) return { ok: false, error: 'email_taken' };
      let playerId;
      do playerId = 'a_' + randomBytes(5).toString('hex'); while (byId.has(playerId));
      const at = now();
      const account = {
        playerId, email, name, createdAt: at, lastSeenAt: at, lastLoginAt: at,
        salt: salt.toString('base64'), hash: hash.toString('base64'), tokens: [],
      };
      const token = issueToken(account);
      byId.set(playerId, account);
      byEmail.set(email, playerId);
      persist();
      log.info(`[accounts] registered ${email} (${playerId}, ${name})`);
      return { ok: true, playerId, token, name, email };
    } finally {
      pending.delete(email);
    }
  }

  async function login(input = {}) {
    const { email: rawEmail, password } = input || {};
    const email = normalizeEmail(rawEmail);
    const passwordOk = typeof password === 'string' && password.length >= 1 && [...password].length <= ACCOUNT.passwordMax;
    if (!email || !passwordOk) return { ok: false, error: 'bad_credentials' };
    const playerId = byEmail.get(email);
    const account = playerId ? byId.get(playerId) : null;
    const salt = account ? Buffer.from(account.salt, 'base64') : DUMMY_SALT;
    const want = account ? Buffer.from(account.hash, 'base64') : DUMMY_HASH;
    const got = await derive(password, salt);
    if (!account || got.length !== want.length || !timingSafeEqual(got, want)) return { ok: false, error: 'bad_credentials' };
    const token = issueToken(account);
    account.lastLoginAt = now();
    account.lastSeenAt = account.lastLoginAt;
    persist();
    log.info(`[accounts] login ${account.email} (${account.playerId})`);
    return { ok: true, playerId: account.playerId, token, name: account.name, email: account.email };
  }

  /**
   * Reset a password with a mailed `reset` code (DESIGN §25.8): the code is consumed first, then the new password is
   * hashed into a fresh salt, and **every token the account had is revoked** — a reset is the way back into an account
   * whose password somebody else may know, so every other device is signed out (its next `hello` gets no session back)
   * — and one fresh token is issued for the caller, which is what makes a reset a login.
   * @param {{ email?: unknown, code?: unknown, password?: unknown }} input
   * @returns {Promise<{ ok: true, playerId: string, token: string, name: string, email: string } | { ok: false, error: string }>}
   */
  async function resetPassword(input = {}) {
    const { email: rawEmail, code, password } = input || {};
    const email = normalizeEmail(rawEmail);
    if (!email) return { ok: false, error: 'bad_email' };
    if (!smtp) return { ok: false, error: 'accounts_disabled' };
    if (!validAccountPassword(password)) return { ok: false, error: 'bad_password' };
    const checked = verifyCode(email, code, 'reset');
    if (!checked.ok) return { ok: false, error: checked.error };
    const playerId = byEmail.get(email);
    const account = playerId ? byId.get(playerId) : null;
    if (!account) return { ok: false, error: 'code_expired' }; // the account went away between the mail and the code
    const salt = randomBytes(16);
    const hash = await derive(password, salt);
    account.salt = salt.toString('base64');
    account.hash = hash.toString('base64');
    const revoked = account.tokens.length;
    for (const t of account.tokens) byToken.delete(t.hash);
    account.tokens = [];
    const token = issueToken(account);
    account.lastLoginAt = now();
    account.lastSeenAt = account.lastLoginAt;
    persist();
    log.info(`[accounts] password reset for ${email} (${account.playerId}); ${revoked} token(s) revoked`);
    return { ok: true, playerId: account.playerId, token, name: account.name, email: account.email };
  }

  /** Revoke one token. @param {unknown} token @returns {boolean} whether it was a known, live token */
  function logout(token) {
    const hit = lookup(token);
    if (!hit) return false;
    hit.account.tokens = hit.account.tokens.filter((t) => t !== hit.record);
    byToken.delete(hit.record.hash);
    persist();
    return true;
  }

  /**
   * The account a token proves, or null. Touches lastSeenAt (persisted at most once a second).
   * @param {unknown} token
   * @returns {{ playerId: string, name: string, email: string } | null}
   */
  function verify(token) {
    const hit = lookup(token);
    if (!hit) return null;
    const at = now();
    hit.account.lastSeenAt = at;
    hit.record.lastSeenAt = at;
    touchDirty = true;
    scheduleTouchWrite();
    return { playerId: hit.account.playerId, name: hit.account.name, email: hit.account.email };
  }

  /** @returns {{ accounts: number, tokens: number, codes: number }} */
  function stats() {
    let tokens = 0;
    for (const a of byId.values()) tokens += a.tokens.length;
    return { accounts: byId.size, tokens, codes: codes.size };
  }

  load();
  return { requestCode, requestResetCode, verifyCode, register, login, resetPassword, logout, verify, stats, flush, file, smtp };
}
