// test/accounts.test.js — server/accounts.js + the protocol's account rules (DESIGN §25), without a socket or a lobby.
// The e-mail verification flow is the centre: a code is mailed (through an injected fake relay), valid for ten
// minutes, one-use, voided by five wrong tries, and the throttles that protect a public mail-sending endpoint (60 s
// per address, 5/h per address, 20/h per client address). Then registration/login/tokens/the on-disk store, and the
// browser side of the wire (public/js/net.js: hello.auth, the auth answers, the account token in localStorage).
import { describe, test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { createAccounts, accountsConfigState, accountsMode, ACCOUNTS_MODES, normalizeEmail, normalizeNickname, validAccountPassword, newAccountToken, accountTokenHash } from '../server/accounts.js';
import { sanitizeName } from '../server/net.js';
import { ACCOUNT, EMAIL_RE, S2C, validateC2S } from '../shared/protocol.js';

const root = mkdtempSync(path.join(tmpdir(), 'sp-accounts-'));
after(() => rmSync(root, { recursive: true, force: true }));

const EMAIL = 'doctor@rhodes.example';
const PASSWORD = 'sol-9!gamma';
let seq = 0;

/** The fake relay accounts.js mails through: it keeps what it was asked to send and reads the code back out of it. */
function fakeMailer({ fail = false } = {}) {
  const mails = [];
  return {
    mails,
    async send(mail) {
      if (fail) throw new Error('relay refused the message');
      mails.push(mail);
      return { ok: true };
    },
    /** The 6-digit code of the i-th mail (from where any player would read it: the text). */
    code(i = mails.length - 1) {
      const m = mails[i];
      return m ? (String(m.text).match(/(?:^|[^0-9])([0-9]{6})(?:[^0-9]|$)/) || [])[1] : null;
    },
  };
}

/** A fresh store in its own file; `clock.now` is the injected time, `mail` the fake relay. */
function mk({ smtp = fakeMailer(), file: given = null, ...rest } = {}) {
  const dir = given ? path.dirname(given) : path.join(root, `case-${++seq}`);
  const file = given || path.join(dir, 'accounts.json');
  const clock = { now: 1_700_000_000_000 };
  const errors = [];
  const log = { info() {}, warn() {}, error: (...a) => errors.push(a.map(String).join(' ')), debug() {} };
  const accounts = createAccounts({ file, log, smtp, now: () => clock.now, ...rest });
  return { accounts, file, clock, mail: smtp, errors, dir };
}

/** Request a code and return the code itself (what the player reads in the mail). */
async function codeFor(ctx, email = EMAIL) {
  const res = await ctx.accounts.requestCode(email);
  assert.equal(res.ok, true, JSON.stringify(res));
  const code = ctx.mail.code();
  assert.match(code, /^[0-9]{6}$/, 'the mail carries the code');
  return code;
}

/** Request a *reset* code and return it (the 忘记密码 flow). */
async function codeForReset(ctx, email = EMAIL) {
  const res = await ctx.accounts.requestResetCode(email);
  assert.equal(res.ok, true, JSON.stringify(res));
  const code = ctx.mail.code();
  assert.match(code, /^[0-9]{6}$/, 'the mail carries the code');
  return code;
}

/** Register through the real two-step flow. */
async function signUp(ctx, { email = EMAIL, name = '阿米娅', password = PASSWORD } = {}) {
  const code = await codeFor(ctx, email);
  return await ctx.accounts.register({ email, code, name, password });
}

describe('accounts: configuration (ACCOUNTS / SMTP_*)', () => {
  test('the feature is opt-in: unset, blank, off-ish or unknown ACCOUNTS means off', () => {
    const full = { SMTP_HOST: 'smtp.example', SMTP_FROM: 'noreply@stronghold.example' };
    assert.deepEqual(ACCOUNTS_MODES, ['off', 'auto', 'on']);
    for (const env of [{}, { ACCOUNTS: '' }, { ACCOUNTS: '   ' }, { ACCOUNTS: 'off' }, { ACCOUNTS: 'OFF' }, { ACCOUNTS: '0' }, { ACCOUNTS: 'no' }, { ACCOUNTS: 'false' }, { ACCOUNTS: 'nonsense' }, { ACCOUNTS: 'yes please' }]) {
      const state = accountsConfigState({ ...env, ...full });
      assert.equal(state.mode, 'off', JSON.stringify(env));
      assert.equal(state.enabled, false, JSON.stringify(env));
      assert.equal(state.error, null, 'off is deliberate, not an error');
      assert.equal(state.smtp, null);
    }
    assert.equal(accountsMode(undefined), 'off');
    assert.equal(accountsMode(42), 'off');
  });

  test('ACCOUNTS=on (alias required) with a complete configuration is on', () => {
    const full = { SMTP_HOST: 'smtp.example', SMTP_USER: 'bot', SMTP_PASS: 'pw', SMTP_PORT: '465', SMTP_FROM: 'noreply@stronghold.example' };
    for (const ACCOUNTS of ['on', 'required', 'ON', '1', 'true', 'yes']) {
      const state = accountsConfigState({ ACCOUNTS, ...full });
      assert.equal(state.mode, 'on', ACCOUNTS);
      assert.equal(state.enabled, true, ACCOUNTS);
      assert.equal(state.error, null, ACCOUNTS);
      assert.equal(state.smtp.host, 'smtp.example');
      assert.equal(state.smtp.secure, true);
      assert.equal(state.smtp.user, 'bot');
    }
  });

  test('ACCOUNTS=on with SMTP missing or half configured is a startup error (the caller exits)', () => {
    for (const ACCOUNTS of ['on', 'required']) {
      const nothing = accountsConfigState({ ACCOUNTS });
      assert.equal(nothing.enabled, false);
      assert.equal(nothing.mode, 'on', 'required is reported as on');
      assert.match(nothing.error, /accounts require SMTP/);
      assert.match(nothing.error, /账号注册需要 SMTP/);
      assert.match(nothing.error, /ACCOUNTS=off/);
      assert.match(nothing.error, /set ACCOUNTS=off/);
      const half = accountsConfigState({ ACCOUNTS, SMTP_HOST: 'smtp.example' });
      assert.equal(half.enabled, false);
      assert.match(half.error, /missing SMTP_FROM/);
      const invalid = accountsConfigState({ ACCOUNTS, SMTP_HOST: 'smtp.example', SMTP_FROM: 'nope', SMTP_PORT: 'x' });
      assert.equal(invalid.enabled, false);
      assert.match(invalid.error, /invalid SMTP_FROM, SMTP_PORT|invalid SMTP_PORT, SMTP_FROM/);
    }
  });

  test('ACCOUNTS=auto is decided by the SMTP settings alone (never an exit)', () => {
    const full = { SMTP_HOST: 'smtp.example', SMTP_FROM: 'noreply@stronghold.example' };
    const none = accountsConfigState({ ACCOUNTS: 'auto' });
    assert.equal(none.enabled, false);
    assert.equal(none.error, null, 'nothing configured is not a mistake');
    assert.deepEqual(none.missing, ['SMTP_HOST', 'SMTP_FROM']);
    const on = accountsConfigState({ ACCOUNTS: 'auto', ...full });
    assert.equal(on.enabled, true);
    assert.equal(on.error, null);
    const half = accountsConfigState({ ACCOUNTS: 'auto', SMTP_HOST: 'smtp.example' });
    assert.equal(half.enabled, false);
    assert.match(half.error, /incomplete SMTP configuration/);
    assert.equal(half.mode, 'auto', 'auto never asks the caller to exit');
  });

  test('ACCOUNTS=off wins over a complete SMTP configuration', () => {
    const off = accountsConfigState({ ACCOUNTS: 'off', SMTP_HOST: 'smtp.example', SMTP_FROM: 'noreply@stronghold.example' });
    assert.equal(off.enabled, false);
    assert.equal(off.error, null);
    assert.equal(off.smtp, null);
    assert.equal(off.mode, 'off');
  });
});

describe('accounts: e-mail verification codes', () => {
  test('requestCode mails a 6-digit code and reports how long it lasts', async () => {
    const ctx = mk();
    const res = await ctx.accounts.requestCode(`  ${EMAIL.toUpperCase()}  `);
    assert.deepEqual(res, { ok: true, ttlSec: ACCOUNT.codeTtlSec });
    assert.equal(ctx.mail.mails.length, 1);
    const mail = ctx.mail.mails[0];
    assert.equal(mail.to, EMAIL, 'the address is normalized before it is used');
    assert.match(mail.subject, /[0-9]{6}/, 'the code is in the subject');
    assert.match(mail.text, new RegExp(ctx.mail.code()));
    assert.match(mail.text, /10 分钟/, 'and the validity is spelled out for the player');
    assert.deepEqual(ctx.accounts.stats(), { accounts: 0, tokens: 0, codes: 1 });
    assert.deepEqual(normalizeEmail('  Doctor@Rhodes.Example '), EMAIL);
  });

  test('a malformed address is refused before anything is sent', async () => {
    const ctx = mk();
    for (const bad of ['', 'nope', 'a@b', 'a b@c.d', '@x.y', 'x@y.', 42, null, undefined]) {
      assert.deepEqual(await ctx.accounts.requestCode(bad), { ok: false, error: 'bad_email' }, JSON.stringify(bad));
    }
    assert.equal(ctx.mail.mails.length, 0);
    assert.equal(normalizeEmail('x'.repeat(300) + '@a.b'), null, 'over the length cap');
    assert.equal(EMAIL_RE.test(EMAIL), true);
  });

  test('an address that already has an account is refused (and the register step agrees)', async () => {
    const ctx = mk();
    const reg = await signUp(ctx);
    assert.equal(reg.ok, true);
    assert.deepEqual(await ctx.accounts.requestCode(EMAIL), { ok: false, error: 'email_taken' });
    assert.equal(ctx.mail.mails.length, 1, 'nothing is mailed for an address that cannot register');
  });

  test('no relay configured / a relay that refuses ⇒ accounts_disabled / smtp_failed, never a throw', async () => {
    const off = mk({ smtp: null });
    assert.deepEqual(await off.accounts.requestCode(EMAIL), { ok: false, error: 'accounts_disabled' });
    const broken = mk({ smtp: fakeMailer({ fail: true }) });
    assert.deepEqual(await broken.accounts.requestCode(EMAIL), { ok: false, error: 'smtp_failed' });
    assert.deepEqual(broken.accounts.stats(), { accounts: 0, tokens: 0, codes: 0 }, 'a failed mail leaves no code');
    assert.equal(broken.errors.length, 1, 'the operator gets the reason');
  });

  test('throttling: one code per minute, five per hour per address, twenty per hour per client address', async () => {
    const ctx = mk();
    assert.equal((await ctx.accounts.requestCode(EMAIL, { ip: '1.2.3.4' })).ok, true);
    assert.deepEqual(await ctx.accounts.requestCode(EMAIL, { ip: '1.2.3.4' }), { ok: false, error: 'too_many' }, 'within the minute');
    // the per-address hourly budget: 60 s apart, so the minute window never blocks
    const stamps = [];
    for (let i = 0; i < ACCOUNT.codesPerHour - 1; i++) {
      ctx.clock.now += ACCOUNT.resendSec * 1000;
      stamps.push((await ctx.accounts.requestCode(EMAIL, { ip: '1.2.3.4' })).ok);
    }
    assert.deepEqual(stamps, new Array(ACCOUNT.codesPerHour - 1).fill(true));
    assert.deepEqual(await ctx.accounts.requestCode(EMAIL, { ip: '1.2.3.4' }), { ok: false, error: 'too_many' }, 'the fifth was the last');
    // the hourly window slides: an hour later the address may ask again
    ctx.clock.now += 3_600_001;
    assert.equal((await ctx.accounts.requestCode(EMAIL, { ip: '1.2.3.4' })).ok, true);
    assert.equal(ctx.mail.mails.length, ACCOUNT.codesPerHour + 1);
  });

  test('throttling per client address (a shared IP cannot mail for the whole village)', async () => {
    const ctx = mk();
    for (let i = 0; i < ACCOUNT.codesPerHourPerIp; i++) {
      ctx.clock.now += 2_000; // each from a fresh address, so only the IP budget can bite
      const res = await ctx.accounts.requestCode(`doctor${i}@rhodes.example`, { ip: '9.9.9.9' });
      assert.equal(res.ok, true, `mail ${i}`);
    }
    assert.deepEqual(await ctx.accounts.requestCode('doctor99@rhodes.example', { ip: '9.9.9.9' }), { ok: false, error: 'too_many' });
    assert.equal((await ctx.accounts.requestCode('doctor99@rhodes.example', { ip: '9.9.9.8' })).ok, true, 'another address is unaffected');
  });

  test('a code is one-use, expires after ten minutes, and five wrong tries void it', async () => {
    const ctx = mk();
    const TTL = ACCOUNT.codeTtlSec * 1000;
    const RESEND = ACCOUNT.resendSec * 1000;
    const first = await codeFor(ctx);
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, first), { ok: true });
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, first), { ok: false, error: 'code_expired' }, 'consumed by the first use');

    ctx.clock.now += RESEND;
    const second = await codeFor(ctx);
    ctx.clock.now += TTL + 1;
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, second), { ok: false, error: 'code_expired' }, 'ten minutes is the limit');
    ctx.clock.now -= TTL + 1;
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, second), { ok: false, error: 'code_expired' }, 'an expired code is gone');

    ctx.clock.now += RESEND;
    const third = await codeFor(ctx);
    const wrong = third === '000000' ? '111111' : '000000';
    for (let i = 1; i < ACCOUNT.codeTries; i++) {
      assert.deepEqual(ctx.accounts.verifyCode(EMAIL, wrong), { ok: false, error: 'bad_code' }, `try ${i}`);
    }
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, wrong), { ok: false, error: 'code_expired' }, 'the fifth wrong try voids it');
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, third), { ok: false, error: 'code_expired' }, 'the right code is void too');
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, '123'), { ok: false, error: 'code_expired' }, 'nothing pending');
    assert.deepEqual(ctx.accounts.verifyCode('not-an-email', '123456'), { ok: false, error: 'bad_email' });
  });

  test('the newest code replaces an older one', async () => {
    const ctx = mk();
    const first = await codeFor(ctx);
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const second = await codeFor(ctx);
    assert.notEqual(first, second);
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, first), { ok: false, error: 'bad_code' });
    assert.deepEqual(ctx.accounts.verifyCode(EMAIL, second), { ok: true });
  });
});

describe('accounts: password reset (找回密码)', () => {
  test('a reset code goes to an existing address only, and reads as a reset mail', async () => {
    const ctx = mk();
    assert.deepEqual(await ctx.accounts.requestResetCode('nobody@rhodes.example'), { ok: false, error: 'unknown_email' });
    assert.deepEqual(await ctx.accounts.requestResetCode('nope'), { ok: false, error: 'bad_email' });
    assert.equal(ctx.mail.mails.length, 0, 'no mail for an address without an account');
    await signUp(ctx);
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const res = await ctx.accounts.requestResetCode(EMAIL);
    assert.deepEqual(res, { ok: true, ttlSec: ACCOUNT.codeTtlSec });
    const mail = ctx.mail.mails[ctx.mail.mails.length - 1];
    assert.equal(mail.to, EMAIL);
    assert.match(mail.subject, /密码重置验证码/);
    assert.match(mail.text, /你的密码重置验证码是：[0-9]{6}/);
    assert.match(mail.text, /如果你没有请求重置，请忽略这封邮件/);
    assert.deepEqual(ctx.accounts.stats().accounts, 1);
  });

  test('the two purposes are isolated: a registration code never resets, a reset code never registers', async () => {
    const ctx = mk();
    const registerCode = await codeFor(ctx);                 // a pending registration code
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    await ctx.accounts.requestResetCode(EMAIL).then((r) => assert.equal(r.ok, false, 'no account yet'));
    // register with the registration code
    const reg = await ctx.accounts.register({ email: EMAIL, code: registerCode, name: '阿米娅', password: PASSWORD });
    assert.equal(reg.ok, true);
    // a registration code for this address cannot exist any more (the address is taken), so the reset code is the only
    // one left: a *registration* attempt with a reset code is refused by the address check first…
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const resetCode = await codeForReset(ctx);
    assert.deepEqual(await ctx.accounts.register({ email: EMAIL, code: resetCode, name: '凯尔希', password: PASSWORD }), { ok: false, error: 'code_expired' });
    // …and a *reset* attempt with a registration code (a fresh one for another address) is refused by purpose
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const other = await ctx.accounts.requestCode('other@rhodes.example');
    assert.equal(other.ok, true);
    const otherRegisterCode = ctx.mail.code();
    assert.deepEqual(await ctx.accounts.resetPassword({ email: 'other@rhodes.example', code: otherRegisterCode, password: 'new-password' }), { ok: false, error: 'code_expired' });
    assert.deepEqual(await ctx.accounts.resetPassword({ email: EMAIL, code: otherRegisterCode, password: 'new-password' }), { ok: false, error: 'bad_code' }, 'a registration code is not a reset code (the pending reset code is the only thing that would match)');
    assert.equal((await ctx.accounts.resetPassword({ email: EMAIL, code: resetCode, password: 'new-password' })).ok, true, 'the reset code still works');
  });

  test('a reset changes the password, revokes every token and answers a fresh one (the reset is a login)', async () => {
    const ctx = mk();
    const reg = await signUp(ctx);
    const phone = await ctx.accounts.login({ email: EMAIL, password: PASSWORD });
    const desktop = await ctx.accounts.login({ email: EMAIL, password: PASSWORD });
    assert.deepEqual(ctx.accounts.stats().tokens, 3);
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const code = await codeForReset(ctx);
    const reset = await ctx.accounts.resetPassword({ email: EMAIL, code, password: 'new-pass-9!' });
    assert.equal(reset.ok, true, JSON.stringify(reset));
    assert.equal(reset.playerId, reg.playerId);
    assert.equal(reset.name, reg.name);
    assert.deepEqual(ctx.accounts.stats(), { accounts: 1, tokens: 1, codes: 0 }, 'one token survives: the new one');
    for (const old of [reg.token, phone.token, desktop.token]) assert.equal(ctx.accounts.verify(old), null, 'every older device is signed out');
    assert.deepEqual(ctx.accounts.verify(reset.token), { playerId: reg.playerId, name: '阿米娅', email: EMAIL });
    assert.equal((await ctx.accounts.login({ email: EMAIL, password: PASSWORD })).ok, false, 'the old password is gone');
    assert.equal((await ctx.accounts.login({ email: EMAIL, password: 'new-pass-9!' })).ok, true, 'the new one works');
    // the code is one-use
    assert.deepEqual(await ctx.accounts.resetPassword({ email: EMAIL, code, password: 'another-1' }), { ok: false, error: 'code_expired' });
  });

  test('a reset code expires, is voided by five wrong tries, and obeys the same throttles', async () => {
    const ctx = mk();
    await signUp(ctx);
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const code = await codeForReset(ctx);
    const wrong = code === '000000' ? '111111' : '000000';
    ctx.clock.now += ACCOUNT.codeTtlSec * 1000 + 1;
    assert.deepEqual(await ctx.accounts.resetPassword({ email: EMAIL, code, password: 'new-pass-9!' }), { ok: false, error: 'code_expired' }, 'expired');
    ctx.clock.now -= ACCOUNT.codeTtlSec * 1000 + 1;
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const fresh = await codeForReset(ctx);
    for (let i = 1; i < ACCOUNT.codeTries; i++) {
      assert.deepEqual(await ctx.accounts.resetPassword({ email: EMAIL, code: wrong, password: 'new-pass-9!' }), { ok: false, error: 'bad_code' }, `try ${i}`);
    }
    assert.deepEqual(await ctx.accounts.resetPassword({ email: EMAIL, code: wrong, password: 'new-pass-9!' }), { ok: false, error: 'code_expired' }, 'voided');
    assert.deepEqual(await ctx.accounts.resetPassword({ email: EMAIL, code: fresh, password: 'new-pass-9!' }), { ok: false, error: 'code_expired' }, 'the right code is void too');
    // throttles: one mail a minute, five an hour, and a weak password is refused before the code is spent
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    assert.equal((await ctx.accounts.requestResetCode(EMAIL)).ok, true);
    assert.deepEqual(await ctx.accounts.requestResetCode(EMAIL), { ok: false, error: 'too_many' });
    const last = ctx.mail.code();
    assert.deepEqual(await ctx.accounts.resetPassword({ email: EMAIL, code: last, password: 'short' }), { ok: false, error: 'bad_password' });
    assert.equal((await ctx.accounts.resetPassword({ email: EMAIL, code: last, password: 'long-enough-1' })).ok, true, 'the code is still there after a bad password');
    // no SMTP configured: nothing works
    const off = mk({ smtp: null });
    assert.deepEqual(await off.accounts.requestResetCode(EMAIL), { ok: false, error: 'accounts_disabled' });
    assert.deepEqual(await off.accounts.resetPassword({ email: EMAIL, code: '123456', password: 'long-enough-1' }), { ok: false, error: 'accounts_disabled' });
  });

  test('a reset is recorded in the file (salt/hash replaced, no plaintext) and survives a reload', async () => {
    const ctx = mk();
    await signUp(ctx);
    const before = readFileSync(ctx.file, 'utf8');
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const code = await codeForReset(ctx);
    const reset = await ctx.accounts.resetPassword({ email: EMAIL, code, password: 'new-pass-9!' });
    assert.equal(reset.ok, true);
    ctx.accounts.flush();
    const raw = readFileSync(ctx.file, 'utf8');
    assert.notEqual(raw, before, 'the store was rewritten');
    assert.ok(!raw.includes('new-pass-9!'), 'no plaintext password');
    assert.ok(!raw.includes(reset.token), 'no plaintext token');
    const reloaded = createAccounts({ file: ctx.file, smtp: fakeMailer(), log: { info() {}, warn() {}, error() {}, debug() {} }, now: () => ctx.clock.now });
    assert.deepEqual(reloaded.verify(reset.token), { playerId: reset.playerId, name: '阿米娅', email: EMAIL });
    assert.equal((await reloaded.login({ email: EMAIL, password: 'new-pass-9!' })).ok, true);
  });
});

describe('accounts: registration & login', () => {
  test('register answers a stable playerId, an account token and the nickname', async () => {
    const ctx = mk();
    const res = await signUp(ctx);
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.match(res.playerId, /^a_[0-9a-f]{10}$/, 'account ids are distinct from session ids (p_…)');
    assert.match(res.token, /^[A-Za-z0-9_-]{43}$/, '32 random bytes base64url');
    assert.equal(res.name, '阿米娅');
    assert.equal(res.email, EMAIL);
    assert.deepEqual(ctx.accounts.stats(), { accounts: 1, tokens: 1, codes: 0 });
    assert.ok(existsSync(ctx.file), 'the file is created on the first write');
    assert.ok(!existsSync(`${ctx.file}.tmp`), 'the temp file is renamed, never left behind');
  });

  test('the code is required, consumed and checked before anything is created', async () => {
    const ctx = mk();
    const code = await codeFor(ctx);
    assert.deepEqual(await ctx.accounts.register({ email: EMAIL, code: '000000', name: '阿米娅', password: PASSWORD }), { ok: false, error: 'bad_code' });
    const reg = await ctx.accounts.register({ email: EMAIL, code, name: '阿米娅', password: PASSWORD });
    assert.equal(reg.ok, true, JSON.stringify(reg));
    // The code went with the registration, and the address is known from then on: a second attempt is refused by the
    // one that answers (register re-checks the address too, a safety net a race or a hand-edited file cannot slip past).
    assert.deepEqual(await ctx.accounts.register({ email: EMAIL, code, name: '凯尔希', password: PASSWORD }), { ok: false, error: 'code_expired' });
    assert.deepEqual(await ctx.accounts.requestCode(EMAIL), { ok: false, error: 'email_taken' });
    assert.deepEqual(ctx.accounts.stats(), { accounts: 1, tokens: 1, codes: 0 });
    // a register without ever asking for a code
    assert.deepEqual(await ctx.accounts.register({ email: 'other@rhodes.example', code: '123456', name: '凯尔希', password: PASSWORD }), { ok: false, error: 'code_expired' });
    assert.deepEqual(await ctx.accounts.register({ email: 'nope', code: '123456', name: '凯尔希', password: PASSWORD }), { ok: false, error: 'bad_email' });
  });

  test('a second account needs its own code, and two addresses are independent', async () => {
    const ctx = mk();
    const a = await signUp(ctx);
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const b = await signUp(ctx, { email: 'kaltsit@rhodes.example', name: '凯尔希', password: 'kal-tsit!' });
    assert.equal(b.ok, true, JSON.stringify(b));
    assert.notEqual(a.playerId, b.playerId);
    assert.equal((await ctx.accounts.login({ email: 'kaltsit@rhodes.example', password: PASSWORD })).ok, false, 'a password belongs to one account');
    assert.deepEqual(ctx.accounts.verify(a.token), { playerId: a.playerId, name: '阿米娅', email: EMAIL });
  });

  test('a bad password or nickname is refused (and the code is spent either way)', async () => {
    const ctx = mk();
    const weak = await codeFor(ctx);
    assert.deepEqual(await ctx.accounts.register({ email: EMAIL, code: weak, name: '阿米娅', password: 'short' }), { ok: false, error: 'bad_password' });
    assert.equal(validAccountPassword('123456'), true);
    assert.equal(validAccountPassword('12345'), false);
    assert.equal(validAccountPassword('a'.repeat(ACCOUNT.passwordMax + 1)), false);
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const code = await codeFor(ctx);
    assert.deepEqual(await ctx.accounts.register({ email: EMAIL, code, name: '阿米', password: PASSWORD }), { ok: false, error: 'bad_name' });
    // the code was spent on that attempt (verifyCode comes first, so an address must prove itself before anything else)
    assert.deepEqual(await ctx.accounts.register({ email: EMAIL, code, name: '阿米娅', password: PASSWORD }), { ok: false, error: 'code_expired' });
    assert.equal(ctx.accounts.stats().accounts, 0);
    assert.equal(normalizeNickname('  阿米娅  '), '阿米娅', 'trimmed like net.js sanitizeName');
    assert.equal(normalizeNickname('a\u0000bcd'), 'abcd', 'control characters stripped, like sanitizeName');
    assert.equal(normalizeNickname('阿米 娅'), '阿米 娅', 'an inner space is kept (the nickname is only a display name)');
    assert.equal(normalizeNickname('a'.repeat(ACCOUNT.nameMax)), 'aaaaaaaaaaaa');
    assert.equal(normalizeNickname('a'.repeat(ACCOUNT.nameMax + 1)), null, 'longer than a session name could carry');
    for (const bad of ['', 'ab', '阿米', 42, null, undefined]) assert.equal(normalizeNickname(bad), null, JSON.stringify(bad));
    assert.equal(sanitizeName('  阿米娅  '), '阿米娅');
  });

  test('two nicknames may clash (the e-mail is the identity)', async () => {
    const ctx = mk();
    const a = await signUp(ctx, { name: '阿米娅' });
    ctx.clock.now += ACCOUNT.resendSec * 1000;
    const b = await signUp(ctx, { email: 'second@rhodes.example', name: '阿米娅' });
    assert.equal(a.ok, true);
    assert.equal(b.ok, true, JSON.stringify(b));
    assert.notEqual(a.playerId, b.playerId);
  });

  test('login mints a second, different token; the first device stays signed in', async () => {
    const ctx = mk();
    const first = await signUp(ctx);
    const second = await ctx.accounts.login({ email: EMAIL, password: PASSWORD });
    assert.equal(second.ok, true, JSON.stringify(second));
    assert.equal(second.playerId, first.playerId, 'the playerId is stable across logins');
    assert.equal(second.name, first.name);
    assert.notEqual(second.token, first.token);
    assert.deepEqual(ctx.accounts.verify(first.token), { playerId: first.playerId, name: '阿米娅', email: EMAIL });
    assert.deepEqual(ctx.accounts.verify(second.token), { playerId: first.playerId, name: '阿米娅', email: EMAIL });
    assert.deepEqual(ctx.accounts.stats(), { accounts: 1, tokens: 2, codes: 0 });
    assert.deepEqual(await ctx.accounts.login({ email: '  Doctor@Rhodes.Example  ', password: PASSWORD }).then((r) => ({ ok: r.ok })), { ok: true }, 'the address is case-insensitive');
  });

  test('a wrong password and an unknown address answer the same (bad_credentials, no enumeration)', async () => {
    const ctx = mk();
    await signUp(ctx);
    for (const input of [
      { email: EMAIL, password: 'wrong-pass' },
      { email: EMAIL, password: 'sol-9!gammA' },
      { email: 'nobody@rhodes.example', password: PASSWORD },
      { email: EMAIL, password: '' },
      { email: EMAIL, password: 'x'.repeat(ACCOUNT.passwordMax + 1) },
      { email: 'not-an-email', password: PASSWORD },
      { email: EMAIL },
      {},
      null,
    ]) {
      assert.deepEqual(await ctx.accounts.login(input), { ok: false, error: 'bad_credentials' }, JSON.stringify(input));
    }
    assert.deepEqual(ctx.accounts.stats(), { accounts: 1, tokens: 1, codes: 0 }, 'a failed login mints no token');
  });

  test('an account keeps 5 tokens; the 6th evicts the oldest', async () => {
    const ctx = mk();
    const first = await signUp(ctx);
    const tokens = [first.token];
    for (let i = 0; i < ACCOUNT.tokens - 1; i++) tokens.push((await ctx.accounts.login({ email: EMAIL, password: PASSWORD })).token);
    assert.deepEqual(ctx.accounts.stats().tokens, ACCOUNT.tokens);
    for (const t of tokens) assert.ok(ctx.accounts.verify(t), 'every kept token verifies');
    const extra = await ctx.accounts.login({ email: EMAIL, password: PASSWORD });
    assert.equal(ctx.accounts.verify(first.token), null, 'the oldest token is rotated out');
    assert.ok(ctx.accounts.verify(extra.token));
    for (const t of tokens.slice(1)) assert.ok(ctx.accounts.verify(t));
    assert.deepEqual(ctx.accounts.stats().tokens, ACCOUNT.tokens);
  });

  test('verify refuses anything that is not a known token, and never throws', async () => {
    const ctx = mk();
    const { token } = await signUp(ctx);
    for (const junk of [null, undefined, '', 123, {}, [], 'x'.repeat(ACCOUNT.tokenMaxLen + 1), newAccountToken(), token.slice(0, -1), token.toUpperCase(), '__proto__', 'constructor']) {
      assert.equal(ctx.accounts.verify(junk), null, JSON.stringify(junk));
    }
    assert.ok(ctx.accounts.verify(token));
  });

  test('logout revokes one token and leaves the others', async () => {
    const ctx = mk();
    const first = await signUp(ctx);
    const second = await ctx.accounts.login({ email: EMAIL, password: PASSWORD });
    assert.equal(ctx.accounts.logout(first.token), true);
    assert.equal(ctx.accounts.verify(first.token), null);
    assert.ok(ctx.accounts.verify(second.token), 'the other device keeps its session');
    assert.equal(ctx.accounts.logout(first.token), false, 'revoking twice is just false');
    assert.equal(ctx.accounts.logout(''), false);
    assert.equal(ctx.accounts.logout(null), false);
    assert.equal((await ctx.accounts.login({ email: EMAIL, password: PASSWORD })).ok, true, 'the password still works');
  });
});

describe('accounts: on-disk store', () => {
  test('accounts and tokens survive a restart (a second store on the same file)', async () => {
    const first = mk();
    const reg = await signUp(first);
    const extra = await first.accounts.login({ email: EMAIL, password: PASSWORD });
    first.accounts.flush();

    const log2 = [];
    const reloaded = createAccounts({ file: first.file, smtp: fakeMailer(), log: { info() {}, warn() {}, error: (...a) => log2.push(a.join(' ')), debug() {} }, now: () => first.clock.now });
    assert.deepEqual(log2, [], 'a file we wrote ourselves loads without complaint');
    assert.deepEqual(reloaded.verify(reg.token), { playerId: reg.playerId, name: '阿米娅', email: EMAIL });
    assert.deepEqual(reloaded.verify(extra.token), { playerId: reg.playerId, name: '阿米娅', email: EMAIL });
    assert.deepEqual(reloaded.stats(), { accounts: 1, tokens: 2, codes: 0 });
    assert.deepEqual(await reloaded.requestCode(EMAIL), { ok: false, error: 'email_taken' }, 'the address is still taken');
    const login = await reloaded.login({ email: EMAIL, password: PASSWORD });
    assert.equal(login.ok, true);
    assert.equal(login.playerId, reg.playerId, 'the playerId is the same after a restart');
    assert.equal((await reloaded.login({ email: EMAIL, password: 'not-it' })).ok, false);
  });

  test('the file holds neither the password nor a usable token', async () => {
    const ctx = mk();
    const reg = await signUp(ctx);
    const login = await ctx.accounts.login({ email: EMAIL, password: PASSWORD });
    ctx.accounts.flush();
    const raw = readFileSync(ctx.file, 'utf8');
    assert.ok(!raw.includes(PASSWORD), 'no plaintext password');
    assert.ok(!raw.includes(reg.token), 'no plaintext token');
    assert.ok(!raw.includes(login.token), 'no plaintext token (second)');
    assert.ok(raw.includes(accountTokenHash(reg.token)), 'sha256(token) is what is stored');
    const doc = JSON.parse(raw);
    assert.equal(doc.version, 1);
    const [rec] = Object.values(doc.accounts);
    assert.equal(rec.playerId, reg.playerId);
    assert.equal(rec.email, EMAIL, 'the e-mail is the account key');
    assert.equal(rec.name, '阿米娅');
    assert.equal(typeof rec.salt, 'string');
    assert.equal(typeof rec.hash, 'string');
    assert.ok(Number.isFinite(rec.createdAt) && Number.isFinite(rec.lastSeenAt) && Number.isFinite(rec.lastLoginAt));
    assert.deepEqual(rec.tokens.map((t) => t.hash), [accountTokenHash(reg.token), accountTokenHash(login.token)]);
    for (const t of rec.tokens) assert.match(t.hash, /^[0-9a-f]{64}$/);
    assert.ok(!('password' in rec) && !('token' in rec) && !('hash_' in rec));
    assert.ok(!/\b[0-9]{6}\b/.test(raw), 'a verification code is never written to the file');
  });

  test('the write is atomic and the directory is created on demand', async () => {
    const ctx = mk();
    assert.ok(!existsSync(path.dirname(ctx.file)), 'the case directory does not exist yet');
    await signUp(ctx);
    assert.ok(existsSync(ctx.file));
    assert.ok(!existsSync(`${ctx.file}.tmp`), 'no temp file left behind');
    assert.doesNotThrow(() => JSON.parse(readFileSync(ctx.file, 'utf8')), 'the file is always valid JSON');
  });

  test('a missing file is an empty store; a corrupt file is kept aside and never overwritten blindly', async () => {
    const dir = path.join(root, `case-${++seq}`);
    const file = path.join(dir, 'accounts.json');
    const errors = [];
    const log = { info() {}, warn() {}, error: (...a) => errors.push(a.join(' ')), debug() {} };
    const fresh = createAccounts({ file, log, smtp: fakeMailer() });
    assert.deepEqual(fresh.stats(), { accounts: 0, tokens: 0, codes: 0 }, 'a store that was never written is empty');
    assert.equal((await fresh.requestCode(EMAIL)).ok, true);

    mkdirSync(dir, { recursive: true });
    writeFileSync(file, '{ this is not JSON');
    const broken = createAccounts({ file, log, smtp: fakeMailer() });
    assert.deepEqual(broken.stats(), { accounts: 0, tokens: 0, codes: 0 }, 'starts empty instead of exploding');
    assert.equal(errors.length, 1, 'the operator is told');
    assert.ok(errors[0].includes('not an accounts file'));
    const aside = readdirSync(dir).filter((f) => f.startsWith('accounts.json.corrupt-'));
    assert.equal(aside.length, 1, 'the unreadable file is preserved under a .corrupt- side name');
    assert.equal(readFileSync(path.join(dir, aside[0]), 'utf8'), '{ this is not JSON', 'and is kept byte for byte');
    const mailer = fakeMailer();
    const worked = createAccounts({ file, log, smtp: mailer, now: () => 1_700_000_000_000 });
    assert.equal((await worked.requestCode('other@rhodes.example')).ok, true, 'the store works again');
    const code = (mailer.mails[0].text.match(/([0-9]{6})/) || [])[1];
    assert.equal((await worked.register({ email: 'other@rhodes.example', code, name: '凯尔希', password: PASSWORD })).ok, true);
    assert.doesNotThrow(() => JSON.parse(readFileSync(file, 'utf8')));
  });

  test('verify touches lastSeenAt — coalesced into one write per second; login records lastLoginAt', async () => {
    const ctx = mk();
    const { token } = await signUp(ctx);
    let doc = JSON.parse(readFileSync(ctx.file, 'utf8'));
    const [pid] = Object.keys(doc.accounts);
    const before = doc.accounts[pid].lastSeenAt;
    ctx.clock.now += 60_000;
    assert.ok(ctx.accounts.verify(token));
    ctx.accounts.flush();
    doc = JSON.parse(readFileSync(ctx.file, 'utf8'));
    assert.equal(doc.accounts[pid].lastSeenAt, ctx.clock.now);
    assert.equal(doc.accounts[pid].tokens[0].lastSeenAt, ctx.clock.now);
    assert.notEqual(doc.accounts[pid].lastSeenAt, before);
    assert.equal(ctx.accounts.flush(), false, 'nothing left to write');
    ctx.clock.now += 60_000;
    await ctx.accounts.login({ email: EMAIL, password: PASSWORD });
    doc = JSON.parse(readFileSync(ctx.file, 'utf8'));
    assert.equal(doc.accounts[pid].lastLoginAt, ctx.clock.now);
  });
});

describe('accounts: protocol (shared/protocol.js)', () => {
  test('the wire accepts exactly what the module accepts', () => {
    assert.equal(validateC2S({ t: 'auth.requestCode', email: EMAIL }), null);
    assert.equal(validateC2S({ t: 'auth.register', email: EMAIL, code: '123456', name: '阿米娅', password: PASSWORD }), null);
    assert.equal(validateC2S({ t: 'auth.login', email: EMAIL, password: PASSWORD }), null);
    assert.equal(validateC2S({ t: 'auth.logout' }), null);
    assert.equal(S2C.includes('auth.codeSent'), true, 'auth.codeSent is a documented push');
    assert.equal(S2C.includes('auth.ok') && S2C.includes('auth.error'), true);
    for (const msg of [
      { t: 'auth.requestCode' },
      { t: 'auth.requestCode', email: 'nope' },
      { t: 'auth.requestCode', email: `${'x'.repeat(300)}@a.b` },
      { t: 'auth.register', email: EMAIL, code: '12345', name: '阿米娅', password: PASSWORD },
      { t: 'auth.register', email: EMAIL, code: '12345a', name: '阿米娅', password: PASSWORD },
      { t: 'auth.register', email: EMAIL, code: 123456, name: '阿米娅', password: PASSWORD },
      { t: 'auth.register', email: EMAIL, code: '123456', name: '阿米', password: PASSWORD },
      { t: 'auth.register', email: EMAIL, code: '123456', name: 'a'.repeat(ACCOUNT.nameMax + 1), password: PASSWORD },
      { t: 'auth.register', email: EMAIL, code: '123456', name: '阿米娅', password: 'short' },
      { t: 'auth.register', email: EMAIL, code: '123456', name: '阿米娅' },
      { t: 'auth.register', email: EMAIL, code: '123456', password: PASSWORD },
      { t: 'auth.login', email: EMAIL },
      { t: 'auth.login', email: EMAIL, password: '' },
      { t: 'auth.login', email: 'nope', password: PASSWORD },
    ]) assert.notEqual(validateC2S(msg), null, JSON.stringify(msg));
    // a login password is deliberately lax: the server answers bad_credentials, not a protocol error
    assert.equal(validateC2S({ t: 'auth.login', email: EMAIL, password: 'x' }), null);
    assert.equal(validateC2S({ t: 'auth.register', email: EMAIL, code: '123456', name: '阿米娅', password: PASSWORD, junk: 1 }), null, 'unknown fields are ignored, as everywhere else');
  });

  test('hello.auth carries an optional account token and nothing else', () => {
    const token = newAccountToken();
    assert.equal(validateC2S({ t: 'hello', name: '阿米娅', auth: token }), null);
    assert.equal(validateC2S({ t: 'hello', name: '阿米娅', token: 'abc', auth: token, version: 1 }), null);
    assert.equal(validateC2S({ t: 'hello', name: '阿米娅' }), null, 'a guest hello is unchanged');
    for (const bad of ['', 'x'.repeat(ACCOUNT.tokenMaxLen + 1), 'has space', 'has/slash', 12, {}, []]) {
      assert.notEqual(validateC2S({ t: 'hello', name: '阿米娅', auth: bad }), null, JSON.stringify(bad));
    }
    // a protocol that does not know accounts rejects the intent — what the client must degrade from
    assert.notEqual(validateC2S({ t: 'auth.whatever' }), null);
  });
});

// ---- client wiring (public/js/net.js) — no browser needed: a fake WebSocket, fake timers and a memory storage ----

const clientNet = () => import(new URL('../public/js/net.js', import.meta.url).href);

/** setTimeout/setInterval on a virtual clock (the client's heartbeat must not keep the test process alive). */
function fakeTimers() {
  let now = 1_000_000;
  let seq = 0;
  const queue = new Map();
  const add = (fn, ms, every) => { const id = ++seq; queue.set(id, { fn, at: now + Math.max(every ? 1 : 0, ms || 0), every }); return id; };
  return {
    timers: {
      setTimeout: (fn, ms) => add(fn, ms, null),
      setInterval: (fn, ms) => add(fn, ms, Math.max(1, ms || 1)),
      clearTimeout: (id) => queue.delete(id),
      clearInterval: (id) => queue.delete(id),
    },
    now: () => now,
  };
}

function makeFakeWS() {
  const sockets = [];
  class FakeWS {
    constructor(url) { this.url = url; this.readyState = 0; this.sent = []; sockets.push(this); }
    send(data) { if (this.readyState !== 1) throw new Error('not open'); this.sent.push(JSON.parse(data)); }
    close(code) { this.readyState = 3; this.onclose?.({ code: code ?? 1000 }); }
    open() { this.readyState = 1; this.onopen?.(); }
    recv(obj) { this.onmessage?.({ data: JSON.stringify(obj) }); }
    last(t) { return [...this.sent].reverse().find((m) => m.t === t) || null; }
  }
  return { FakeWS, sockets };
}

function memStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
}

async function clientOf({ auth = null } = {}) {
  const { Net } = await clientNet();
  const clock = fakeTimers();
  const { FakeWS, sockets } = makeFakeWS();
  const net = new Net({ url: 'ws://test/ws', WebSocket: FakeWS, timers: clock.timers, now: clock.now, getToken: () => null, getAuth: () => auth });
  const ws = () => sockets[sockets.length - 1];
  return { net, ws, clock };
}

/** A client that already said hello and is online. */
async function onlineClient(auth = null) {
  const ctx = await clientOf({ auth });
  ctx.net.setName('阿米娅');
  ctx.ws().open();
  const hello = ctx.ws().last('hello');
  ctx.ws().recv({ t: 'welcome', rid: hello.rid, playerId: 'a_0123456789', token: 'session-1', name: '阿米娅', serverNow: ctx.clock.now() });
  return { ...ctx, hello };
}

describe('accounts: client wiring (public/js/net.js)', () => {
  test('hello carries the account token as auth — and a guest hello carries none', async () => {
    const token = newAccountToken();
    const signed = await onlineClient(token);
    assert.equal(signed.hello.auth, token, 'the signed-in browser proves the account on every hello');
    assert.equal(signed.hello.name, '阿米娅');
    const guest = await onlineClient(null);
    assert.equal('auth' in guest.hello, false, 'a guest hello is exactly what it always was');
    signed.net.close();
    guest.net.close();
  });

  test('a token the server does not know only produces an unsolicited auth.error (never a failed hello)', async () => {
    const { net, ws } = await onlineClient(newAccountToken());
    const seen = [];
    net.on('auth.error', (m) => seen.push(m.code));
    ws().recv({ t: 'auth.error', code: 'bad_token', message: 'unknown token' });
    assert.deepEqual(seen, ['bad_token'], 'emitted, so the app can forget the token and stay a guest');
    assert.equal(net.status, 'online', 'the session it just got is untouched');
    assert.equal(net.pendingCount, 0);
    net.close();
  });

  test('auth.login / auth.register answer through auth.ok; a refusal rejects with player-facing text', async () => {
    const { net, ws } = await onlineClient(null);
    const NetErrorRef = (await clientNet()).NetError;
    const login = net.request('auth.login', { email: EMAIL, password: PASSWORD });
    const sent = ws().sent[ws().sent.length - 1];
    assert.equal(sent.t, 'auth.login');
    ws().recv({ t: 'auth.ok', rid: sent.rid, playerId: 'a_1', name: '阿米娅', token: 'acct-token' });
    assert.deepEqual(await login, { t: 'auth.ok', rid: sent.rid, playerId: 'a_1', name: '阿米娅', token: 'acct-token' });

    const failed = net.request('auth.register', { email: EMAIL, code: '123456', name: '阿米娅', password: PASSWORD });
    const reg = ws().sent[ws().sent.length - 1];
    assert.equal(reg.t, 'auth.register');
    ws().recv({ t: 'auth.error', rid: reg.rid, code: 'email_taken', message: 'email taken' });
    await assert.rejects(failed, (err) => {
      assert.ok(err instanceof NetErrorRef, 'still a NetError, so every existing error path works');
      assert.equal(err.code, 'email_taken');
      assert.match(err.message, /已注册/);
      return true;
    });

    // an older server answers the intent with a protocol error — the client must degrade, not break
    const legacy = net.request('auth.login', { email: EMAIL, password: PASSWORD });
    const old = ws().sent[ws().sent.length - 1];
    ws().recv({ t: 'error', rid: old.rid, code: 'BAD_MSG', msg: 'unknown type auth.login' });
    await assert.rejects(legacy, (err) => err.code === 'BAD_MSG');
    assert.equal(net.status, 'online', 'and the guest session keeps running');
    // the account feature is off on this server: the panel hides itself instead of offering a dead flow
    const disabled = net.request('auth.login', { email: EMAIL, password: PASSWORD });
    const off = ws().sent[ws().sent.length - 1];
    ws().recv({ t: 'auth.error', rid: off.rid, code: 'accounts_disabled', message: 'no smtp' });
    await assert.rejects(disabled, (err) => {
      assert.equal(err.code, 'accounts_disabled');
      assert.match(err.message, /不支持账号系统|未开启/);
      return true;
    });
    net.close();
  });

  test('requestCode is the one intent that needs no session (status connected, no name)', async () => {
    const { net, ws } = await clientOf();
    net.connect();
    ws().open();
    assert.equal(net.status, 'connected', 'the title screen has no session yet');
    const pending = net.request('auth.requestCode', { email: EMAIL }, { session: false });
    const sent = ws().sent[ws().sent.length - 1];
    assert.equal(sent.t, 'auth.requestCode');
    ws().recv({ t: 'auth.codeSent', rid: sent.rid, email: EMAIL, ttlSec: ACCOUNT.codeTtlSec });
    assert.deepEqual(await pending, { t: 'auth.codeSent', rid: sent.rid, email: EMAIL, ttlSec: ACCOUNT.codeTtlSec });
    // without the flag it is refused, exactly like every other session intent
    await assert.rejects(net.request('auth.login', { email: EMAIL, password: PASSWORD }), (err) => err.code === 'OFFLINE');
    net.close();
  });

  test('a server older than accounts: the hello is retried without auth and the guest session comes up', async () => {
    const token = newAccountToken();
    const { net, ws } = await clientOf({ auth: token });
    const unsupported = [];
    const helloErrors = [];
    net.on('authUnsupported', (e) => unsupported.push(e.code));
    net.on('helloError', (e) => helloErrors.push(e.code));
    net.setName('阿米娅');
    ws().open();
    const first = ws().last('hello');
    assert.equal(first.auth, token);
    ws().recv({ t: 'error', rid: first.rid, code: 'BAD_MSG', msg: 'bad field auth' });
    const retry = ws().last('hello');
    assert.ok(retry.rid !== first.rid, 'the hello is sent again');
    assert.equal('auth' in retry, false, 'without the field that server rejected');
    assert.deepEqual(helloErrors, [], 'no error toast: the player just goes on as a guest');
    assert.deepEqual(unsupported, ['BAD_MSG'], 'the UI is told to stop claiming an account');
    ws().recv({ t: 'welcome', rid: retry.rid, playerId: 'p_2', token: 'session-2', name: '阿米娅', serverNow: 1 });
    assert.equal(net.status, 'online');
    net.setName('凯尔希');
    assert.equal('auth' in ws().last('hello'), false, 'even a later rename stays a guest hello');
    net.close();
  });

  test('identity keeps the account token in localStorage (not in sessionStorage)', async () => {
    const { createIdentity } = await clientNet();
    const local = memStorage();
    const session = memStorage();
    const id = createIdentity({ local, session, tabId: 'X', channel: null });
    await id.init();
    assert.equal(id.loadAccountToken(), null, 'a fresh browser is a guest');
    id.saveAccountToken('acct-1');
    assert.equal(id.loadAccountToken(), 'acct-1');
    assert.equal(session.getItem('sp.account'), null, 'the credential does not live in sessionStorage');
    id.saveAccountToken('');
    id.saveAccountToken('x'.repeat(ACCOUNT.tokenMaxLen + 1));
    assert.equal(id.loadAccountToken(), 'acct-1', 'junk is ignored, the good token stays');
    id.clearAccountToken();
    assert.equal(id.loadAccountToken(), null);
    assert.equal(id.getToken(), null, 'the session token is a separate thing');
  });
});
