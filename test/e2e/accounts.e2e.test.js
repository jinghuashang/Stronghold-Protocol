// test/e2e/accounts.e2e.test.js — the wired account system, end to end and re-runnable: the real server
// (server/index.js → server/net.js → server/accounts.js → server/smtp.js), a fake SMTP relay on node:net, and real
// `ws` clients. Covers what only the wiring can show:
//   * `ACCOUNTS=on` (alias `required`) without the SMTP settings refuses to start (a real child process, exit code 1, the error on
//     stderr) while accounts are opt-in: unset / `off` simply turns the feature off, `auto` lets SMTP decide;
//   * `/healthz` reports the switch (`accounts: 'on' | 'off'`);
//   * the two-step registration over the wire (requestCode → the code the relay received → register → auth.ok +
//     welcome), with no `hello` needed first;
//   * a second connection logging into the same account takes the seat over: the SAME playerId, the room resent to it,
//     and the first socket closed with 4001;
//   * a wrong password answers `auth.error bad_credentials`, a bind that would move a seated session answers `in_room`;
//   * with no SMTP configured every auth intent answers `accounts_disabled`.
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { startServer } from '../../server/index.js';
import { StubMatch } from '../../server/match/StubMatch.js';
import { TestClient } from '../helpers/wsClient.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const EMAIL = 'doctor@rhodes.example';
const EMAIL2 = 'kaltsit@rhodes.example';
const PASSWORD = 'sol-9!gamma';
const NAME = '阿米娅';
const tmp = mkdtempSync(path.join(tmpdir(), 'sp-accounts-e2e-'));
after(() => rmSync(tmp, { recursive: true, force: true }));

const noopLog = () => {
  const errors = [];
  return { errors, log: { info() {}, warn() {}, debug() {}, error: (...a) => errors.push(a.map(String).join(' ')) } };
};

/** A fake SMTP relay: enough of RFC 5321 for the real client, and it keeps every message it was handed. */
function fakeRelay() {
  const mails = [];
  const server = net.createServer((socket) => {
    let buf = '';
    let inData = false;
    let data = [];
    socket.write('220 relay ESMTP ready\r\n');
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      let nl;
      while ((nl = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (inData) {
          if (line === '.') { inData = false; mails.push(data.join('\r\n')); data = []; socket.write('250 2.0.0 queued\r\n'); continue; }
          data.push(line.startsWith('..') ? line.slice(1) : line);
          continue;
        }
        const u = line.toUpperCase();
        if (u.startsWith('EHLO')) socket.write('250-relay greets you\r\n250-SIZE 10240000\r\n250 8BITMIME\r\n');
        else if (u.startsWith('MAIL')) socket.write('250 2.1.0 Ok\r\n');
        else if (u.startsWith('RCPT')) socket.write('250 2.1.5 Ok\r\n');
        else if (u === 'DATA') { inData = true; socket.write('354 End data with <CR><LF>.<CR><LF>\r\n'); }
        else if (u === 'QUIT') { socket.write('221 2.0.0 Bye\r\n'); socket.end(); }
        else socket.write('250 2.0.0 Ok\r\n');
      }
    });
  });
  return { mails, server, close: () => new Promise((r) => server.close(() => r())) };
}

/** The 6-digit code of the newest mail, read exactly as a player would (the base64 body). */
function latestCode(relay) {
  const mail = relay.mails[relay.mails.length - 1];
  assert.ok(mail, 'a verification mail arrived');
  const body = mail.split('\r\n\r\n').slice(1).join('\r\n\r\n').replace(/\r\n/g, '');
  const text = Buffer.from(body, 'base64').toString('utf8');
  const code = (text.match(/([0-9]{6})/) || [])[1];
  assert.match(code || '', /^[0-9]{6}$/, `a code in the mail: ${text}`);
  return code;
}

const healthz = (port) => new Promise((resolve, reject) => {
  http.get({ host: '127.0.0.1', port, path: '/healthz' }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
  }).on('error', reject);
});

/** Send an intent and wait for an account answer (the client's `request()` only knows ok/error/welcome/pong). */
async function auth(client, msg, type, timeout = 5000) {
  const rid = client.nextRid++;
  client.send({ ...msg, rid });
  return await client.waitFor(type, (m) => m.rid === rid, timeout);
}

let takeoverHost = null;

describe('accounts end to end (wired server)', () => {
  /** @type {any} */ let srv;
  /** @type {{ errors: string[], log: object }} */ let cap;
  /** @type {ReturnType<typeof fakeRelay>} */ let relay;
  let url;
  let relayPort;

  before(async () => {
    relay = fakeRelay();
    await new Promise((r) => relay.server.listen(0, '127.0.0.1', r));
    relayPort = relay.server.address().port;
    cap = noopLog();
    srv = await startServer({
      port: 0, host: '127.0.0.1', log: cap.log, MatchClass: StubMatch,
      env: { ACCOUNTS: 'auto', SMTP_HOST: '127.0.0.1', SMTP_PORT: String(relayPort), SMTP_FROM: 'noreply@stronghold.example' },
      accountsFile: path.join(tmp, 'accounts.json'),
    });
    url = `ws://127.0.0.1:${srv.port}/ws`;
  });
  after(async () => {
    await srv?.close();
    await relay?.close();
  });

  test('the switch: /healthz says accounts are on when SMTP is configured', async () => {
    const h = await healthz(srv.port);
    assert.equal(h.ok, true);
    assert.equal(h.accounts, 'on');
    assert.ok(srv.accounts, 'startServer exposes the store');
    assert.equal(srv.accountsState.enabled, true);
    assert.equal(srv.accountsState.mode, 'auto');
  });

  test('registration is two steps over the wire, and needs no hello first', async () => {
    const c = await TestClient.connect(url);
    try {
      const sent = await auth(c, { t: 'auth.requestCode', email: EMAIL }, 'auth.codeSent');
      assert.equal(sent.email, EMAIL);
      assert.equal(sent.ttlSec, 600);
      assert.equal(relay.mails.length, 1, 'exactly one mail');
      assert.ok(relay.mails[0].includes('To: ' + EMAIL), 'the mail went to the address asked for');
      const code = latestCode(relay);

      const ok = await auth(c, { t: 'auth.register', email: EMAIL, code, name: NAME, password: PASSWORD }, 'auth.ok');
      assert.match(ok.playerId, /^a_[0-9a-f]{10}$/);
      assert.equal(ok.name, NAME);
      assert.match(ok.token, /^[A-Za-z0-9_-]{43}$/);
      const welcome = await c.waitFor('welcome', (m) => m.playerId === ok.playerId);
      assert.equal(welcome.name, NAME, 'the session carries the account nickname');
      assert.ok(welcome.token && welcome.token !== ok.token, 'the session token is its own (welcome), the account token is auth.ok');
      c.session = { playerId: ok.playerId, token: welcome.token, accountToken: ok.token };

      // a co-op room to be handed over later
      const created = await c.request({ t: 'room.create', mode: 'coop', difficulty: 'NORMAL' });
      assert.equal(created.t, 'ok');
      const state = await c.waitFor('room.state', (s) => s.hostId === ok.playerId);
      assert.equal(state.seats.find((s) => s && s.playerId === ok.playerId).name, NAME);
      c.roomCode = state.code;
      // the connection stays open: the take-over test closes it with 4001
      takeoverHost = c;
    } finally {
      if (!takeoverHost) await c.close();
    }
  });

  test('a second connection logging into the same account takes the seat over (4001 on the first)', async () => {
    assert.ok(takeoverHost, 'the first connection is still open');
    const c2 = await TestClient.connect(url);
    const ok = await auth(c2, { t: 'auth.login', email: EMAIL, password: PASSWORD }, 'auth.ok');
    assert.equal(ok.playerId, takeoverHost.session.playerId, 'the same account playerId');
    const welcome = await c2.waitFor('welcome', (m) => m.playerId === ok.playerId);
    assert.equal(welcome.resumed, true, 'the hand-over resends everything');
    const state = await c2.waitFor('room.state', (s) => s.code === takeoverHost.roomCode, 5000);
    assert.equal(state.seats.find((s) => s && s.playerId === ok.playerId).name, NAME, 'the phone holds the same seat');
    const closed = await takeoverHost.closed;
    assert.equal(closed.code, 4001, 'the desktop is told the session was replaced');
    await c2.close();
  });

  test('a wrong password answers bad_credentials; a bind that would move a seat answers in_room', async () => {
    const c = await TestClient.connect(url);
    const bad = await auth(c, { t: 'auth.login', email: EMAIL, password: 'definitely-wrong' }, 'auth.error');
    assert.equal(bad.code, 'bad_credentials');
    const unknown = await auth(c, { t: 'auth.login', email: 'nobody@rhodes.example', password: PASSWORD }, 'auth.error');
    assert.equal(unknown.code, 'bad_credentials', 'no account enumeration');
    await c.close();

    // a guest who is already seated cannot be re-bound to another account: register a second account, then try it
    // from a connection that holds a seat
    const seated = await TestClient.connect(url);
    const logged = await auth(seated, { t: 'auth.login', email: EMAIL, password: PASSWORD }, 'auth.ok');
    await seated.waitFor('welcome', (m) => m.playerId === logged.playerId);
    await seated.request({ t: 'room.create', mode: 'coop', difficulty: 'NORMAL' });
    await seated.waitFor('room.state', (s) => s.hostId === logged.playerId);
    const second = await auth(seated, { t: 'auth.requestCode', email: EMAIL2 }, 'auth.codeSent');
    assert.equal(second.email, EMAIL2);
    const code2 = latestCode(relay);
    const refused = await auth(seated, { t: 'auth.register', email: EMAIL2, code: code2, name: '凯尔希', password: PASSWORD }, 'auth.error');
    assert.equal(refused.code, 'in_room', 'a seated session is not moved to another account');
    await seated.close();
  });

  test('accounts are opt-in: no ACCOUNTS at all (and ACCOUNTS=off) means off, and every intent says so', async () => {
    const cap2 = noopLog();
    // nothing in the environment: the DEFAULT is off, whatever SMTP_HOST/SMTP_FROM might say in the shell
    const plain = await startServer({ port: 0, host: '127.0.0.1', log: cap2.log, MatchClass: StubMatch, env: {} });
    try {
      const h = await healthz(plain.port);
      assert.equal(h.accounts, 'off');
      assert.equal(plain.accounts, null);
      assert.equal(plain.accountsState.mode, 'off');
      assert.equal(plain.accountsState.error, null);
      const c = await TestClient.connect(`ws://127.0.0.1:${plain.port}/ws`);
      const res = await auth(c, { t: 'auth.requestCode', email: EMAIL }, 'auth.error');
      assert.equal(res.code, 'accounts_disabled');
      const login = await auth(c, { t: 'auth.login', email: EMAIL, password: PASSWORD }, 'auth.error');
      assert.equal(login.code, 'accounts_disabled');
      // …and the game itself is untouched: a guest still says hello and plays
      const w = await c.hello('游客');
      assert.match(w.playerId, /^p_/);
      await c.close();
    } finally {
      await plain.close();
      assert.deepEqual(cap2.errors, [], 'no errors logged for an off feature');
    }

    // …and ACCOUNTS=off wins even with a perfectly good SMTP configuration
    const explicit = await startServer({
      port: 0, host: '127.0.0.1', log: cap2.log, MatchClass: StubMatch,
      env: { ACCOUNTS: 'off', SMTP_HOST: '127.0.0.1', SMTP_PORT: String(relayPort), SMTP_FROM: 'noreply@stronghold.example' },
    });
    try {
      assert.equal((await healthz(explicit.port)).accounts, 'off');
      assert.equal(explicit.accounts, null);
      const c = await TestClient.connect(`ws://127.0.0.1:${explicit.port}/ws`);
      assert.equal((await auth(c, { t: 'auth.requestCode', email: EMAIL }, 'auth.error')).code, 'accounts_disabled');
      await c.close();
    } finally {
      await explicit.close();
    }
  });

  test('ACCOUNTS=on (and its old alias required) without the SMTP settings refuses to start (exit 1, clear error)', () => {
    for (const ACCOUNTS of ['on', 'required']) {
      const env = { ...process.env, ACCOUNTS, PORT: '0' };
      for (const k of ['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM']) delete env[k];
      const r = spawnSync(process.execPath, [path.join(ROOT, 'server', 'index.js')], { env, encoding: 'utf8', timeout: 30_000 });
      assert.equal(r.status, 1, `ACCOUNTS=${ACCOUNTS} exit code (stderr: ${r.stderr})`);
      assert.match(r.stderr, /\[accounts\]/, ACCOUNTS);
      assert.match(r.stderr, /accounts require SMTP/, ACCOUNTS);
      assert.match(r.stderr, /账号注册需要 SMTP/, ACCOUNTS);
      assert.match(r.stderr, /ACCOUNTS=off/, ACCOUNTS);
      assert.match(r.stderr, /set ACCOUNTS=off/, ACCOUNTS);
    }
  });

  test('with the accounts off, a plain start still comes up (the default must not block the game)', () => {
    const env = { ...process.env, PORT: '0' };
    delete env.ACCOUNTS;
    // a short-lived child: it must reach "listening" and then be killed by the timeout (exit code null + signal)
    const r = spawnSync(process.execPath, [path.join(ROOT, 'server', 'index.js')], { env, encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL' });
    assert.equal(r.status, null, 'still running when the test killed it — it did not exit on its own');
    assert.match(r.stdout + r.stderr, /\[accounts\] OFF/);
  });

  test('nothing was logged as an error while the wired feature ran', () => {
    assert.deepEqual(cap.errors, []);
  });
});
