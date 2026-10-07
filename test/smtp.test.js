// test/smtp.test.js — server/smtp.js (DESIGN §25): the hand-rolled SMTP client, exercised against a fake relay on
// node:net. Covers the command sequence one verification mail produces (EHLO → AUTH → MAIL FROM → RCPT TO → DATA →
// QUIT), the message that is actually written (encoded subject, base64 body, CRLF framing), AUTH PLAIN vs LOGIN, a
// relay that refuses the recipient, the TLS policy (cleartext AUTH needs an explicit opt-in), `verify()` never
// throwing, and the SMTP_* environment parsing (including the half-configured case the account feature refuses).
import { describe, test, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';

import { createSmtp, buildMail, smtpOptionsFromEnv, SMTP_ENV_KEYS } from '../server/smtp.js';

/** A minimal SMTP relay: enough of RFC 5321 to answer one mail, recording everything it received. */
function fakeRelay({ authModes = ['PLAIN', 'LOGIN'], starttls = false, rcptCode = 250, greetingCode = 220 } = {}) {
  const state = { commands: [], auth: [], data: null, connections: 0 };
  const server = net.createServer((socket) => {
    state.connections += 1;
    let buf = '';
    let inData = false;
    let dataLines = [];
    /** '' | 'user' | 'pass' — the AUTH LOGIN dialogue's stage. */
    let loginStage = '';
    const send = (line) => socket.write(`${line}\r\n`);
    send(`${greetingCode} fake-relay ESMTP ready`);
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      let nl;
      while ((nl = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (inData) {
          if (line === '.') {
            inData = false;
            state.data = dataLines.join('\r\n');
            dataLines = [];
            send('250 2.0.0 Ok: queued as 3F1A');
          } else dataLines.push(line.startsWith('..') ? line.slice(1) : line);
          continue;
        }
        if (loginStage === 'user') { loginStage = 'pass'; state.auth.push(`LOGIN ${Buffer.from(line, 'base64').toString('utf8')} /`); send(`334 ${Buffer.from('Password:').toString('base64')}`); continue; }
        if (loginStage === 'pass') { loginStage = ''; state.auth[state.auth.length - 1] += ` ${Buffer.from(line, 'base64').toString('utf8')}`; send('235 2.7.0 Authentication successful'); continue; }
        state.commands.push(line);
        const upper = line.toUpperCase();
        if (upper.startsWith('EHLO') || upper.startsWith('HELO')) {
          send('250-fake-relay greets you');
          send('250-SIZE 10240000');
          if (starttls) send('250-STARTTLS');
          if (authModes.length) send(`250-AUTH ${authModes.join(' ')}`);
          send('250 8BITMIME');
        } else if (upper.startsWith('AUTH PLAIN')) {
          state.auth.push(`PLAIN ${Buffer.from(line.slice(11).trim(), 'base64').toString('utf8').replace(/\0/g, '|')}`);
          send('235 2.7.0 Authentication successful');
        } else if (upper === 'AUTH LOGIN') {
          loginStage = 'user';
          send(`334 ${Buffer.from('Username:').toString('base64')}`);
        } else if (upper.startsWith('MAIL FROM')) send('250 2.1.0 Ok');
        else if (upper.startsWith('RCPT TO')) send(rcptCode === 250 ? '250 2.1.5 Ok' : `${rcptCode} 5.1.1 no such user`);
        else if (upper === 'DATA') { inData = true; send('354 End data with <CR><LF>.<CR><LF>'); }
        else if (upper === 'QUIT') { send('221 2.0.0 Bye'); socket.end(); }
        else if (upper === 'RSET' || upper === 'NOOP') send('250 2.0.0 Ok');
        else send('502 5.5.2 Command not implemented');
      }
    });
  });
  return {
    state,
    async listen() {
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      return server.address().port;
    },
    close() { return new Promise((resolve) => { server.close(() => resolve()); }); },
  };
}

const relays = [];
async function relay(opts) {
  const r = fakeRelay(opts);
  relays.push(r);
  const port = await r.listen();
  return { r, port };
}
after(async () => { await Promise.all(relays.map((r) => r.close())); });

const FROM = 'noreply@stronghold.example';

describe('smtp: options from the environment', () => {
  test('nothing set: not configured at all (the difference auto-mode needs)', () => {
    const s = smtpOptionsFromEnv({});
    assert.equal(s.anySet, false);
    assert.deepEqual(s.missing, ['SMTP_HOST', 'SMTP_FROM']);
    assert.deepEqual(s.invalid, []);
    assert.equal(s.port, 587, 'STARTTLS is the default transport');
    assert.equal(s.secure, false);
    assert.deepEqual(SMTP_ENV_KEYS.length, 6);
  });

  test('a complete configuration is ready for createSmtp', () => {
    const s = smtpOptionsFromEnv({ SMTP_HOST: 'smtp.example', SMTP_USER: 'bot', SMTP_PASS: 'pw', SMTP_FROM: FROM });
    assert.deepEqual(s.missing, []);
    assert.deepEqual(s.invalid, []);
    assert.equal(s.anySet, true);
    assert.equal(s.port, 587);
    assert.equal(s.options.host, 'smtp.example');
    assert.equal(s.options.secure, false);
    assert.equal(s.options.from, FROM);
  });

  test('SMTP_PORT/SMTP_SECURE decide the transport (465 implies implicit TLS)', () => {
    assert.equal(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: FROM, SMTP_PORT: '465' }).secure, true);
    assert.equal(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: FROM, SMTP_PORT: '465' }).port, 465);
    assert.equal(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: FROM, SMTP_SECURE: '1' }).secure, true);
    assert.equal(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: FROM, SMTP_SECURE: 'no' }).secure, false);
    assert.equal(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: FROM, SMTP_PORT: '2525' }).port, 2525);
  });

  test('a half configuration is reported (missing / invalid), never silently used', () => {
    const half = smtpOptionsFromEnv({ SMTP_HOST: 'smtp.example' });
    assert.equal(half.anySet, true);
    assert.deepEqual(half.missing, ['SMTP_FROM']);
    assert.equal(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: FROM, SMTP_USER: 'u' }).missing.includes('SMTP_PASS'), true);
    assert.equal(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: FROM, SMTP_PASS: 'p' }).missing.includes('SMTP_USER'), true);
    assert.deepEqual(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: FROM, SMTP_PORT: 'nope' }).invalid, ['SMTP_PORT']);
    assert.deepEqual(smtpOptionsFromEnv({ SMTP_HOST: 'h', SMTP_FROM: 'not-an-address' }).invalid, ['SMTP_FROM']);
  });
});

describe('smtp: the message', () => {
  test('a Chinese subject is ONE RFC 2047 encoded word that decodes back exactly', () => {
    const subject = '[卫戍协议：盟约] 注册验证码 123456';
    const mail = buildMail({ from: FROM, to: 'player@example.com', subject, text: '你的注册验证码是：123456' });
    const headers = mail.split('\r\n\r\n')[0];
    const subjectLine = headers.split('\r\n').find((l) => l.startsWith('Subject: '));
    assert.match(subjectLine, /^Subject: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/, 'exactly one encoded word, with a space after the colon');
    assert.ok(!headers.split('\r\n').some((l) => l.startsWith(' =?UTF-8?')), 'and no continuation line for a short subject');
    const b64 = subjectLine.slice('Subject: =?UTF-8?B?'.length, -'?='.length);
    assert.equal(Buffer.from(b64, 'base64').toString('utf8'), subject, 'the word decodes to the subject, whole');
    // the body stays a base64 block, its own encoding untouched
    assert.match(headers, /^Content-Transfer-Encoding: base64$/m);
    assert.match(headers, /^Content-Type: text\/plain; charset=utf-8$/m);
    const body = mail.split('\r\n\r\n')[1];
    assert.equal(Buffer.from(body.replace(/\r\n/g, ''), 'base64').toString('utf8'), '你的注册验证码是：123456');
  });

  test('a subject that has to be split keeps every word decodable (characters are never cut in half)', () => {
    const subject = '[卫戍协议：盟约] 你的注册验证码已经生成，请在十分钟之内输入到游戏登录界面以免失效，谢谢配合与支持。'
      + '（这是一封很长的邮件主题，用来验证折行时每个编码词都能独立解码。）'.repeat(2);
    const mail = buildMail({ from: FROM, to: 'a@b.co', subject, text: 'x' });
    const lines = mail.split('\r\n\r\n')[0].split('\r\n');
    const start = lines.findIndex((l) => l.startsWith('Subject: '));
    const parts = [lines[start].slice('Subject: '.length)];
    for (let i = start + 1; i < lines.length && lines[i].startsWith(' =?'); i++) parts.push(lines[i].trim());
    assert.ok(parts.length > 1, 'a long subject still wraps');
    const words = parts.map((p) => {
      assert.match(p, /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/, p);
      const text = Buffer.from(p.slice('=?UTF-8?B?'.length, -'?='.length), 'base64').toString('utf8');
      // One word carries up to 150 UTF-8 bytes (deliberately more than RFC 2047's 75-char recommendation, so a real
      // subject never folds); a word that splits is bounded by that budget.
      assert.ok(Buffer.byteLength(text, 'utf8') <= 150, `a word's bytes stay within the budget (${Buffer.byteLength(text, 'utf8')})`);
      return text;
    });
    for (const w of words) assert.ok(!/\uFFFD/.test(w), `every word decodes on its own (${JSON.stringify(w)})`);
    assert.equal(words.join(''), subject);
  });

  test('an all-ASCII subject stays readable, and a Chinese display name is encoded', () => {
    const plain = buildMail({ from: FROM, to: 'a@b.co', subject: 'Login code 123456', text: 'hi' });
    assert.match(plain, /^Subject: Login code 123456$/m);
    const named = buildMail({ from: '卫戍协议：盟约 <noreply@stronghold.example>', to: 'a@b.co', subject: 'Login code', text: 'hi' });
    const fromLine = named.split('\r\n')[0];
    assert.match(fromLine, /^From: =\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?= <noreply@stronghold\.example>$/);
    assert.equal(Buffer.from(/^From: =\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=/.exec(fromLine)[1], 'base64').toString('utf8'), '卫戍协议：盟约');
    const bare = buildMail({ from: FROM, to: 'a@b.co', subject: 's', text: 't' });
    assert.match(bare, /^From: noreply@stronghold\.example$/m, 'a bare address is left alone');
  });
});

describe('smtp: talking to a relay', () => {
  test('send() runs EHLO → MAIL FROM → RCPT TO → DATA → QUIT and delivers the message', async () => {
    const { r, port } = await relay();
    const smtp = createSmtp({ host: '127.0.0.1', port, from: FROM, timeoutMs: 5000 });
    await smtp.send({ to: 'player@example.com', subject: '注册验证码 654321', text: '你的注册验证码是：654321' });
    assert.deepEqual(r.state.commands.map((c) => c.split(' ')[0]), ['EHLO', 'MAIL', 'RCPT', 'DATA', 'QUIT']);
    assert.equal(r.state.commands[1], `MAIL FROM:<${FROM}>`);
    assert.equal(r.state.commands[2], 'RCPT TO:<player@example.com>');
    const data = r.state.data;
    assert.match(data, /^To: player@example\.com$/m);
    const body = data.split('\r\n\r\n')[1];
    assert.equal(Buffer.from(body.replace(/\r\n/g, ''), 'base64').toString('utf8'), '你的注册验证码是：654321');
    assert.equal(r.state.auth.length, 0, 'no credentials configured ⇒ no AUTH');
  });

  test('AUTH PLAIN is preferred, AUTH LOGIN works when it is the only mechanism', async () => {
    const plain = await relay({ authModes: ['PLAIN', 'LOGIN'] });
    await createSmtp({ host: '127.0.0.1', port: plain.port, from: FROM, user: 'bot', pass: 'pw', allowInsecureAuth: true, timeoutMs: 5000 })
      .send({ to: 'a@b.co', subject: 's', text: 't' });
    assert.deepEqual(plain.r.state.auth, ['PLAIN |bot|pw']);

    const login = await relay({ authModes: ['LOGIN'] });
    await createSmtp({ host: '127.0.0.1', port: login.port, from: FROM, user: 'bot', pass: 'pw', allowInsecureAuth: true, timeoutMs: 5000 })
      .send({ to: 'a@b.co', subject: 's', text: 't' });
    assert.deepEqual(login.r.state.auth, ['LOGIN bot / pw']);
  });

  test('a refused recipient fails with the relay own words', async () => {
    const { port } = await relay({ rcptCode: 550 });
    const smtp = createSmtp({ host: '127.0.0.1', port, from: FROM, timeoutMs: 5000 });
    await assert.rejects(() => smtp.send({ to: 'nobody@example.com', subject: 's', text: 't' }), (err) => {
      assert.match(err.message, /RCPT TO rejected: 550 5\.1\.1 no such user/);
      return true;
    });
  });

  test('the credentials are never sent over a cleartext link unless asked to', async () => {
    const { port } = await relay({ authModes: ['PLAIN'] });
    const strict = createSmtp({ host: '127.0.0.1', port, from: FROM, user: 'bot', pass: 'pw', timeoutMs: 5000 });
    const checked = await strict.verify();
    assert.equal(checked.ok, false);
    assert.match(checked.error, /cleartext/);
    await assert.rejects(() => strict.send({ to: 'a@b.co', subject: 's', text: 't' }), /cleartext/);
    const loose = createSmtp({ host: '127.0.0.1', port, from: FROM, user: 'bot', pass: 'pw', allowInsecureAuth: true, timeoutMs: 5000 });
    assert.deepEqual(await loose.verify(), { ok: true });
  });

  test('verify() answers instead of throwing, and reports a relay that is not there', async () => {
    const ok = await relay();
    assert.deepEqual(await createSmtp({ host: '127.0.0.1', port: ok.port, from: FROM, timeoutMs: 5000 }).verify(), { ok: true });
    const gone = await relay();
    const deadPort = gone.port;
    await gone.r.close();
    const res = await createSmtp({ host: '127.0.0.1', port: deadPort, from: FROM, timeoutMs: 3000 }).verify();
    assert.equal(res.ok, false);
    assert.match(res.error, /connect failed|timeout/);
  });

  test('a relay with no AUTH at all is reported when credentials are configured', async () => {
    const { port } = await relay({ authModes: [] });
    const res = await createSmtp({ host: '127.0.0.1', port, from: FROM, user: 'bot', pass: 'pw', allowInsecureAuth: true, timeoutMs: 5000 }).verify();
    assert.equal(res.ok, false);
    assert.match(res.error, /offers no AUTH/);
  });

  test('a message that is not accepted at DATA fails too', async () => {
    const server = net.createServer((socket) => {
      let buf = '';
      socket.write('220 strict-relay ESMTP\r\n');
      socket.on('data', (c) => {
        buf += c;
        while (buf.includes('\r\n')) {
          const line = buf.slice(0, buf.indexOf('\r\n'));
          buf = buf.slice(buf.indexOf('\r\n') + 2);
          const u = line.toUpperCase();
          if (u.startsWith('EHLO')) socket.write('250 ok\r\n');
          else if (u.startsWith('MAIL')) socket.write('250 ok\r\n');
          else if (u.startsWith('RCPT')) socket.write('250 ok\r\n');
          else if (u === 'DATA') socket.write('354 go\r\n');
          else if (u === 'QUIT') socket.write('221 bye\r\n');
          else if (line === '.') socket.write('552 5.3.4 message too big\r\n');
        }
      });
      socket.on('error', () => {});
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    relays.push({ close: () => new Promise((r) => server.close(() => r())) });
    await assert.rejects(() => createSmtp({ host: '127.0.0.1', port, from: FROM, timeoutMs: 5000 }).send({ to: 'a@b.co', subject: 's', text: 't' }), /DATA rejected: 552/);
  });
});
