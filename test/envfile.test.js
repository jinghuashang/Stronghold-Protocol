// test/envfile.test.js — server/envfile.js (DESIGN §25.3): the project-root .env the CLI entry point reads.
// The forms an operator actually writes (plain, quoted, `export`, cmd's `set K=V` and `set "K=V"`, comments including
// `rem`), the promise that a real environment variable always wins, and the never-throwing behaviour on a missing
// file. `env` is injected so the tests never touch this process's own environment.
import { describe, test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { loadEnvFile } from '../server/envfile.js';

const dir = mkdtempSync(path.join(tmpdir(), 'sp-envfile-'));
after(() => rmSync(dir, { recursive: true, force: true }));

let seq = 0;
/** Write a .env in the temp dir and load it into a fresh environment. @returns {{ env, result, file }} */
function load(text, env = {}) {
  const file = path.join(dir, `env-${++seq}`);
  writeFileSync(file, text);
  const result = loadEnvFile(file, { env });
  return { env, result, file };
}

describe('envfile: the syntaxes an operator writes', () => {
  test('plain, quoted, export, cmd set and cmd set "…" all work, and CRLF/LF/blank lines are fine', () => {
    const { env, result } = load([
      '# a comment',
      '',
      'SMTP_HOST=smtp.example',
      'SMTP_PORT="587"',
      'export SMTP_USER=bot',
      'set SMTP_PASS=secret',
      'set "SMTP_FROM=noreply@stronghold.example"',
      'set "SMTP_SECURE=1"',
      '',
    ].join('\r\n'));
    assert.equal(result.found, true);
    assert.equal(result.loaded, 6);
    assert.deepEqual(result.keys, ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM', 'SMTP_SECURE']);
    assert.deepEqual(env, {
      SMTP_HOST: 'smtp.example',
      SMTP_PORT: '587',
      SMTP_USER: 'bot',
      SMTP_PASS: 'secret',
      SMTP_FROM: 'noreply@stronghold.example',
      SMTP_SECURE: '1',
    });
  });

  test('a deploy script\'s own cmd file reads the same way, and `rem` lines never assign', () => {
    const { env } = load([
      '@echo off',
      'rem set "SMTP_HOST=should-not-win"',
      'REM set SMTP_USER=nope',
      '@rem commented out too',
      'set "SMTP_HOST=real.example"',
      'set SMTP_FROM=noreply@real.example',
    ].join('\n'));
    assert.equal(env.SMTP_HOST, 'real.example');
    assert.equal(env.SMTP_FROM, 'noreply@real.example');
    assert.equal('SMTP_USER' in env, false, 'a commented-out line stays a comment');
  });

  test('values keep spaces and the one quote layer is removed; an inline comment is dropped', () => {
    const { env } = load([
      'A=  spaced value  ',
      'B="quoted with # hash"',
      "C='single quoted'",
      'D=secret # my app password',
      'E=pass#word',
    ].join('\n'));
    assert.equal(env.A, 'spaced value');
    assert.equal(env.B, 'quoted with # hash');
    assert.equal(env.C, 'single quoted');
    assert.equal(env.D, 'secret');
    assert.equal(env.E, 'pass#word', 'a # without preceding whitespace stays in the value');
  });

  test('a real environment variable always wins, and empty ones count as unset', () => {
    const { env, result } = load('SMTP_HOST=from-file\nSMTP_USER=from-file\nSMTP_FROM=from-file\n', {
      SMTP_HOST: 'from-shell',
      SMTP_USER: '',
    });
    assert.equal(env.SMTP_HOST, 'from-shell', 'a non-empty environment value is never overwritten');
    assert.equal(env.SMTP_USER, 'from-file', 'an empty one is treated as unset');
    assert.equal(env.SMTP_FROM, 'from-file');
    assert.equal(result.loaded, 2);
    assert.deepEqual(result.keys, ['SMTP_USER', 'SMTP_FROM']);
    assert.deepEqual(result.skipped, ['SMTP_HOST']);
  });

  test('comment-only files and invalid lines are skipped without throwing', () => {
    const { env, result } = load('# nothing here\n\n   \n');
    assert.equal(result.found, true);
    assert.equal(result.loaded, 0);
    assert.deepEqual(env, {});
    const junk = load('not a variable\n1BAD=x\n=empty\nSMTP_HOST=ok\n', {}).result;
    assert.equal(junk.loaded, 1, 'only the valid line is applied');
  });

  test('comments and rem lines are ignored quietly — only a line that meant to be a variable warns', () => {
    const file = path.join(dir, 'warn.env');
    writeFileSync(file, ['rem accounts for the box', '# a comment', '', 'set "A=1"', 'a bare sentence', 'B=2'].join('\r\n'));
    const warns = [];
    const env = {};
    const result = loadEnvFile(file, { env, log: { warn: (m) => warns.push(m) } });
    assert.equal(result.loaded, 2);
    assert.deepEqual(result.keys, ['A', 'B']);
    assert.equal(warns.length, 1, 'one warning for the one invalid line');
    assert.match(warns[0], /1 line\(s\).*not KEY=VALUE/);
  });

  test('a missing or unreadable file answers found:false instead of throwing', () => {
    const env = {};
    const result = loadEnvFile(path.join(dir, 'does-not-exist'), { env });
    assert.deepEqual(result, { found: false, loaded: 0, keys: [], skipped: [] });
    assert.deepEqual(env, {});
    const asDir = loadEnvFile(dir, { env });
    assert.equal(asDir.found, false, 'a directory is not a file');
  });

  test('the default target is process.env — and the test restores it', () => {
    const before = { SP_ENVFILE_PROBE: process.env.SP_ENVFILE_PROBE, SMTP_HOST: process.env.SMTP_HOST };
    try {
      delete process.env.SP_ENVFILE_PROBE;
      process.env.SMTP_HOST = 'from-shell';
      const file = path.join(dir, 'process-env.env');
      writeFileSync(file, 'SP_ENVFILE_PROBE=loaded\nSMTP_HOST=from-file\n');
      const result = loadEnvFile(file);
      assert.equal(process.env.SP_ENVFILE_PROBE, 'loaded');
      assert.equal(process.env.SMTP_HOST, 'from-shell', 'the shell value wins');
      assert.deepEqual(result.keys, ['SP_ENVFILE_PROBE']);
    } finally {
      if (before.SP_ENVFILE_PROBE === undefined) delete process.env.SP_ENVFILE_PROBE;
      else process.env.SP_ENVFILE_PROBE = before.SP_ENVFILE_PROBE;
      if (before.SMTP_HOST === undefined) delete process.env.SMTP_HOST;
      else process.env.SMTP_HOST = before.SMTP_HOST;
    }
  });
});
