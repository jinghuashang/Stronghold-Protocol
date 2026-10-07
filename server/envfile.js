// server/envfile.js — the project-root `.env`, read by the CLI entry point only (`server/index.js main()`), no
// dependency: `npm start` must work with the SMTP settings written in one file instead of exported in every shell.
//
// What the file may contain (the subset an operator actually writes):
//   KEY=VALUE              the plain form
//   KEY="VALUE"            one layer of surrounding quotes is removed (so spaces and `#` are safe)
//   export KEY=VALUE       a shell-exported line is accepted verbatim
//   set KEY=VALUE          cmd / a Windows deploy script (D:\Game\accounts.env style), and
//   set "KEY=VALUE"        its quoted form — the same file can serve the launcher and this reader
//   # comment / rem …      ignored (`rem set "X=1"` is a comment, never an assignment)
//   blank line / CRLF      ignored; a trailing newline is fine
// A line whose key is not `[A-Za-z_][A-Za-z0-9_]*` is skipped (a typo must not silently do nothing — `keys` and the
// caller's log line make the effective set visible). An unquoted value ending in ` # …` is read as a comment, the
// usual .env convention, so `SMTP_PASS=secret # my app password` keeps working.
//
// A key that is already set to a non-empty value in `process.env` is **never** overwritten: a real environment
// variable (a shell export, a service unit, `docker -e`) always wins over the file, which is what makes a one-off
// override possible. Empty values in `process.env` count as unset.
//
// The reader never throws: a missing or unreadable file answers `{ found: false, loaded: 0, keys: [] }`.

import fs from 'node:fs';

/**
 * One `KEY=VALUE` line → `[key, value]`.
 * `undefined` = nothing to read at all (blank, `#` comment, `rem …`), `null` = a line that meant to be a variable but
 * is not valid (the caller warns about those: a typo must not silently do nothing while a comment stays quiet).
 */
function parseLine(line) {
  let raw = line.replace(/\r$/, '').trim();
  if (!raw || raw.startsWith('#')) return undefined;
  // cmd's own comment (`rem …`), including `rem set "X=1"`: the reader must not be fooled by a commented-out line.
  if (/^@?rem(\s|$)/i.test(raw)) return undefined;
  // Shell syntaxes seen in practice: `export KEY=VALUE` (sh) and `set KEY=VALUE` / `set "KEY=VALUE"` (cmd, the form a
  // Windows deploy script already writes — the same file can then serve both).
  raw = raw.replace(/^@?(export|set)\s+/i, '');
  // `set "KEY=VALUE"` quotes the whole assignment: unwrap it before splitting on the first `=`.
  const whole = /^"([\s\S]*)"$/.exec(raw);
  if (whole && /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(whole[1])) raw = whole[1].trim();
  const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([\s\S]*)$/.exec(raw);
  if (!m) return null; // meant to be a variable, is not one: the caller warns
  let value = m[2];
  const quoted = /^(["'])([\s\S]*)\1$/.exec(value);
  if (quoted) value = quoted[2];
  else {
    const comment = /\s#/.exec(value);
    if (comment) value = value.slice(0, comment.index);
  }
  return [m[1], value.trim()];
}

/**
 * Load `file` into an environment object (default `process.env`).
 *
 * @param {string} file
 * @param {{ env?: Record<string, string | undefined>, log?: { warn?: Function } }} [opts]
 * @returns {{ found: boolean, loaded: number, keys: string[], skipped: string[] }}
 *   `found` = the file could be read, `loaded` = how many variables it actually set, `keys` = those names,
 *   `skipped` = the names already present in the environment (kept, not overwritten).
 */
export function loadEnvFile(file, { env = process.env, log = null } = {}) {
  let text = null;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return { found: false, loaded: 0, keys: [], skipped: [] };
  }
  const keys = [];
  const skipped = [];
  let invalid = 0;
  for (const line of text.split('\n')) {
    const trimmed = line.replace(/\r$/, '').trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parsed = parseLine(line);
    if (parsed === undefined) continue;   // blank / comment / rem: quietly ignored
    if (parsed === null) { invalid += 1; continue; }
    const [key, value] = parsed;
    const current = env[key];
    if (typeof current === 'string' && current !== '') { skipped.push(key); continue; } // a real variable wins
    env[key] = value;
    keys.push(key);
  }
  if (invalid) log?.warn?.(`[env] ${invalid} line(s) in ${file} are not KEY=VALUE and were ignored`);
  return { found: true, loaded: keys.length, keys, skipped };
}
