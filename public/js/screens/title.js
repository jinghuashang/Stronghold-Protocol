// Title screen: season-style backdrop, big title 卫戍协议：盟约, remembered nickname, 开始, and a minimal account
// panel (登录 / 注册, DESIGN §25) beside the guest flow.
//
// Pressing 开始 validates the nickname (1..NAME_MAX_LEN chars, no control characters), stores it,
// marks this tab as "entered" (so reloads skip the title) and hands the name to net.js, which
// sends `hello` (now, or as soon as the socket is open). The router then shows the lobby.
//
// The account panel is optional: 开始 stays the guest path and is unchanged. 注册 takes two steps — an e-mail, 发送验证码,
// then the 6-digit code + 昵称 + password — and 登录 is an e-mail and a password. The server answers `auth.ok` with the
// account token; main.js stores it and every later `hello` carries it as `auth`, so any device that proves it becomes
// the same player (the same seat, room and match). An older server that does not know the intents — or one with the
// account feature off (`ACCOUNTS=off`, no SMTP) — hides the panel entirely and the guest flow carries on; a login that
// fails shows its reason in the panel, never as a toast.
//
// Backdrop art: if data/assets.json lists a UI backdrop (`ui.titleBackdrop`, or one of the
// entry/loading illustration names) it is layered under the CSS art; otherwise the screen is
// pure CSS/SVG (radar, ridgelines, glow), so it never issues a request that can 404.

import { useEffect, useMemo, useRef, useState } from '../../vendor/hooks.module.js';
import { NAME_MAX_LEN, APP_VERSION } from '../../../shared/constants.js';
import { ACCOUNT, EMAIL_RE } from '../../../shared/protocol.js';
import { html, Button, Icon, MicroLabel, TextField, PingPill } from '../ui/components.js';
import { GuideButton } from '../ui/guide.js';
import { toast } from '../ui/toasts.js';
import { net, identity, authErrorText } from '../net.js';
import { store, useStore, shallowEqual } from '../store.js';
import { data, useData } from '../data.js';
import { FullscreenButton, detectFeatures } from '../ui/device.js';
import { GIcon } from '../ui/gameComponents.js';
import { SettingsModal } from '../ui/settings.js';

// Same character classes as server/net.js sanitizeName (control, zero-width, bidi, BOM), so a name
// the client accepts is never rejected by the server's hello validation.
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g;
// Lone surrogates are removed by a scan, not a regex: the lookbehind such a regex needs is a *syntax error* in Safari
// < 16.4, which would stop the whole client from loading there.
export function stripLoneSurrogates(str) {
  let out = '';
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = i + 1 < str.length ? str.charCodeAt(i + 1) : 0;
      if (n >= 0xdc00 && n <= 0xdfff) { out += str[i] + str[i + 1]; i++; }
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) continue;
    out += str[i];
  }
  return out;
}

/**
 * Normalise a nickname like the server does (NFC, strip lone surrogates / control / invisible /
 * bidi characters, collapse whitespace, trim), then clamp to NAME_MAX_LEN UTF-16 code units — the
 * protocol's `hello.name` limit — without splitting a surrogate pair.
 * @param {any} raw
 * @returns {string}
 */
export function sanitizeName(raw) {
  let s = String(raw ?? '');
  try { s = s.normalize('NFC'); } catch { /* keep as is */ }
  s = stripLoneSurrogates(s).replace(/\s+/g, ' ').replace(CONTROL_CHARS, '').replace(/ {2,}/g, ' ').trim();
  if (s.length > NAME_MAX_LEN) {
    s = s.slice(0, NAME_MAX_LEN);
    // Don't leave half a surrogate pair at the end.
    if (/[\ud800-\udbff]$/.test(s)) s = s.slice(0, -1);
    s = s.trim();
  }
  return s;
}

/** @param {any} raw @returns {boolean} */
export const isValidName = (raw) => sanitizeName(raw).length > 0;

/**
 * Enter the game shell with a nickname (title → lobby).
 * @param {string} rawName
 * @returns {boolean} false when the name is invalid
 */
export function enterSession(rawName) {
  const name = sanitizeName(rawName);
  if (!name) return false;
  identity.saveName(name);
  identity.setEntered(true);
  store.set((s) => ({ me: { ...s.me, name }, session: { ...s.session, entered: true } }));
  net.setName(name);
  return true;
}

// data/assets.json `ui` keys are 'group/key' (docs/ASSETS.md).
const BACKDROP_KEYS = ['titleBackdrop', 'entry/bkg_01', 'entry/bkg_02'];
const RIDGE_KEYS = ['titleRidges', 'entry/bg_mountains_tiled'];

/**
 * Find a UI image URL in data/assets.json (tolerant of a few plausible shapes).
 * @param {any} assets
 * @param {string[]} names
 * @returns {string|null}
 */
export function findUiAsset(assets, names) {
  if (!assets || typeof assets !== 'object') return null;
  const asUrl = (v) => {
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object') return v.url || v.path || v.src || null;
    return null;
  };
  const ui = assets.ui;
  if (ui && typeof ui === 'object' && !Array.isArray(ui)) {
    for (const n of names) {
      const u = asUrl(ui[n]);
      if (u) return u;
    }
  }
  const lists = [Array.isArray(ui) ? ui : null, Array.isArray(assets.files) ? assets.files : null].filter(Boolean);
  for (const list of lists) {
    for (const n of names) {
      const hit = list.map(asUrl).find((u) => typeof u === 'string' && u.includes('/ui/') && u.toLowerCase().split('/').pop().startsWith(n.toLowerCase()));
      if (hit) return hit;
    }
  }
  return null;
}

// Dot-matrix watchtower emblem (13×14 bitmap; dots grow toward the base for depth).
const EMBLEM = [
  'XXX..XXX..XXX',
  'XXX..XXX..XXX',
  'XXXXXXXXXXXXX',
  '.XXXXXXXXXXX.',
  '..XXXXXXXXX..',
  '..XXXXXXXXX..',
  '..XXXX.XXXX..',
  '..XXXX.XXXX..',
  '..XXXXXXXXX..',
  '..XXXXXXXXX..',
  '..XXXXXXXXX..',
  '.XXXXXXXXXXX.',
  'XXXXXXXXXXXXX',
  'XXXXXXXXXXXXX',
];

function Emblem() {
  const dots = useMemo(() => {
    const out = [];
    EMBLEM.forEach((row, r) => {
      [...row].forEach((ch, c) => {
        if (ch !== 'X') return;
        const rad = 0.2 + (r / (EMBLEM.length - 1)) * 0.2;
        const accent = (r === 6 || r === 7) && (c === 5 || c === 7);
        out.push({ cx: c + 0.5, cy: r + 0.5, r: rad, accent, d: (r * 13 + c) % 7 });
      });
    });
    return out;
  }, []);
  return html`<div class="emblem" aria-hidden="true">
    <span class="emblem__bracket emblem__bracket--l"></span>
    <svg class="emblem__svg" viewBox="-0.5 -0.5 14 15">
      ${dots.map((d, i) => html`<circle key=${i} cx=${d.cx} cy=${d.cy} r=${d.r} class=${d.accent ? 'is-accent' : `d${d.d}`} />`)}
    </svg>
    <span class="emblem__bracket emblem__bracket--r"></span>
  </div>`;
}

function Ridges() {
  return html`<svg class="title-bg__ridges" viewBox="0 0 1920 420" preserveAspectRatio="none" aria-hidden="true">
    <defs>
      <linearGradient id="ridge-far" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="#16231f" /><stop offset="1" stop-color="#0a0e0d" />
      </linearGradient>
      <linearGradient id="ridge-near" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="#0f1714" /><stop offset=".6" stop-color="#080b0a" />
      </linearGradient>
      <linearGradient id="ridge-edge" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0" stop-color="#17f9b7" stop-opacity="0" />
        <stop offset=".3" stop-color="#17f9b7" stop-opacity=".55" />
        <stop offset=".7" stop-color="#17f9b7" stop-opacity=".55" />
        <stop offset="1" stop-color="#17f9b7" stop-opacity="0" />
      </linearGradient>
    </defs>
    <path class="ridge ridge--far" fill="url(#ridge-far)" stroke="url(#ridge-edge)"
      d="M0 420V250l120-40 90 30 90-70 60 20 80-70 80 55 80-25 90 70 90-20 80 50 100-15 90 25 90-55 90-55 70-55 70 45 80-20 90 65 80-20 100 55 100-20 100 40v180z" />
    <path class="ridge ridge--near" fill="url(#ridge-near)" stroke="url(#ridge-edge)"
      d="M0 420V322l160-32 100 20 120-50 90 40 130-20 120 50 140-30 140 35 120-35 140 20 140-50 120 30 120-20 120 40 160-20v147z" />
  </svg>`;
}

const STATUS_TEXT = {
  idle: '准备连接', connecting: '正在连接服务器', connected: '已连接服务器', handshaking: '正在验证身份',
  online: '已连接服务器', reconnecting: '连接中断，正在重连', closed: '连接已关闭',
};

/**
 * Password box in the TextField look: ui/components.js TextField has no `type` prop and is shared with every other
 * screen, so this twin repeats its markup (same `field` classes, same composition handling) with `type="password"`.
 * Enter submits, exactly like the CALLSIGN field above it.
 */
function PasswordField({ label = '密码', micro, value, onInput, onEnter, placeholder = `输入密码（至少 ${ACCOUNT.passwordMin} 位）`, autoComplete, disabled, autoFocus, hint, invalid }) {
  const composing = useRef(false);
  const inputRef = useRef(null);
  const id = useMemo(() => `pw-${Math.random().toString(36).slice(2, 8)}`, []);
  useEffect(() => { if (autoFocus) setTimeout(() => inputRef.current?.focus(), 60); }, []);
  const handle = (e) => { if (!composing.current) onInput?.(e.currentTarget.value); };
  return html`<label class=${`field field--md${invalid ? ' is-invalid' : ''}`} for=${id}>
    <span class="field__label">${label}${micro ? html`<span class="micro">${micro}</span>` : null}</span>
    <span class="field__box brackets">
      <${Icon} name="key" class="field__icon" />
      <input id=${id} ref=${inputRef} class="field__input" type="password" name="password" value=${value}
        placeholder=${placeholder} maxLength=${ACCOUNT.passwordMax} disabled=${disabled}
        autocomplete=${autoComplete || 'current-password'} spellcheck=${false}
        onInput=${handle}
        oncompositionstart=${() => { composing.current = true; }}
        oncompositionend=${(e) => { composing.current = false; handle(e); }}
        onKeyDown=${(e) => { if (e.key === 'Enter' && !e.isComposing && !composing.current) onEnter?.(e); }} />
    </span>
    ${hint ? html`<span class="field__hint">${hint}</span>` : null}
  </label>`;
}

/**
 * E-mail box in the TextField look (shared with every screen's CALLSIGN field): ui/components.js TextField is fine
 * as it is, so the account panel uses it — this wrapper only fixes the label/micro a caller of the panel would repeat.
 */
function EmailField({ value, onInput, onEnter, disabled, invalid, autoFocus }) {
  return html`<${TextField} label="邮箱" micro="E-MAIL" size="md" icon="link" name="email" value=${value}
    maxLength=${ACCOUNT.emailMax} placeholder="you@example.com" invalid=${invalid} disabled=${disabled}
    autoFocus=${autoFocus} onInput=${onInput} onEnter=${onEnter} />`;
}

/** Verification-code box (6 digits, numeric keypad on phones). */
function CodeField({ value, onInput, onEnter, disabled, invalid }) {
  const composing = useRef(false);
  const id = useMemo(() => `code-${Math.random().toString(36).slice(2, 8)}`, []);
  return html`<label class=${`field field--md${invalid ? ' is-invalid' : ''}`} for=${id}>
    <span class="field__label">验证码<span class="micro">CODE</span></span>
    <span class="field__box brackets">
      <${Icon} name="key" class="field__icon" />
      <input id=${id} class="field__input" type="text" name="code" inputmode="numeric" autocomplete="one-time-code"
        spellcheck=${false} maxLength=${ACCOUNT.codeLength} placeholder=${'0'.repeat(ACCOUNT.codeLength)} value=${value}
        disabled=${disabled}
        onInput=${(e) => { if (!composing.current) onInput?.(e.currentTarget.value.replace(/[^0-9]/g, '')); }}
        oncompositionstart=${() => { composing.current = true; }}
        oncompositionend=${(e) => { composing.current = false; onInput?.(e.currentTarget.value.replace(/[^0-9]/g, '')); }}
        onKeyDown=${(e) => { if (e.key === 'Enter' && !e.isComposing && !composing.current) onEnter?.(e); }} />
    </span>
  </label>`;
}

/** Big, centred 6-digit message: the one line the mail carries. */
const CODE_SENT_TEXT = (ttlSec) => `验证码已发送（${Math.round(ttlSec / 60)} 分钟内有效）`;

const AUTH_MODE = { LOGIN: 'login', REGISTER: 'register', RESET: 'reset' };

/**
 * Account panel under 开始 (server/accounts.js, DESIGN §25): 账号登录 (e-mail + password) or 注册 in two steps —
 * e-mail → 发送验证码, then 验证码 + 昵称 + 密码 → 完成注册 — or the signed-in account with 退出. A guest is the default
 * and 开始 is untouched: an account only adds the stable playerId behind the name, which is what lets the same player
 * take over their seat from another device (the phone signs in with the same address and password and the server
 * closes the other socket with 4001 for it).
 *
 * The panel hides itself when the server has no account feature (`store.ui.accountsOff`: ACCOUNTS=off, an incomplete
 * SMTP configuration, an older server — see main.js), and every failure is shown here, never as a toast.
 *
 * @param {{ name: string, autoFocusPassword?: boolean }} props the current 博士代号 value (the nickname a registration
 *   is filed under); touch devices pass `autoFocusPassword: false` (an on-screen keyboard would cover the panel)
 */
function AuthPanel({ name, autoFocusPassword = false }) {
  const account = useStore((s) => s.account);
  const accountsOff = useStore((s) => !!s.ui.accountsOff);
  const [mode, setMode] = useState(AUTH_MODE.LOGIN);
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState('');
  const [sentEmail, setSentEmail] = useState('');
  const [code, setCode] = useState('');
  const [nickname, setNickname] = useState('');
  const [password, setPassword] = useState('');
  const [wait, setWait] = useState(0);   // seconds left before another code may be asked for
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // the 60 s resend countdown (one timer per second while it runs)
  useEffect(() => {
    if (wait <= 0) return undefined;
    const t = setTimeout(() => setWait((s) => (s > 0 ? s - 1 : 0)), 1000);
    return () => clearTimeout(t);
  }, [wait]);

  const address = email.trim().toLowerCase();
  const emailOk = address.length > 0 && address.length <= ACCOUNT.emailMax && EMAIL_RE.test(address);
  // The nickname lives in the panel, not in the guest 博士代号 field above it: a player who never pressed 开始 has no
  // reason to connect the two, and a disabled 完成注册 buttons explains nothing (the field is prefilled from the guest
  // field when the panel opens, and the guest field is synced back once the account exists).
  const nick = sanitizeName(nickname);
  const nickOk = [...nick].length >= ACCOUNT.nameMin;
  const codeOk = new RegExp(`^[0-9]{${ACCOUNT.codeLength}}$`).test(code);
  // What is still missing, said out loud next to the button (a disabled button alone is the trap this fixes).
  const nickHint = !nickname.trim() ? `请输入昵称（${ACCOUNT.nameMin}–${ACCOUNT.nameMax} 字）` : (nickOk ? '' : `昵称需 ${ACCOUNT.nameMin}–${ACCOUNT.nameMax} 字，当前 ${[...nick].length} 字`);

  const pick = (m) => {
    if (m === AUTH_MODE.REGISTER) setNickname((v) => v || sanitizeName(name)); // prefill from the guest field
    setMode(m);
    setOpen(true);
    setError('');
  };
  const reset = () => { setPassword(''); setCode(''); setError(''); };

  /** Leave the account: forget the token *before* asking the server, so a failed request can never re-login us. */
  const signOut = () => {
    identity.clearAccountToken();
    store.set({ account: null });
    setOpen(false);
    reset();
    net.request('auth.logout').catch(() => {}); // best effort: revoke the credential server-side too
    toast('已退出账号，将以游客身份开始', 'info');
  };

  /** Step 1 (both flows): mail a code to the address in the field — a registration or a password-reset one. */
  const sendCode = async () => {
    if (busy) return;
    if (!emailOk) { setError(authErrorText('bad_email')); return; }
    setBusy(true);
    setError('');
    try {
      const res = await net.request(mode === AUTH_MODE.RESET ? 'auth.requestReset' : 'auth.requestCode', { email: address }, { session: false });
      setSentEmail(res?.email ? String(res.email) : address);
      setCode('');
      setWait(ACCOUNT.resendSec);
    } catch (err) {
      setError(authErrorText(err?.code, err?.serverMsg || err?.message));
    } finally {
      setBusy(false);
    }
  };

  /** Step 2 of 注册: prove the address, name the account and set a password. */
  const submitRegister = async () => {
    if (busy) return;
    if (!sentEmail) { setError(authErrorText('bad_email')); return; }
    if (!nickOk) { setError(authErrorText('bad_name')); return; }
    if (!codeOk) { setError(authErrorText('bad_code')); return; }
    if ([...password].length < ACCOUNT.passwordMin) { setError(authErrorText('bad_password')); return; }
    setBusy(true);
    setError('');
    try {
      // No session of our own yet: the server creates one for the account and answers `welcome` (with the session
      // token) right after `auth.ok`, which is what main.js stores.
      const msg = await net.request('auth.register', { email: sentEmail, code, name: nick, password }, { session: false });
      reset();
      setOpen(false);
      setSentEmail('');
      toast(`注册成功，已登录：${msg.name}`, 'success');
    } catch (err) {
      setError(authErrorText(err?.code, err?.serverMsg || err?.message));
    } finally {
      setBusy(false);
    }
  };

  /** Step 2 of 忘记密码: prove the address, set a new password — and the answer is a login (every old token is gone). */
  const submitReset = async () => {
    if (busy) return;
    if (!sentEmail) { setError(authErrorText('bad_email')); return; }
    if (!codeOk) { setError(authErrorText('bad_code')); return; }
    if ([...password].length < ACCOUNT.passwordMin) { setError(authErrorText('bad_password')); return; }
    setBusy(true);
    setError('');
    try {
      const msg = await net.request('auth.resetPassword', { email: sentEmail, code, password }, { session: false });
      reset();
      setOpen(false);
      setSentEmail('');
      toast(`密码已重置，已登录：${msg.name}`, 'success');
    } catch (err) {
      setError(authErrorText(err?.code, err?.serverMsg || err?.message));
    } finally {
      setBusy(false);
    }
  };

  const submitLogin = async () => {
    if (busy) return;
    if (!emailOk) { setError(authErrorText('bad_email')); return; }
    if (!password) { setError(authErrorText('bad_credentials')); return; }
    setBusy(true);
    setError('');
    try {
      const msg = await net.request('auth.login', { email: address, password }, { session: false });
      reset();
      setOpen(false);
      toast(`已登录：${msg.name}`, 'success');
    } catch (err) {
      setError(authErrorText(err?.code, err?.serverMsg || err?.message));
    } finally {
      setBusy(false);
    }
  };

  // This server has no account feature at all (ACCOUNTS=off, no SMTP, or an older server): no entries, and one quiet
  // line so the missing login button is explained rather than mysterious.
  if (accountsOff) return html`<${MicroLabel}>当前服务器未开启账号系统，请以游客身份开始<//>`;

  const rowStyle = 'display:flex;align-items:center;gap:.08rem';
  const isRegister = mode === AUTH_MODE.REGISTER;
  const isReset = mode === AUTH_MODE.RESET;
  const codeFlow = isRegister || isReset;
  const step2 = codeFlow && !!sentEmail;
  const step1Label = isReset ? '发送重置码' : '发送验证码';
  const submitStep2 = isReset ? submitReset : submitRegister;
  return html`<div style="display:flex;flex-direction:column;gap:.1rem">
    ${account ? html`<div style=${rowStyle}>
      <span class="status-dot is-on"></span>
      <${MicroLabel}>ACCOUNT<//>
      <b style="color:var(--mint-glow);font-size:.15rem">${account.name}</b>
      <span style="flex:1"></span>
      <${Button} size="sm" variant="ghost" icon="exit" title="退出账号" onClick=${signOut}>退出<//>
    </div>` : html`<div style=${rowStyle}>
      <${Button} size="sm" variant="ghost" block=${true} icon="key" active=${open && mode === AUTH_MODE.LOGIN}
        onClick=${() => pick(AUTH_MODE.LOGIN)}>账号登录<//>
      <${Button} size="sm" variant="ghost" block=${true} icon="plus" active=${open && isRegister}
        onClick=${() => pick(AUTH_MODE.REGISTER)}>注册<//>
    </div>`}

    ${!account && open && mode === AUTH_MODE.LOGIN ? html`<${EmailField} value=${email} disabled=${busy}
      invalid=${!!error} autoFocus=${autoFocusPassword} onInput=${setEmail} onEnter=${submitLogin} />` : null}
    ${!account && open && mode === AUTH_MODE.LOGIN ? html`<${PasswordField} value=${password} micro="PASSWORD"
      disabled=${busy} invalid=${!!error} autoComplete="current-password" onInput=${setPassword} onEnter=${submitLogin} />` : null}
    ${!account && open && mode === AUTH_MODE.LOGIN ? html`<${Button} variant="secondary" size="md" block=${true} loading=${busy}
      icon="check" disabled=${busy || !emailOk || !password} onClick=${submitLogin}>登录<//>` : null}
    ${!account && open && mode === AUTH_MODE.LOGIN ? html`<div style=${rowStyle}>
      <${Button} size="sm" variant="ghost" onClick=${() => pick(AUTH_MODE.RESET)}>忘记密码<//>
      <span style="flex:1"></span>
      <${MicroLabel}>用邮箱重置密码，无需旧密码<//>
    </div>` : null}

    ${!account && open && isRegister ? html`<${TextField} label="昵称" micro="CALLSIGN" size="md" icon="user" name="nickname"
      value=${nickname} maxLength=${NAME_MAX_LEN} invalid=${!nickOk && !!nickname.trim()}
      placeholder=${`输入你的代号（最多 ${NAME_MAX_LEN} 字）`}
      onInput=${setNickname} onEnter=${step2 ? submitStep2 : sendCode} />` : null}
    ${!account && open && isRegister && nickHint ? html`<${MicroLabel}>${nickHint}<//>` : null}
    ${!account && open && codeFlow ? html`<${EmailField} value=${email} disabled=${busy}
      invalid=${!!error} autoFocus=${autoFocusPassword} onInput=${setEmail} onEnter=${sendCode} />` : null}
    ${!account && open && codeFlow ? html`<${Button} variant=${step2 ? 'ghost' : 'secondary'} size="md"
      block=${true} loading=${busy && !step2} icon=${step2 ? 'refresh' : 'key'} disabled=${busy || !emailOk || wait > 0}
      onClick=${sendCode}>${step2 ? (wait > 0 ? `重发（${wait}s）` : '重新发送') : step1Label}<//>` : null}
    ${!account && open && step2 ? html`<${MicroLabel}>${CODE_SENT_TEXT(ACCOUNT.codeTtlSec)}<//>` : null}
    ${!account && open && step2 ? html`<${CodeField} value=${code} disabled=${busy} invalid=${!!error}
      onInput=${setCode} onEnter=${submitStep2} />` : null}
    ${!account && open && step2 ? html`<${PasswordField} value=${password} micro=${isReset ? 'NEW PASSWORD' : 'NEW PASSWORD'}
      disabled=${busy} invalid=${!!error} autoComplete="new-password" onInput=${setPassword} onEnter=${submitStep2} />` : null}
    ${!account && open && step2 ? html`<${Button} variant="secondary" size="md" block=${true} loading=${busy}
      icon=${isReset ? 'refresh' : 'plus'} disabled=${busy || !codeOk || !password || (isRegister && !nickOk)} onClick=${submitStep2}>${isReset ? '重置并登录' : '完成注册'}<//>` : null}
    ${!account && open && step2 && isRegister ? html`<${MicroLabel}>${nickOk
      ? `昵称：${nick}`
      : `填写上方的昵称即可完成注册（${nickHint}）`}<//>` : null}
    ${!account && open && codeFlow ? html`<${MicroLabel}>${isReset
      ? '重置成功后其他设备会全部退出登录，本机直接进入已登录状态'
      : '注册后可在手机等设备上登录，继续同一局'}<//>` : null}
    ${!account && open && codeFlow && isReset ? html`<div style=${rowStyle}>
      <${Button} size="sm" variant="ghost" onClick=${() => pick(AUTH_MODE.LOGIN)}>返回登录<//>
    </div>` : null}
    ${!account && open && mode === AUTH_MODE.LOGIN ? html`<${MicroLabel}>登录后可在其他设备接管当前同盟与对局<//>` : null}
    ${!account && !open ? html`<${MicroLabel}>账号可选：以游客身份也可直接开始<//>` : null}
    ${error ? html`<div style="font-size:.13rem;color:var(--red-premium);line-height:1.4">${error}</div>` : null}
  </div>`;
}

/** Title screen component. */
export function TitleScreen() {
  const conn = useStore((s) => s.connection, shallowEqual);
  const pendingJoin = useStore((s) => s.ui.pendingJoin);
  const accountName = useStore((s) => s.account?.name ?? null);
  const [name, setName] = useState(() => store.get().me.name || identity.loadName() || '');
  // Signing in renames the player server-side (the account's name wins): show that name in the field the guest 开始
  // button sends, so pressing 开始 right after a login keeps the identity the account was bound with.
  useEffect(() => { if (accountName) setName(sanitizeName(accountName)); }, [accountName]);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const assetsSettled = useData('assets');
  const assets = data.get('assets');
  const backdrop = findUiAsset(assets, BACKDROP_KEYS);
  const ridges = findUiAsset(assets, RIDGE_KEYS);
  // Track load/fail per URL (not as booleans reset in effects: an image can load before an effect runs).
  const [bgLoadedUrl, setBgLoadedUrl] = useState(null);
  const [ridgesLoadedUrl, setRidgesLoadedUrl] = useState(null);
  const [ridgesFailedUrl, setRidgesFailedUrl] = useState(null);
  const bgLoaded = !!backdrop && bgLoadedUrl === backdrop;
  const ridgesLoaded = !!ridges && ridgesLoadedUrl === ridges;
  const ridgesFailed = !!ridges && ridgesFailedUrl === ridges;
  // CSS ridgelines only when there is no ridge art (avoids a swap flash when the art arrives).
  const cssRidges = assetsSettled && (!ridges || ridgesFailed);

  const valid = isValidName(name);
  const start = () => {
    if (!valid) { toast('请输入博士代号', 'warn'); return; }
    enterSession(name);
  };

  const online = conn.status === 'online' || conn.status === 'connected';
  const dotClass = online ? 'is-on' : conn.status === 'reconnecting' || conn.status === 'connecting' || conn.status === 'handshaking' ? 'is-warn' : 'is-bad';

  // touch screens: no autofocus (it would pop the on-screen keyboard over a landscape phone's whole view)
  const touchUi = useMemo(() => detectFeatures().coarse, []);
  return html`<div class="screen title-screen">
    <div class=${`title-bg${bgLoaded ? ' has-art' : ''}${ridgesLoaded ? ' has-ridges' : ''}`} aria-hidden="true">
      ${backdrop ? html`<img class="title-bg__art" src=${backdrop} alt="" draggable=${false}
        onLoad=${() => setBgLoadedUrl(backdrop)} />` : null}
      <div class="title-bg__glow"></div>
      <div class="title-bg__radar"><div class="title-bg__sweep"></div></div>
      <div class="title-bg__target"></div>
      ${cssRidges ? html`<${Ridges} />` : null}
      ${ridges && !ridgesFailed ? html`<div class="title-bg__ridge-art" style=${`background-image:url("${ridges}")`}>
        <img src=${ridges} alt="" hidden onLoad=${() => setRidgesLoadedUrl(ridges)} onError=${() => setRidgesFailedUrl(ridges)} />
      </div>` : null}
      <div class="title-bg__haze"></div>
      <span class="cross" style="left:7%;top:22%"></span>
      <span class="cross" style="left:93%;top:30%"></span>
      <span class="cross" style="left:14%;top:70%"></span>
      <span class="cross" style="left:88%;top:62%"></span>
      <span class="cross" style="left:60%;top:12%"></span>
    </div>

    <div class="title-corner title-corner--tl">
      <span class="title-corner__mark"></span>
      <div><${MicroLabel} tone="mint">RHODES ISLAND // SIMULATION SERVICE<//><br /><${MicroLabel}>TACTICAL CO-OP NODE · 02<//></div>
    </div>
    <div class="title-corner title-corner--tr">
      <${MicroLabel} tone="hi">TARGET POINT<//><br /><${MicroLabel}>STRONGHOLD PROTOCOL<//>
    </div>

    <div class="screen__scroll title-screen__scroll">
    <main class="title-main">
      <${Emblem} />
      <div class="title-en">
        <span class="title-en__a">STRONGHOLD PROTOCOL</span>
        <span class="title-en__b">ALLIANCE</span>
      </div>
      <h1 class="title-cn">卫戍协议<span class="title-cn__colon">：</span><em>盟约</em></h1>
      <p class="title-tag">调配资金与干员，与同伴协同布防，抵御多波次进攻，直至击败敌方领袖。</p>

      <div class="title-login">
        ${pendingJoin ? html`<div class="title-invite">
          <${Icon} name="key" />
          <span>收到同盟邀请</span><b class="num">${pendingJoin}</b><span class="t-lo">· 输入代号后将自动加入</span>
        </div>` : null}
        <${TextField} label="博士代号" micro="CALLSIGN" size="lg" icon="user" value=${name} maxLength=${NAME_MAX_LEN}
          placeholder="输入你的代号（最多 ${NAME_MAX_LEN} 字）" autoFocus=${!touchUi}
          onInput=${setName} onEnter=${start} />
        <${Button} variant="primary" size="xl" block=${true} iconRight="chevrons" disabled=${!valid} onClick=${start}>开始<//>
        <${AuthPanel} name=${name} autoFocusPassword=${!touchUi} />
        <div class="title-conn">
          <span class=${`status-dot ${dotClass}`}></span>
          <span>${STATUS_TEXT[conn.status] || conn.status}</span>
          ${conn.status === 'online' ? html`<${PingPill} ms=${conn.ping} />` : null}
          <${GuideButton} class="title-guide" />
          <button type="button" class="title-settings fsbtn tapx" aria-label="设置" title="设置"
            onClick=${() => setSettingsOpen(true)}><${GIcon} name="gear" /></button>
          <${FullscreenButton} class="title-fs" />
        </div>
      </div>
    </main>
    </div>

    <${SettingsModal} open=${settingsOpen} onClose=${() => setSettingsOpen(false)} />

    <footer class="title-foot">
      <span>非官方同人复刻 · 游戏素材版权归 上海鹰角网络 / Yostar 所有</span>
      <${MicroLabel}>v${APP_VERSION} · WEB SIMULATION<//>
    </footer>
  </div>`;
}
