// test/proxyprotocol.test.js — server/proxyprotocol.js: HAProxy's PROXY protocol v1/v2 on the game's own listener.
//
// The user-visible promise: a balancer in front (HAProxy `send-proxy*`, an frp/nginx stream listener, Cloudflare
// Spectrum) hands us the real client address *before* the HTTP bytes, and the per-network limits + the room's
// client records key on that address — even though the socket peer is the balancer. Everything here runs on real
// sockets: the header must be consumed and the rest of the stream handed to the http server untouched (HTTP and the
// /ws upgrade alike), a garbage/missing header must not be served, and `clientAddress` must prefer the header.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { parseProxyProtocol, matchProxyHeader, createProxyProtocolListener } from '../server/proxyprotocol.js';
import { startServer } from '../server/index.js';
import { clientAddress, limitKeyOf } from '../server/net.js';

const V1 = (src, sport, proto = 'TCP4', dst = '10.0.0.1', dport = 3000) => Buffer.from(`PROXY ${proto} ${src} ${dst} ${sport} ${dport}\r\n`);
const SIG = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);
/** A v2 header with 4-byte IPv4 addresses; cmd 0 = LOCAL, 1 = PROXY. */
function v2Ipv4(src, sport, dst = '10.0.0.1', dport = 3000, cmd = 1) {
  const body = Buffer.alloc(12);
  src.split('.').forEach((n, i) => { body[i] = Number(n); });
  dst.split('.').forEach((n, i) => { body[4 + i] = Number(n); });
  body.writeUInt16BE(sport, 8);
  body.writeUInt16BE(dport, 10);
  const head = Buffer.from([0x20 | cmd, 0x11, 0x00, 0x0c]);
  return Buffer.concat([SIG, head, body]);
}

/** Open a socket, write `payload`, resolve with the server's first reply (status line included). */
function rawExchange(port, payload, { closeAfter = true, expect = 'HTTP/' } = {}) {
  return new Promise((resolve, reject) => {
    let out = '';
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write(payload);
      if (closeAfter) socket.end();
    });
    const done = () => { socket.destroy(); resolve(out); };
    socket.on('data', (c) => { out += c.toString('latin1'); if (out.includes(expect)) done(); });
    socket.on('error', reject);
    socket.on('close', () => resolve(out));
    setTimeout(done, 5000).unref();
  });
}

const silent = { info() {}, warn() {}, error() {}, debug() {} };
const HTTP_GET = 'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n';
const WS_HANDSHAKE = 'GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
  + 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n';

// ---------------------------------------------------------------------------------------------------------------
// parsing

test('parseProxyProtocol: only the operator opts in, and can require the header', () => {
  assert.equal(parseProxyProtocol(undefined), 'off');
  assert.equal(parseProxyProtocol(''), 'off');
  assert.equal(parseProxyProtocol('0'), 'off');
  assert.equal(parseProxyProtocol('nonsense'), 'off');
  assert.equal(parseProxyProtocol('1'), 'on');
  assert.equal(parseProxyProtocol('ON'), 'on');
  assert.equal(parseProxyProtocol('true'), 'on');
  assert.equal(parseProxyProtocol('auto'), 'on');
  assert.equal(parseProxyProtocol('required'), 'required');
  assert.equal(parseProxyProtocol('require'), 'required');
});

test('matchProxyHeader: v1 TCP4/TCP6/UNKNOWN, bad lines and plain HTTP', () => {
  const ok = matchProxyHeader(V1('198.51.100.7', 51234));
  assert.equal(ok.status, 'ok');
  assert.deepEqual(ok.info, { sourceIp: '198.51.100.7', sourcePort: 51234, destinationIp: '10.0.0.1', destinationPort: 3000, family: 4, version: 1 });
  assert.equal(ok.length, V1('198.51.100.7', 51234).length);
  const six = matchProxyHeader(V1('2001:db8::1', 1, 'TCP6', '2001:db8::2', 2));
  assert.equal(six.status, 'ok');
  assert.equal(six.info.family, 6);
  assert.equal(six.info.sourceIp, '2001:db8::1');
  const unknown = matchProxyHeader(Buffer.from('PROXY UNKNOWN\r\n'));
  assert.deepEqual(unknown, { status: 'ok', info: null, length: 15 });
  assert.equal(matchProxyHeader(Buffer.from('PRO')).status, 'need-more');
  assert.equal(matchProxyHeader(Buffer.from('PROXY TCP4 1.2.3.4')).status, 'need-more');
  assert.equal(matchProxyHeader(Buffer.from(`PROXY TCP4 ${'9'.repeat(120)} 1.2.3.4 1 2\r\n`)).status, 'bad');
  assert.equal(matchProxyHeader(Buffer.from('PROXY TCP4 nope 10.0.0.1 1 2\r\n')).status, 'bad');
  assert.equal(matchProxyHeader(Buffer.from('PROXY TCP4 1.2.3.4 10.0.0.1 1 99999\r\n')).status, 'bad');
  assert.equal(matchProxyHeader(Buffer.from('PROXY SCTP 1.2.3.4 10.0.0.1 1 2\r\n')).status, 'bad');
  assert.equal(matchProxyHeader(Buffer.from(HTTP_GET)).status, 'none');
  assert.equal(matchProxyHeader(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x50])).status, 'none', 'a TLS record is not a PROXY header');
});

test('matchProxyHeader: v2 PROXY/LOCAL, IPv6, truncation and a bad version', () => {
  const ok = matchProxyHeader(v2Ipv4('203.0.113.9', 40000));
  assert.equal(ok.status, 'ok');
  assert.equal(ok.info.sourceIp, '203.0.113.9');
  assert.equal(ok.info.sourcePort, 40000);
  assert.equal(ok.info.version, 2);
  assert.equal(ok.length, 16 + 12);
  assert.deepEqual(matchProxyHeader(v2Ipv4('203.0.113.9', 40000, '10.0.0.1', 3000, 0)), { status: 'ok', info: null, length: 28 }, 'LOCAL');
  assert.equal(matchProxyHeader(SIG.subarray(0, 8)).status, 'need-more');
  assert.equal(matchProxyHeader(v2Ipv4('203.0.113.9', 40000).subarray(0, 20)).status, 'need-more');
  const badVer = Buffer.from(v2Ipv4('203.0.113.9', 40000));
  badVer[12] = 0x31;
  assert.equal(matchProxyHeader(badVer).status, 'bad');
  const ipv6 = Buffer.concat([SIG, Buffer.from([0x21, 0x21, 0x00, 0x24]), Buffer.alloc(36, 0x11)]);
  const six = matchProxyHeader(ipv6);
  assert.equal(six.status, 'ok');
  assert.equal(six.info.family, 6);
  assert.equal(six.info.sourceIp, '1111:1111:1111:1111:1111:1111:1111:1111');
});

// ---------------------------------------------------------------------------------------------------------------
// clientAddress

test('clientAddress: a PROXY-protocol source outranks the socket peer and the forwarding headers', () => {
  const req = { socket: { remoteAddress: '127.0.0.1', proxyProtocol: { sourceIp: '198.51.100.7' } }, headers: { 'x-forwarded-for': '1.1.1.1' } };
  assert.deepEqual(clientAddress(req), { ip: '198.51.100.7', key: limitKeyOf('198.51.100.7') });
  const priv = { socket: { remoteAddress: '127.0.0.1', proxyProtocol: { sourceIp: '192.168.1.20' } }, headers: {} };
  assert.deepEqual(clientAddress(priv), { ip: '192.168.1.20', key: null }, 'a private client is never limited per network');
  const mapped = { socket: { remoteAddress: '::ffff:127.0.0.1', proxyProtocol: { sourceIp: '::ffff:203.0.113.5' } }, headers: {} };
  assert.equal(clientAddress(mapped).ip, '203.0.113.5', 'IPv4-mapped IPv6 is normalized');
  const none = { socket: { remoteAddress: '203.0.113.5' }, headers: {} };
  assert.equal(clientAddress(none).ip, '203.0.113.5');
});

// ---------------------------------------------------------------------------------------------------------------
// real listeners

test('PROXY_PROTOCOL=required: v1 and v2 headers are consumed, the HTTP request behind them is served', async () => {
  const srv = await startServer({ port: 0, quiet: true, log: silent, proxyProtocol: 'required' });
  try {
    assert.equal(srv.proxyProtocol, 'required');
    const a = await rawExchange(srv.port, Buffer.concat([V1('198.51.100.7', 51234), Buffer.from(HTTP_GET)]));
    assert.match(a, /^HTTP\/1\.1 200/, 'v1: the request behind the header is answered');
    assert.match(a, /"ok":true/);
    const b = await rawExchange(srv.port, Buffer.concat([v2Ipv4('203.0.113.9', 40000), Buffer.from(HTTP_GET)]));
    assert.match(b, /^HTTP\/1\.1 200/, 'v2: same');
    const unknown = await rawExchange(srv.port, Buffer.concat([Buffer.from('PROXY UNKNOWN\r\n'), Buffer.from(HTTP_GET)]));
    assert.match(unknown, /^HTTP\/1\.1 200/, 'v1 UNKNOWN (no address) is legal and keeps the peer address');
  } finally {
    await srv.close();
  }
});

test('PROXY_PROTOCOL=required: a headerless or malformed connection is closed, the ws upgrade works with one', async () => {
  const srv = await startServer({ port: 0, quiet: true, log: silent, proxyProtocol: 'required' });
  try {
    const none = await rawExchange(srv.port, Buffer.from(HTTP_GET));
    assert.equal(none, '', 'no header, no answer');
    const bad = await rawExchange(srv.port, Buffer.concat([Buffer.from('PROXY TCP4 nope 1.2.3.4 1 2\r\n'), Buffer.from(HTTP_GET)]));
    assert.equal(bad, '', 'a malformed header is refused');
    const ws = await rawExchange(srv.port, Buffer.concat([V1('198.51.100.7', 51234), Buffer.from(WS_HANDSHAKE)]), { closeAfter: false });
    assert.match(ws, /^HTTP\/1\.1 101 Switching Protocols/, 'the /ws upgrade travels through the same socket handoff');
  } finally {
    await srv.close();
  }
});

test('PROXY_PROTOCOL=on: a direct client stays served; off: the header is just a broken request', async () => {
  const on = await startServer({ port: 0, quiet: true, log: silent, proxyProtocol: 'on' });
  try {
    const direct = await rawExchange(on.port, Buffer.from(HTTP_GET));
    assert.match(direct, /^HTTP\/1\.1 200/, 'on: a connection without a header is a direct client');
    const proxied = await rawExchange(on.port, Buffer.concat([V1('198.51.100.7', 51234), Buffer.from(HTTP_GET)]));
    assert.match(proxied, /^HTTP\/1\.1 200/, 'on: a header is still honoured');
  } finally {
    await on.close();
  }
  const off = await startServer({ port: 0, quiet: true, log: silent });
  try {
    assert.equal(off.proxyProtocol, 'off');
    assert.equal(off.listener, off.server, 'off: the http server is its own listener');
    const withHeader = await rawExchange(off.port, Buffer.concat([V1('198.51.100.7', 51234), Buffer.from(HTTP_GET)]));
    assert.match(withHeader, /^HTTP\/1\.1 400/, 'off: PROXY is not a request method');
  } finally {
    await off.close();
  }
});

test('the per-network key of a proxied connection is the header address (limits count the client, not the balancer)', async () => {
  // Two "clients" behind the same balancer peer (127.0.0.1): without the header both would share one key; with it,
  // each has its own — the property the per-address limits (maxConnectionsPerAddr, rooms per network) rely on.
  const srv = await startServer({ port: 0, quiet: true, log: silent, proxyProtocol: 'required', maxConnectionsPerAddr: 1 });
  const open = [];
  try {
    const seen = [];
    // the sockets stay open between probes: the per-address limit counts *concurrent* connections
    const probe = (ip) => new Promise((resolve) => {
      const socket = net.connect(srv.port, '127.0.0.1', () => socket.write(Buffer.concat([V1(ip, 1111), Buffer.from(WS_HANDSHAKE)])));
      open.push(socket);
      let out = '';
      socket.on('data', (c) => { out += c.toString('latin1'); if (/101|429/.test(out)) resolve(out.slice(0, 30)); });
      socket.on('close', () => resolve(out.slice(0, 30) || 'closed'));
      socket.on('error', (e) => resolve('error ' + e.code));
      setTimeout(() => resolve(out.slice(0, 30) || 'timeout'), 2000).unref();
    });
    seen.push(await probe('198.51.100.11'));
    seen.push(await probe('198.51.100.12'));
    assert.match(seen[0], /101/, 'first client of its own network: admitted');
    assert.match(seen[1], /101/, 'another address: its own key, admitted although maxConnectionsPerAddr is 1');
    seen.push(await probe('198.51.100.11'));
    assert.match(seen[2], /429/, 'the same address over the limit: refused');
  } finally {
    for (const s of open) s.destroy();
    await srv.close();
  }
});

test('PROXY_PROTOCOL=on: a socket that stays silent is served as a direct client (health checks, pre-connects)', async () => {
  const srv = await startServer({ port: 0, quiet: true, log: silent, proxyProtocol: 'on' });
  try {
    const out = await new Promise((resolve, reject) => {
      const socket = net.connect(srv.port, '127.0.0.1', () => {
        setTimeout(() => socket.write(Buffer.from(HTTP_GET)), 1200);   // longer than the silent grace window
      });
      let data = '';
      socket.on('data', (c) => { data += c.toString('latin1'); if (data.includes('HTTP/')) { socket.destroy(); resolve(data); } });
      socket.on('error', reject);
      setTimeout(() => { socket.destroy(); resolve(data); }, 6000);
    });
    assert.match(out, /^HTTP\/1\.1 200/, 'the request that arrives after the silence is still answered');
  } finally {
    await srv.close();
  }
});

test('PROXY_PROTOCOL=required: a silent socket is closed once the timeout passes', async () => {
  const { createServer } = await import('node:http');
  const http2 = createServer((req, res) => { res.end('x'); });
  const listener = createProxyProtocolListener(http2, { mode: 'required', log: silent, timeoutMs: 120, graceMs: 120 });
  await new Promise((r) => listener.listen(0, '127.0.0.1', r));
  try {
    const closed = await new Promise((resolve) => {
      const socket = net.connect(listener.address().port, '127.0.0.1');
      socket.on('close', () => resolve('closed'));
      setTimeout(() => { socket.destroy(); resolve('open'); }, 1500);
    });
    assert.equal(closed, 'closed', 'required: no header, no service');
  } finally {
    await new Promise((r) => listener.close(r));
    http2.close();
  }
});

test('createProxyProtocolListener: it is a net.Server that can be closed on its own', async () => {
  const { createServer } = await import('node:http');
  const http2 = createServer(() => {});
  const listener = createProxyProtocolListener(http2, { mode: 'on', log: silent });
  assert.equal(listener.constructor.name, 'Server');
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  assert.ok(listener.address().port > 0);
  await new Promise((r) => listener.close(r));
  http2.close();
});
