// Servico de teste sintetico: sem dados reais, sem segredos no codigo.
// Config por variaveis de ambiente: OIDC_ISSUER, OIDC_CLIENT_ID, ALLOWED_EMAILS, BASE_URL.
const http = require('http');
const crypto = require('crypto');
const items = [];
const PORT = process.env.PORT || 3000;
const ISSUER = process.env.OIDC_ISSUER || '';
const CLIENT_ID = process.env.OIDC_CLIENT_ID || '';
const BASE = process.env.BASE_URL || '';
const ALLOWED = (process.env.ALLOWED_EMAILS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const TTL = Number(process.env.SESSION_TTL_SECONDS || 3600) * 1000;
const TEST_ROLE = 'papel-ficticio-de-teste'; // definido no servidor, so para este teste
const b64u = (b) => Buffer.from(b).toString('base64url');
const rnd = (n = 32) => crypto.randomBytes(n).toString('base64url');
const txns = new Map();
const sessions = new Map();
let meta = null;
let jwks = null;

function send(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}
function html(res, code, body, extra = {}) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }, extra));
  res.end('<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><body style="font-family:sans-serif;max-width:480px;margin:40px auto;padding:0 16px">' + body);
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach((p) => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); });
  return o;
}
const ck = (name, val, age) => `__Host-${name}=${val}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
async function discover() {
  if (!meta) meta = await (await fetch(ISSUER + '/.well-known/openid-configuration')).json();
  return meta;
}
async function getKey(kid) {
  if (!jwks || !jwks.keys.find((k) => k.kid === kid)) jwks = await (await fetch((await discover()).jwks_uri)).json();
  const jwk = jwks.keys.find((k) => k.kid === kid);
  if (!jwk) throw new Error('chave desconhecida');
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}
async function verifyIdToken(tok, nonce) {
  const [h, p, s] = tok.split('.');
  const head = JSON.parse(Buffer.from(h, 'base64url'));
  const m = await discover();
  if (!(m.id_token_signing_alg_values_supported || []).includes(head.alg)) throw new Error('alg');
  const hash = { ES256: 'sha256', ES384: 'sha384', ES512: 'sha512' }[head.alg];
  if (!hash) throw new Error('alg nao suportado');
  const ok = crypto.verify(hash, Buffer.from(h + '.' + p), { key: await getKey(head.kid), dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('assinatura');
  const c = JSON.parse(Buffer.from(p, 'base64url'));
  const now = Math.floor(Date.now() / 1000);
  if (c.iss !== ISSUER) throw new Error('iss');
  if (c.aud !== CLIENT_ID && !(Array.isArray(c.aud) && c.aud.includes(CLIENT_ID))) throw new Error('aud');
  if (c.exp < now - 30) throw new Error('exp');
  if (c.nonce !== nonce) throw new Error('nonce');
  return c;
}
function session(req) {
  const id = cookies(req)['__Host-sid'];
  const s = id && sessions.get(id);
  if (!s) return null;
  if (s.exp < Date.now() || !ALLOWED.includes(s.email)) { sessions.delete(id); return null; }
  return s;
}

async function login(req, res) {
  const m = await discover();
  const t = { state: rnd(), nonce: rnd(), verifier: rnd(48), exp: Date.now() + 600000 };
  const id = rnd();
  txns.set(id, t);
  const q = new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: BASE + '/callback', scope: 'openid email',
    state: t.state, nonce: t.nonce, code_challenge: b64u(crypto.createHash('sha256').update(t.verifier).digest()), code_challenge_method: 'S256',
  });
  res.writeHead(302, { Location: m.authorization_endpoint + '?' + q, 'Set-Cookie': ck('txn', id, 600) });
  res.end();
}
async function callback(req, res, u) {
  const id = cookies(req)['__Host-txn'];
  const t = id && txns.get(id);
  txns.delete(id);
  const clear = ck('txn', '', 0);
  if (!t || t.exp < Date.now() || u.searchParams.get('state') !== t.state) return html(res, 400, '<p>Falha: state invalido.</p>', { 'Set-Cookie': clear });
  if (u.searchParams.get('iss') && u.searchParams.get('iss') !== ISSUER) return html(res, 400, '<p>Falha: emissor.</p>', { 'Set-Cookie': clear });
  const code = u.searchParams.get('code');
  if (!code) return html(res, 400, '<p>Falha: sem code.</p>', { 'Set-Cookie': clear });
  try {
    const m = await discover();
    const r = await fetch(m.token_endpoint, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: BASE + '/callback', client_id: CLIENT_ID, code_verifier: t.verifier }),
    });
    const tok = await r.json();
    if (!r.ok || !tok.id_token) throw new Error('token');
    const c = await verifyIdToken(tok.id_token, t.nonce);
    const email = String(c.email || '').toLowerCase();
    if (!c.email || !ALLOWED.includes(email)) return html(res, 403, '<h1>Acesso negado</h1><p>Usuario nao autorizado.</p>', { 'Set-Cookie': clear });
    const sid = rnd();
    sessions.set(sid, { email, role: TEST_ROLE, exp: Date.now() + TTL });
    res.writeHead(302, { Location: '/', 'Set-Cookie': [clear, ck('sid', sid, Math.floor(TTL / 1000))] });
    res.end();
  } catch (e) {
    html(res, 400, '<p>Falha na validacao do login.</p>', { 'Set-Cookie': clear });
  }
}

// Teste de Mongo: so dados ficticios, so no banco fgs_teste; credenciais vem de variaveis de ambiente.
let mclient = null;
async function mongoTeste(s) {
  const { MongoClient } = require('mongodb');
  const host = process.env.MONGO_HOST, user = process.env.MONGO_USER, pass = process.env.MONGO_PASS;
  if (!host || !user || !pass) return { erro: 'mongo nao configurado' };
  if (!mclient) {
    mclient = new MongoClient('mongodb+srv://' + encodeURIComponent(user) + ':' + encodeURIComponent(pass) + '@' + host + '/?retryWrites=true&w=majority', { serverSelectionTimeoutMS: 8000 });
    await mclient.connect();
  }
  const out = { conectou: true };
  const col = mclient.db('fgs_teste').collection('harness_teste');
  const marca = 'sint-' + rnd(6);
  await col.insertOne({ marca, texto: 'registro ficticio', por: s.role, criado: new Date() });
  out.gravou = true;
  const lido = await col.findOne({ marca });
  out.leu = !!lido && lido.texto === 'registro ficticio';
  const del = await col.deleteMany({ marca });
  out.limpou = del.deletedCount === 1;
  out.restantes_na_colecao = await col.countDocuments({});
  // isolamento: escrita em outro banco deve ser negada
  try { await mclient.db('outro_teste').collection('x').insertOne({ a: 1 }); out.escrita_outro_banco = 'PERMITIDA (problema)'; }
  catch (e) { out.escrita_outro_banco = 'negada: ' + String(e.codeName || e.code || 'erro'); }
  try { await mclient.db('admin').command({ listDatabases: 1, nameOnly: true }); out.listar_bancos = 'permitido (problema)'; }
  catch (e) { out.listar_bancos = 'negado: ' + String(e.codeName || e.code || 'erro'); }
  return out;
}

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const path = u.pathname;
  if (path === '/health') return send(res, 200, { ok: true, auth: !!(ISSUER && CLIENT_ID && BASE) });
  if (path === '/' && req.method === 'GET') {
    const s = session(req);
    return html(res, 200, s
      ? '<h1>Pagina ficticia</h1><p>Sessao ativa. Papel (ficticio, definido no servidor): ' + TEST_ROLE + '</p><p><a href="/me">/me</a></p><form method=post action=/logout><button>Sair</button></form>'
      : '<h1>Pagina ficticia</h1><p>Sem sessao.</p><p><a href="/login">Entrar</a></p>');
  }
  if (path === '/login') return login(req, res).catch(() => html(res, 500, '<p>Erro.</p>'));
  if (path === '/callback') return callback(req, res, u);
  if (path === '/me') { const s = session(req); return s ? send(res, 200, { email: s.email, papel: s.role }) : send(res, 401, { erro: 'sem sessao' }); }
  if (path === '/logout' && req.method === 'POST') {
    sessions.delete(cookies(req)['__Host-sid']);
    res.writeHead(302, { Location: '/', 'Set-Cookie': ck('sid', '', 0) });
    return res.end();
  }
  if (path === '/mongo-teste') {
    const s = session(req);
    if (!s) return send(res, 401, { erro: 'sem sessao' });
    return mongoTeste(s).then((r) => send(res, 200, r)).catch((e) => send(res, 500, { erro: 'falha', codigo: String((e && (e.codeName || e.name)) || 'erro') }));
  }
  if (path === '/itens' && !session(req)) return send(res, 401, { erro: 'sem sessao' });
  if (path === '/itens' && req.method === 'GET') return send(res, 200, items);
  if (path === '/itens' && req.method === 'POST') {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 2000) req.destroy(); });
    req.on('end', () => {
      try {
        const d = JSON.parse(raw);
        const item = { id: items.length + 1, texto: String(d.texto || '').slice(0, 100) };
        items.push(item);
        send(res, 201, item);
      } catch (e) { send(res, 400, { erro: 'json invalido' }); }
    });
    return;
  }
  send(res, 404, { erro: 'nao encontrado' });
}).listen(PORT, () => console.log('ok ' + PORT));
