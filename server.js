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
  if (s.exp < Date.now() || !ALLOWED.includes(s.email) || !roleFor(s.sub) || roleFor(s.sub) !== s.role) { sessions.delete(id); return null; }
  return s;
}

async function login(req, res) {
  const m = await discover();
  const t = { state: rnd(), nonce: rnd(), verifier: rnd(48), exp: Date.now() + 600000 };
  const id = rnd();
  txns.set(id, t);
  const q = new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: BASE + '/callback', scope: 'openid email',
    state: t.state, nonce: t.nonce, prompt: 'login', code_challenge: b64u(crypto.createHash('sha256').update(t.verifier).digest()), code_challenge_method: 'S256',
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
    if (!c.email || !ALLOWED.includes(email) || !roleFor(c.sub)) return html(res, 403, '<h1>Acesso negado</h1><p>Usuario nao autorizado.</p>', { 'Set-Cookie': clear });
    const sid = rnd();
    sessions.set(sid, { email, sub: c.sub, role: roleFor(c.sub), exp: Date.now() + TTL });
    res.writeHead(302, { Location: '/', 'Set-Cookie': [clear, ck('sid', sid, Math.floor(TTL / 1000))] });
    res.end();
  } catch (e) {
    html(res, 400, '<p>Falha na validacao do login.</p>', { 'Set-Cookie': clear });
  }
}

// Ensaio separado de graos. Somente dados ficticios. Nenhuma rota do app real.
const BOOT = rnd(8);
const RUN = process.env.TEST_RUN || '';
let testUsers = {};
try { testUsers = JSON.parse(process.env.TEST_USERS || '{}'); } catch (_) {}
const validRoles = ['dono', 'corretora', 'analista', 'fornecedor_graos'];
const roleFor = (sub) => validRoles.includes(testUsers[sub]) ? testUsers[sub] : null;
const supplierSub = () => Object.keys(testUsers).find((k) => testUsers[k] === 'fornecedor_graos');
let dbPromise;
async function testDb() {
  if (!RUN || !process.env.MONGO_PASS) throw new Error('configuracao ausente');
  if (!dbPromise) dbPromise = (async () => {
    const { MongoClient } = require('mongodb');
    const c = new MongoClient('mongodb+srv://' + encodeURIComponent(process.env.MONGO_USER) + ':' + encodeURIComponent(process.env.MONGO_PASS) + '@' + process.env.MONGO_HOST + '/?retryWrites=true&w=majority', { serverSelectionTimeoutMS: 8000 });
    await c.connect();
    return c.db('fgs_teste');
  })().catch((e) => { dbPromise = null; throw e; });
  return dbPromise;
}
const clientId = (s) => s.role === 'corretora' ? 'C' : s.role === 'analista' ? 'A' : null;
const keyFor = (tipo, id) => RUN + ':' + tipo + ':' + id;
const canQuote = (s, d) => !!d && (s.role === 'dono' || d.creator === s.sub || (s.role === 'fornecedor_graos' && d.supplier === s.sub));
function quoteDto(s, d) {
  const v = { id: d.id, produto: d.produto, volume: d.volume, unidade: d.unidade, precoIndicacao: d.precoIndicacao, frete: d.frete, empresa: d.empresa, endereco: d.endereco, cnpj: d.cnpj, classificacao: d.classificacao, resposta: d.resposta || null };
  if (s.role === 'dono') v.comissaoFicticia = d.comissaoFicticia;
  return v;
}
function only(d, fields) { return d && !Array.isArray(d) && typeof d === 'object' && Object.keys(d).every((k) => fields.includes(k)); }
async function readJson(req) {
  let raw = '';
  for await (const b of req) { raw += b; if (raw.length > 4096) throw new Error('body'); }
  return JSON.parse(raw || '{}');
}
async function business(req, res, path, s) {
  if (!s) return send(res, 401, { erro: 'sem sessao' });
  if (!RUN) return send(res, 503, { erro: 'ensaio desativado' });
  const method = req.method;
  if (!['GET', 'POST'].includes(method)) return send(res, 405, { erro: 'metodo' });
  if (method === 'POST' && (req.headers.origin !== BASE || !String(req.headers['content-type'] || '').startsWith('application/json'))) return send(res, 403, { erro: 'origem ou tipo' });
  if (path === '/biz/meta') return send(res, 200, { papel: s.role, execucao: RUN, processo: BOOT });
  if (['/biz/ganhos', '/biz/backup', '/biz/decisoes'].includes(path)) return send(res, s.role === 'dono' ? 200 : 403, s.role === 'dono' ? { ficticio: true, exclusivoDono: true } : { erro: 'nao autorizado' });
  let body = {};
  if (method === 'POST') { try { body = await readJson(req); } catch (_) { return send(res, 400, { erro: 'json invalido' }); } }
  const db = await testDb(), clients = db.collection('ensaio_clientes'), quotes = db.collection('ensaio_cotacoes');
  const mine = clientId(s);
  if (path === '/biz/clientes') {
    if (s.role === 'fornecedor_graos') return send(res, 403, { erro: 'sem lista clientes' });
    if (method === 'GET') return send(res, 200, await clients.find(Object.assign({ run: RUN }, s.role === 'dono' ? {} : { creator: s.sub }), { projection: { _id: 0, creator: 0, run: 0 } }).toArray());
    if (!mine) return send(res, 403, { erro: 'criacao fora do ensaio' });
    if (!only(body, ['empresa', 'endereco', 'cnpj', 'uf']) || ['empresa', 'endereco', 'cnpj', 'uf'].some((k) => typeof body[k] !== 'string' || !body[k] || body[k].length > 120) || !/^[A-Z]{2}$/.test(body.uf)) return send(res, 400, { erro: 'campos invalidos' });
    await clients.updateOne({ _id: keyFor('cliente', mine) }, { $setOnInsert: { run: RUN, id: mine, creator: s.sub, ...body } }, { upsert: true });
    return send(res, 200, { id: mine, salvo: true });
  }
  if (/^\/biz\/clientes\/[CA]$/.test(path)) {
    if (s.role === 'fornecedor_graos' || method !== 'GET') return send(res, 403, { erro: 'nao autorizado' });
    const d = await clients.findOne({ _id: keyFor('cliente', path.slice(-1)), run: RUN });
    if (!d || (s.role !== 'dono' && d.creator !== s.sub)) return send(res, 404, { erro: 'nao encontrado' });
    return send(res, 200, { id: d.id, empresa: d.empresa, endereco: d.endereco, cnpj: d.cnpj, uf: d.uf });
  }
  if (path === '/biz/cotacoes') {
    if (method === 'GET') {
      const filter = { run: RUN };
      if (s.role === 'fornecedor_graos') filter.supplier = s.sub;
      else if (s.role !== 'dono') filter.creator = s.sub;
      return send(res, 200, (await quotes.find(filter).toArray()).map((d) => quoteDto(s, d)));
    }
    if (!mine) return send(res, 403, { erro: 'nao autorizado' });
    if (!only(body, ['produto', 'volume', 'unidade', 'precoIndicacao', 'frete', 'ufFornecedor']) || body.produto !== 'Milho ficticio' || !['SACAS', 'TL'].includes(body.unidade) || !['FOB', 'CIF'].includes(body.frete) || !Number.isFinite(body.volume) || body.volume <= 0 || !Number.isFinite(body.precoIndicacao) || body.precoIndicacao <= 0 || !/^[A-Z]{2}$/.test(body.ufFornecedor || '')) return send(res, 400, { erro: 'campos invalidos' });
    const d = await clients.findOne({ _id: keyFor('cliente', mine), creator: s.sub, run: RUN });
    if (!d || !supplierSub()) return send(res, 409, { erro: 'falta cadastro ou fornecedor teste' });
    await quotes.updateOne({ _id: keyFor('cotacao', mine) }, { $setOnInsert: { run: RUN, id: mine, creator: s.sub, supplier: supplierSub(), ...body, empresa: d.empresa, endereco: d.endereco, cnpj: d.cnpj, classificacao: d.uf === body.ufFornecedor ? 'Pedido Deferido' : 'Pedido Indeferido', comissaoFicticia: 2.5, vistas: [] } }, { upsert: true });
    return send(res, 200, { id: mine, enviada: true });
  }
  const match = path.match(/^\/biz\/cotacoes\/([CA])(?:\/(resposta|vista))?$/);
  if (match) {
    const [, id, action] = match;
    const d = await quotes.findOne({ _id: keyFor('cotacao', id), run: RUN });
    if (!canQuote(s, d)) return send(res, 404, { erro: 'nao encontrado' });
    if (method === 'GET' && !action) return send(res, 200, quoteDto(s, d));
    if (method === 'POST' && action === 'resposta') {
      if (s.role !== 'fornecedor_graos' || d.supplier !== s.sub) return send(res, 403, { erro: 'nao autorizado' });
      if (!only(body, ['preco', 'condicoes']) || !Number.isFinite(body.preco) || body.preco <= 0 || typeof body.condicoes !== 'string' || body.condicoes.length > 120) return send(res, 400, { erro: 'campos invalidos' });
      await quotes.updateOne({ _id: d._id, supplier: s.sub, run: RUN }, { $set: { resposta: { preco: body.preco, condicoes: body.condicoes }, vistas: [] } });
      return send(res, 200, { respondeu: true });
    }
    if (method === 'POST' && action === 'vista' && (s.role === 'dono' || d.creator === s.sub)) {
      if (!only(body, [])) return send(res, 400, { erro: 'campos invalidos' });
      await quotes.updateOne({ _id: d._id, run: RUN }, { $addToSet: { vistas: s.sub } });
      return send(res, 200, { vista: true });
    }
    return send(res, 403, { erro: 'nao autorizado' });
  }
  if (path === '/biz/novas' && method === 'GET') {
    if (!['dono', 'corretora', 'analista'].includes(s.role)) return send(res, 403, { erro: 'nao autorizado' });
    const filter = { run: RUN, resposta: { $exists: true }, vistas: { $ne: s.sub } };
    if (s.role !== 'dono') filter.creator = s.sub;
    return send(res, 200, { novas: await quotes.countDocuments(filter) });
  }
  if (path === '/biz/limpeza' && method === 'POST') {
    if (s.role !== 'dono') return send(res, 403, { erro: 'nao autorizado' });
    if (!only(body, [])) return send(res, 400, { erro: 'campos invalidos' });
    const c = await clients.deleteMany({ run: RUN }), q = await quotes.deleteMany({ run: RUN });
    return send(res, 200, { clientesApagados: c.deletedCount, cotacoesApagadas: q.deletedCount, clientesRestantes: await clients.countDocuments({ run: RUN }), cotacoesRestantes: await quotes.countDocuments({ run: RUN }) });
  }
  return send(res, 404, { erro: 'nao encontrado' });
}
const bench = `<h1>Ensaio ficticio de graos</h1><p>Ambiente separado. Sem dados reais. Papel recebido do servidor.</p><p><a href="/me">Minha sessao</a></p><button onclick="runStage('inicial')">Executar etapa inicial</button> <button onclick="runStage('respostas')">Conferir respostas e sino</button> <button onclick="runStage('persistencia')">Conferir persistencia</button> <button onclick="runStage('limpeza')">Limpar registros deste ensaio</button><form method="post" action="/logout"><button>Sair</button></form><pre id="result" style="white-space:pre-wrap"></pre><script>
async function api(path, method='GET', body) { const r=await fetch('/biz/'+path,{method,headers:method==='POST'?{'Content-Type':'application/json'}:{},body:body===undefined?undefined:JSON.stringify(body)});return {status:r.status,data:await r.json()}; }
window.runStage=async(stage)=>{
 const out=[]; const log=(name,r,ok)=>{out.push({teste:name,passou:!!ok,status:r.status,dados:r.data});document.querySelector('#result').textContent=JSON.stringify(out,null,2)};
 try {
 const m=await api('meta'), role=m.data.papel; log('identidade e processo',m,m.status===200); const mine=role==='corretora'?'C':'A', other=mine==='C'?'A':'C';
 if(stage==='inicial'){
  if(['corretora','analista'].includes(role)){
   let r=await api('clientes','POST',{empresa:'Empresa ficticia '+mine,endereco:'Rua ficticia 1',cnpj:'00000000000000',uf:mine==='C'?'SP':'MG'});log('cadastrar proprio cliente',r,r.status===200);
   r=await api('clientes');log('lista somente cliente proprio',r,r.status===200&&r.data.length===1&&r.data[0].id===mine);
   r=await api('clientes/'+other);log('cliente alheio negado',r,r.status===404);
   const q={produto:'Milho ficticio',volume:100,unidade:'SACAS',precoIndicacao:70,frete:'FOB',ufFornecedor:'SP'};
   r=await api('cotacoes','POST',q);log('enviar direto ao fornecedor',r,r.status===200);
   r=await api('cotacoes','POST',q);log('repeticao idempotente',r,r.status===200);
   r=await api('cotacoes');log('lista somente cotacao propria sem comissao',r,r.status===200&&r.data.length===1&&r.data[0].id===mine&&!('comissaoFicticia' in r.data[0]));
   r=await api('cotacoes/'+other);log('cotacao alheia negada',r,r.status===404);
   r=await api('cotacoes','POST',{...q,papel:'dono',creator:'outro',supplier:'outro'});log('adulterar papel criador fornecedor negado',r,r.status===400);
   r=await api('cotacoes/'+mine+'/resposta','POST',{preco:68,condicoes:'ficticio'});log('criador nao responde como fornecedor',r,r.status===403);
   r=await api('limpeza','POST',{});log('limpeza de dono negada',r,r.status===403);
  } else if(role==='fornecedor_graos') {
   let r=await api('clientes');log('lista clientes negada',r,r.status===403);
   r=await api('clientes/C');log('cadastro direto negado',r,r.status===403);
   r=await api('clientes','POST',{empresa:'X'});log('fornecedor nao cria cliente',r,r.status===403);
   r=await api('cotacoes');log('recebe duas cotacoes sem comissao',r,r.status===200&&r.data.length===2&&r.data.every(d=>!('comissaoFicticia' in d)&&d.empresa&&d.cnpj&&d.endereco));
   for(const id of ['C','A']){r=await api('cotacoes/'+id+'/resposta','POST',{preco:68,condicoes:'Condicao ficticia'});log('responder '+id,r,r.status===200)}
   r=await api('cotacoes','POST',{papel:'dono'});log('fornecedor nao cria cotacao',r,r.status===403);
   r=await api('limpeza','POST',{});log('fornecedor nao limpa',r,r.status===403);
  } else if(role==='dono') {
   let r=await api('clientes');log('dono ve dois clientes',r,r.status===200&&r.data.length===2);
   r=await api('cotacoes');log('dono ve ambas com marcador privado',r,r.status===200&&r.data.length===2&&r.data.every(d=>d.comissaoFicticia===2.5));
  }
  for(const p of ['ganhos','backup','decisoes']){const r=await api(p);log('rota exclusiva '+p,r,r.status===(role==='dono'?200:403))}
 }
 if(stage==='respostas'){
   let r=await api('cotacoes');const expected=role==='dono'?2:1;log('respostas visiveis ao destinatario',r,r.status===200&&r.data.length===expected&&r.data.every(d=>d.resposta&&d.resposta.preco===68));
   r=await api('novas');log('sino antes abrir',r,r.status===200&&r.data.novas===expected);
   for(const id of (role==='dono'?['C','A']:[mine])) {r=await api('cotacoes/'+id+'/vista','POST',{});log('marcar vista '+id,r,r.status===200)}
   r=await api('novas');log('sino zerado por destinatario',r,r.status===200&&r.data.novas===0);
 }
 if(stage==='persistencia'){let r=await api('clientes');log('clientes apos nova sessao ou restart',r,r.status===200&&r.data.length===(role==='dono'?2:1));r=await api('cotacoes');log('cotacoes e respostas persistidas',r,r.status===200&&r.data.length===(role==='dono'?2:1)&&r.data.every(d=>d.resposta&&d.resposta.preco===68));}
 if(stage==='limpeza'){let r=await api('limpeza','POST',{});log('limpeza somente execucao atual',r,r.status===200&&r.data.clientesRestantes===0&&r.data.cotacoesRestantes===0);}
 out.push({etapa:stage,papel:role,concluido:true,passou:out.every(x=>x.passou)});
 }catch(e){out.push({erro:'falha no ensaio',concluido:false});}
 document.querySelector('#result').textContent=JSON.stringify(out,null,2);return out;
};</script>`;

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const path = u.pathname;
  if (path.startsWith('/biz/')) return business(req, res, path, session(req)).catch(() => send(res, 503, { erro: 'falha no ensaio' }));
  if (path === '/ensaio') return session(req) ? html(res, 200, bench) : send(res, 401, { erro: 'sem sessao' });
  if (path === '/health') return send(res, 200, { ok: true, auth: !!(ISSUER && CLIENT_ID && BASE) });
  if (path === '/' && req.method === 'GET') {
    const s = session(req);
    return html(res, 200, s
      ? '<p><a href="/ensaio">Ensaio graos</a></p><h1>Pagina ficticia</h1><p>Sessao ativa. Papel (ficticio, definido no servidor): ' + TEST_ROLE + '</p><p><a href="/me">/me</a></p><form method=post action=/logout><button>Sair</button></form>'
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
  if (path === '/mongo-teste') return send(res, session(req) ? 410 : 401, { erro: 'diagnostico antigo desativado' });
  if (path === '/itens' && !session(req)) return send(res, 401, { erro: 'sem sessao' });
  if (path === '/itens') return send(res, 410, { erro: 'rota antiga desativada' });
  send(res, 404, { erro: 'nao encontrado' });
}).listen(PORT, () => console.log('ok ' + PORT));
