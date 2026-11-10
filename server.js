const FULL_JS=require('fs').readFileSync(__dirname+'/2-fgs-full-app.js','utf8');
const FULL_CSS=require('fs').readFileSync(__dirname+'/3-fgs-full-app.css','utf8');
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

// Isolated full-copy document. Atomic revision check, no production data.
const FULL_VERSION='full-copy-20261109-v1';
const FULL_PRIVATE=['comissao','comissao_base','repasse','repasse_base','sem_corretora','fechado_em','fechado_em_anterior'];
const fullError=(message,status=400)=>Object.assign(new Error(message),{status});
const fullDate=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(x)&&!isNaN(Date.parse(x))&&new Date(x).toISOString().slice(0,10)===x;
const fullText=(x,max=160)=>typeof x==='string'&&x.trim().length>0&&x.length<=max;
const fullId=x=>typeof x==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(x);
const fullNum=x=>typeof x==='number'&&Number.isFinite(x)&&x>=0&&x<=1e10;
function fullSuppliers(){return Object.entries(testUsers).filter(([,r])=>r==='fornecedor_graos').map(([sub],i)=>({id:'fornecedor-'+(i+1),sub,nome:'Fornecedor fictício '+(i+1),uf:i?'MG':'SP'}));}
function fullQuote(s,q){const a={...q};delete a.creator;delete a.supplier;delete a.seen;if(s.role!=='dono')for(const k of FULL_PRIVATE)delete a[k];a.nova=s.role!=='fornecedor_graos'&&!!q.resposta&&!q.seen?.includes(s.sub);return a;}
function fullView(s,d){const supplier=s.role==='fornecedor_graos';return{version:FULL_VERSION,run:RUN,revision:d.revision,papel:s.role,quotes:d.quotes.filter(q=>s.role==='dono'||(supplier?q.supplier===s.sub:q.creator===s.sub)).map(q=>fullQuote(s,q)),clientes:supplier?[]:d.clientes.filter(c=>s.role==='dono'||c.creator===s.sub).map(({creator,...c})=>c),extras:d.extras,suppliers:fullSuppliers().map(({sub,...a})=>a)};}
function validateFullClient(c){if(!c||!fullId(c.id)||!fullText(c.nome)||!fullText(c.uf,2)||!fullText(c.endereco,240)||!fullText(c.cnpj,30))throw fullError('Empresa fictícia exige nome, UF, endereço e CNPJ.');if(!Object.keys(c).every(k=>['id','nome','cidade','segmento','contato','telefone','email','endereco','cnpj','empresa','validado','uf'].includes(k)))throw fullError('Campo de empresa não permitido.');for(const[k,v]of Object.entries(c))if(k!=='validado'&&(typeof v!=='string'||v.length>500))throw fullError('Campo de empresa inválido.');if(!/^[A-Z]{2}$/.test(c.uf))throw fullError('UF inválida.');}
function fullValidateQuote(q,owner){const keys=['id','data','produto','grupo','fornecedor','venda','unidade','condicao','empresa','fornecedorNome','quantidade','quantidadeUnidade','prazo_dias','uf_fornecedor','uf_cliente','clienteId','supplierId',...owner?FULL_PRIVATE:[]];if(!q||!Object.keys(q).every(k=>keys.includes(k)))throw fullError('Campo de cotação não permitido.');if(!fullId(q.id)||!fullDate(q.data)||!fullText(q.produto)||!fullNum(q.venda)||!fullNum(q.quantidade)||q.quantidade<=0||!['Grãos','Óleos','Gorduras Vegetais','Outros'].includes(q.grupo)||!['FOB','CIF'].includes(q.condicao))throw fullError('Confira produto, data, volume e preço.');const units={'R$/saca':'SACAS','R$/ton':'TL','R$/litro':'Litros','R$/kg':'KG'};if(units[q.unidade]!==q.quantidadeUnidade)throw fullError('Preço e volume precisam da mesma base. Sem conversão.');if(q.grupo==='Grãos'&&!['R$/saca','R$/ton'].includes(q.unidade)||q.grupo==='Óleos'&&!['R$/litro','R$/ton'].includes(q.unidade))throw fullError('Unidade incompatível com categoria.');for(const k of ['fornecedor','repasse','comissao','prazo_dias'])if(q[k]!==undefined&&!fullNum(q[k]))throw fullError('Número inválido.');for(const k of ['fechado_em','fechado_em_anterior'])if(q[k]!==undefined&&!fullDate(q[k]))throw fullError('Data de fechamento inválida.');if(q.comissao!==undefined&&!(q.grupo==='Grãos'?['R$/saca','R$/ton']:q.grupo==='Óleos'?['%venda']:['%']).includes(q.comissao_base))throw fullError('Base da comissão inválida.');if(q.repasse!==undefined&&!['R$/saca','R$/ton','R$/litro','R$/kg'].includes(q.repasse_base))throw fullError('Base de repasse inválida.');if(q.sem_corretora!==undefined&&typeof q.sem_corretora!=='boolean')throw fullError('Marcador inválido.');}
function fullMerge(s,doc,patch){const next=structuredClone(doc);const owner=s.role==='dono';if(!patch||typeof patch!=='object'||!Object.keys(patch).every(k=>['quotes','clientes','extras','reply','seen'].includes(k)))throw fullError('Operação inválida.');
 if(patch.clientes){if(s.role==='fornecedor_graos')throw fullError('Área privada.',403);if(!Array.isArray(patch.clientes)||patch.clientes.length>150)throw fullError('Lista de clientes inválida.');const old=doc.clientes.filter(c=>owner||c.creator===s.sub);if(old.some(c=>!patch.clientes.some(n=>n.id===c.id)))throw fullError('Exclusão em lote não permitida neste teste.');const ids=new Set();for(const c of patch.clientes){validateFullClient(c);if(ids.has(c.id))throw fullError('Empresa repetida.');ids.add(c.id);const original=doc.clientes.find(x=>x.id===c.id);if(original&&!owner&&original.creator!==s.sub)throw fullError('Empresa não disponível.',404);if(!original&&doc.clientes.some(x=>x.creator===s.sub&&x.nome.toLowerCase()===c.nome.toLowerCase()))throw fullError('Nome de empresa já cadastrado.');next.clientes=next.clientes.filter(x=>x.id!==c.id);next.clientes.push({...c,creator:original?.creator||s.sub});}}
 if(patch.extras){if(!owner)throw fullError('Catálogo exclusivo do dono.',403);if(!Array.isArray(patch.extras)||patch.extras.length>100||patch.extras.some(p=>!fullText(p.nome)||!['Grãos','Óleos','Gorduras Vegetais','Outros'].includes(p.grupo)||!Array.isArray(p.unidades)||p.unidades.some(u=>!['R$/saca','R$/ton','R$/litro','R$/kg'].includes(u))))throw fullError('Produtos inválidos.');next.extras=patch.extras;}
 if(patch.quotes){if(s.role==='fornecedor_graos')throw fullError('Fornecedor apenas responde.',403);if(!Array.isArray(patch.quotes)||patch.quotes.length>250)throw fullError('Lista de cotações inválida.');const visible=doc.quotes.filter(q=>owner||q.creator===s.sub);if(visible.some(q=>!patch.quotes.some(n=>n.id===q.id)))throw fullError('Exclusão em lote não permitida.');const ids=new Set();for(const incoming of patch.quotes){const q={...incoming};for(const k of ['resposta','nova','cnpj','endereco','destino'])delete q[k];fullValidateQuote(q,owner);if(ids.has(q.id))throw fullError('Cotação repetida.');ids.add(q.id);const old=doc.quotes.find(x=>x.id===q.id);if(old&&!owner&&old.creator!==s.sub)throw fullError('Cotação não disponível.',404);const c=next.clientes.find(x=>x.id===q.clienteId&&(owner||x.creator===s.sub));const oil=q.grupo==='Óleos';if(oil&&!owner&&s.role!=='analista')throw fullError('Fluxo de óleos desta cópia: analista para o dono.',403);const sup=oil?{id:'dono-oleos',sub:null,nome:'Fabiano · recebimento de óleos',uf:q.uf_fornecedor||'SP'}:fullSuppliers().find(x=>x.id===q.supplierId);if(!c||!sup||oil&&q.supplierId!=='dono-oleos')throw fullError('Escolha empresa e fornecedor cadastrados.');if(!owner&&q.fornecedor!==undefined&&q.fornecedor!==old?.fornecedor)throw fullError('Preço do fornecedor só na resposta.',403);if(old&&(q.clienteId!==old.clienteId||q.supplierId!==old.supplierId||q.venda!==old.venda||q.produto!==old.produto||q.quantidade!==old.quantidade||q.unidade!==old.unidade||q.grupo!==old.grupo||q.fornecedor!==old.fornecedor))throw fullError('Não altere a base de uma cotação enviada. Crie outra.');const original={...old};if(owner)for(const k of FULL_PRIVATE)delete original[k];const merged={...original,...q,creator:old?.creator||s.sub,supplier:sup.sub,destino:oil?'dono':'fornecedor',empresa:c.nome,endereco:c.endereco,cnpj:c.cnpj,uf_cliente:c.uf,uf_fornecedor:sup.uf,fornecedorNome:sup.nome,seen:old?.seen||[]};next.quotes=next.quotes.filter(x=>x.id!==q.id);next.quotes.push(merged);}}
 if(patch.reply){const{id,preco,condicoes}=patch.reply;const q=next.quotes.find(x=>x.id===id);if(s.role!=='fornecedor_graos'||!q||q.supplier!==s.sub)throw fullError('Apenas fornecedor destinatário responde.',403);if(!fullNum(preco)||!fullText(condicoes,500)||Object.keys(patch.reply).some(k=>!['id','preco','condicoes'].includes(k)))throw fullError('Resposta inválida.');q.resposta={preco,condicoes,data:new Date().toISOString()};q.fornecedor=preco;q.seen=[];}
 if(patch.seen){const q=next.quotes.find(x=>x.id===patch.seen);if(s.role==='fornecedor_graos'||!q||!(owner||q.creator===s.sub))throw fullError('Resposta não disponível.',404);q.seen=[...new Set([...(q.seen||[]),s.sub])];}
 if(Buffer.byteLength(JSON.stringify(next))>180000)throw fullError('Limite seguro desta cópia atingido.');return next;}
async function fullApi(req,res,path,s){if(!s)return send(res,401,{erro:'Entre com um login fictício autorizado.'});if(!RUN)return send(res,503,{erro:'Teste encerrado.'});if(!path.startsWith('/fullapi/'))return send(res,404,{erro:'Não encontrado.'});try{const col=(await testDb()).collection('full_copy');const key='full:'+RUN;let d=await col.findOne({_id:key});if(!d){await col.updateOne({_id:key},{$setOnInsert:{revision:0,quotes:[],clientes:[],extras:[],operations:[]}},{upsert:true});d=await col.findOne({_id:key});}if(path==='/fullapi/state'&&req.method==='GET')return send(res,200,fullView(s,d));if(req.method!=='POST'||req.headers.origin!==BASE||!String(req.headers['content-type']||'').startsWith('application/json'))return send(res,403,{erro:'Origem ou método inválido.'});let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>190000)throw fullError('Pedido acima do limite.',413);}let b;try{b=JSON.parse(raw||'{}')}catch(_){throw fullError('JSON inválido.');}if(path==='/fullapi/cleanup'){if(s.role!=='dono'||!only(b,['confirm'])||b.confirm!==RUN)return send(res,403,{erro:'Confirmação inválida.'});const r=await col.deleteMany({_id:key});return send(res,200,{removed:r.deletedCount});}if(path!=='/fullapi/commit'||!only(b,['revision','operationId','patch'])||!Number.isInteger(b.revision)||!fullId(b.operationId))return send(res,400,{erro:'Operação inválida.'});const past=d.operations.find(x=>x.id===b.operationId&&x.sub===s.sub);if(past){if(past.hash!==crypto.createHash('sha256').update(JSON.stringify(b.patch)).digest('hex'))return send(res,409,{erro:'Identificador já usado para outros dados.'});return send(res,200,{...fullView(s,d),repeated:true});}if(d.revision!==b.revision)return send(res,409,{erro:'Outra sessão alterou a base. Atualize e confira antes de repetir. Seu formulário foi mantido.'});const next=fullMerge(s,d,b.patch);next.revision=d.revision+1;next.operations=[...d.operations,{id:b.operationId,sub:s.sub,hash:crypto.createHash('sha256').update(JSON.stringify(b.patch)).digest('hex')}].slice(-60);const r=await col.updateOne({_id:key,revision:d.revision},{$set:{revision:next.revision,quotes:next.quotes,clientes:next.clientes,extras:next.extras,operations:next.operations}});if(r.matchedCount!==1)return send(res,409,{erro:'Conflito de revisão. Nada desta operação foi salvo.'});return send(res,200,fullView(s,next));}catch(e){return send(res,e.status||503,{erro:e.status?e.message:'Banco indisponível. Nada foi confirmado; preserve o formulário.'});}}

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const path = u.pathname;
  if (path.startsWith('/fullapi/')) return fullApi(req,res,path,session(req));
  if(path==='/full.js') {res.writeHead(200,{'Content-Type':'text/javascript','Cache-Control':'no-store'});return res.end(FULL_JS);}
  if(path==='/full.css') {res.writeHead(200,{'Content-Type':'text/css','Cache-Control':'no-store'});return res.end(FULL_CSS);}
  if(path.startsWith('/biz/')) return send(res,410,{erro:'Rota antiga desativada.'});
  if(path==='/ensaio')return send(res,410,{erro:'Rota antiga desativada.'});if (false) return session(req) ? html(res, 200, bench) : send(res, 401, { erro: 'sem sessao' });
  if (path === '/health') return send(res, 200, { ok: true, auth: !!(ISSUER && CLIENT_ID && BASE) });
  if(path==='/' && req.method==='GET'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src data: 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"});return res.end('<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FGS · cópia completa de teste</title><link rel="stylesheet" href="/full.css"><div id="root"></div><script src="/full.js"></script></html>');}
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
