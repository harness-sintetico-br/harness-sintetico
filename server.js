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

// Rotas da interface isolada. Identidade e filtros sempre no servidor.
const UI_VERSION = 'telas-20261109-v1';
const cleanClient = d => ({id:d.id,empresa:d.empresa,endereco:d.endereco,cnpj:d.cnpj,uf:d.uf});
function cleanQuote(s,d){const v={id:d.id,produto:d.produto,volume:d.volume,unidade:d.unidade,precoIndicacao:d.precoIndicacao,frete:d.frete,empresa:d.empresa,endereco:d.endereco,cnpj:d.cnpj,classificacao:d.classificacao,resposta:d.resposta||null}; if(s.role==='dono')v.finance=d.finance||null; return v;}
const idOk = x => typeof x==='string' && /^[a-zA-Z0-9-]{1,60}$/.test(x);
const textOk = x => typeof x==='string' && x.trim().length>0 && x.length<=120;
const numberOk = x => Number.isFinite(x)&&x>=0&&x<1e12;
async function uiApi(req,res,path,s){
 if(!s)return send(res,401,{erro:'Entre com um acesso fictício autorizado.'});
 if(!RUN)return send(res,503,{erro:'Teste encerrado. Conexão desativada.'});
 const method=req.method;
 if(!['GET','POST'].includes(method))return send(res,405,{erro:'Método não permitido.'});
 if(method==='POST'&&(req.headers.origin!==BASE||!String(req.headers['content-type']||'').startsWith('application/json')))return send(res,403,{erro:'Origem ou tipo inválido.'});
 let b={};if(method==='POST'){try{b=await readJson(req)}catch(_){return send(res,400,{erro:'Dados inválidos.'})}}
 if(path==='/appapi/meta')return send(res,200,{papel:s.role,versao:UI_VERSION,processo:BOOT});
 const db=await testDb(), cs=db.collection('ui_clientes'),qs=db.collection('ui_cotacoes');
 if(path==='/appapi/clientes'){
  if(s.role==='fornecedor_graos')return send(res,403,{erro:'Cadastro de clientes não disponível para fornecedor.'});
  if(method==='GET')return send(res,200,(await cs.find({run:RUN,...(s.role==='dono'?{}:{creator:s.sub})}).toArray()).map(cleanClient));
  if(!only(b,['id','empresa','endereco','cnpj','uf'])||!idOk(b.id)||!['empresa','endereco','cnpj','uf'].every(k=>textOk(b[k]))||!/^[A-Z]{2}$/.test(b.uf))return send(res,400,{erro:'Confira os campos da empresa fictícia.'});
  const key=RUN+':'+s.sub+':'+b.id;
  await cs.updateOne({_id:key},{$setOnInsert:{...b,id:s.sub+'-'+b.id,creator:s.sub,run:RUN}},{upsert:true});return send(res,200,{salvo:true});
 }
 if(path==='/appapi/cotacoes'){
  if(method==='GET'){const filter={run:RUN};if(s.role==='fornecedor_graos')filter.supplier=s.sub;else if(s.role!=='dono')filter.creator=s.sub;return send(res,200,(await qs.find(filter).toArray()).map(d=>cleanQuote(s,d)));}
  if(!['dono','analista','corretora'].includes(s.role))return send(res,403,{erro:'Fornecedor não cria cotações.'});
  if(!only(b,['id','clienteId','produto','volume','unidade','precoIndicacao','frete','ufFornecedor'])||!idOk(b.id)||typeof b.clienteId!=='string'||b.produto!=='Milho fictício'||!['SACAS','TL'].includes(b.unidade)||!['FOB','CIF'].includes(b.frete)||!numberOk(b.volume)||b.volume===0||!numberOk(b.precoIndicacao)||!/^[A-Z]{2}$/.test(b.ufFornecedor||''))return send(res,400,{erro:'Confira volume, preço e unidades.'});
  const c=await cs.findOne({run:RUN,id:b.clienteId,...(s.role==='dono'?{}:{creator:s.sub})});if(!c||!supplierSub())return send(res,404,{erro:'Empresa ou fornecedor não disponível.'});
  await qs.updateOne({_id:RUN+':'+s.sub+':'+b.id},{$setOnInsert:{...b,id:s.sub+'-'+b.id,creator:s.sub,supplier:supplierSub(),run:RUN,empresa:c.empresa,endereco:c.endereco,cnpj:c.cnpj,classificacao:c.uf===b.ufFornecedor?'Pedido Deferido':'Pedido Indeferido',vistas:[]}},{upsert:true});return send(res,200,{enviada:true});
 }
 if(path==='/appapi/novas'&&method==='GET'){
  if(s.role==='fornecedor_graos')return send(res,403,{erro:'Não disponível.'});
  return send(res,200,{novas:await qs.countDocuments({run:RUN,resposta:{$exists:true},vistas:{$ne:s.sub},...(s.role==='dono'?{}:{creator:s.sub})})});
 }
 const m=path.match(/^\/appapi\/cotacoes\/([a-zA-Z0-9-]+)(?:\/(resposta|vista|finance))?$/);
 if(m){const d=await qs.findOne({run:RUN,id:m[1]});if(!canQuote(s,d))return send(res,404,{erro:'Cotação não encontrada.'});
  if(method==='GET'&&!m[2])return send(res,200,cleanQuote(s,d));
  if(method==='POST'&&m[2]==='resposta'){
   if(s.role!=='fornecedor_graos'||d.supplier!==s.sub)return send(res,403,{erro:'Apenas o fornecedor destinatário responde.'});
   if(!only(b,['preco','condicoes'])||!numberOk(b.preco)||!textOk(b.condicoes))return send(res,400,{erro:'Confira preço e condições.'});
   await qs.updateOne({_id:d._id},{$set:{resposta:b,vistas:[]}});return send(res,200,{salvo:true});
  }
  if(method==='POST'&&m[2]==='vista'&&s.role!=='fornecedor_graos'){
   if(!only(b,[]))return send(res,400,{erro:'Dados inválidos.'});await qs.updateOne({_id:d._id},{$addToSet:{vistas:s.sub}});return send(res,200,{salvo:true});
  }
  if(method==='POST'&&m[2]==='finance'){
   if(s.role!=='dono')return send(res,403,{erro:'Área exclusiva do dono.'});
   if(!only(b,['comissao','base','repasse','fechado','dataFechamento'])||!numberOk(b.comissao)||!numberOk(b.repasse)||!['SACAS','TL'].includes(b.base)||typeof b.fechado!=='boolean'||typeof b.dataFechamento!=='string'||(b.fechado&&!/^\d{4}-\d{2}-\d{2}$/.test(b.dataFechamento)))return send(res,400,{erro:'Confira comissão, repasse e data de fechamento.'});
   await qs.updateOne({_id:d._id},{$set:{finance:b}});return send(res,200,{salvo:true});
  }
  return send(res,403,{erro:'Ação não permitida.'});
 }
 if(path==='/appapi/ganhos'){
  if(s.role!=='dono')return send(res,403,{erro:'Área exclusiva do dono.'});
  return send(res,200,(await qs.find({run:RUN,'finance.fechado':true}).toArray()).map(d=>cleanQuote(s,d)));
 }
 if(path==='/appapi/limpeza'&&method==='POST'){
  if(s.role!=='dono')return send(res,403,{erro:'Área exclusiva do dono.'});if(!only(b,[]))return send(res,400,{erro:'Dados inválidos.'});
  const c=await cs.deleteMany({run:RUN}),q=await qs.deleteMany({run:RUN});return send(res,200,{clientesApagados:c.deletedCount,cotacoesApagadas:q.deletedCount,clientesRestantes:await cs.countDocuments({run:RUN}),cotacoesRestantes:await qs.countDocuments({run:RUN})});
 }
 return send(res,404,{erro:'Não encontrado.'});
}

const integratedUi = "<!doctype html><html lang=\"pt-BR\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>FGS - teste integrado de grãos</title>\n<style> *{box-sizing:border-box}body{margin:0;background:#12190e;color:#e8ecdf;font:15px/1.55 Arial,sans-serif}main{max-width:1040px;margin:auto;padding:24px 20px}h1{font:32px Georgia,serif;margin:20px 0 8px}h2{font-size:21px}h3{font-size:17px}p{margin:8px 0 14px}.muted,small{color:#a7b19a}.tag{color:#bde58c;font-size:12px;font-weight:bold;letter-spacing:.04em}header{border-bottom:1px solid #48563a;padding-bottom:20px}nav{display:flex;gap:8px;flex-wrap:wrap;padding:18px 0}button,a.button{border:1px solid #627449;border-radius:8px;padding:11px 15px;background:transparent;color:#d9eac7;font:inherit;cursor:pointer;min-height:44px;text-decoration:none;display:inline-block}button.active,button.primary{background:#bde58c;color:#18230e;border-color:#bde58c;font-weight:bold}button:disabled{opacity:.5;cursor:wait}label{display:block;font-size:13px;color:#c3cfb6}input,select{display:block;width:100%;margin:5px 0 14px;background:#12190e;border:1px solid #61704e;border-radius:7px;padding:11px;color:#eef3e5;font:inherit;min-width:0}input[type=checkbox]{display:inline;width:auto;margin-right:8px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 20px}.box{border:1px solid #455433;background:#222d1b;border-radius:12px;padding:20px;margin:15px 0;overflow-wrap:anywhere}.quote h3{margin-top:0}.line{border-top:1px solid #465438;padding-top:12px;margin-top:12px}.finance{border-left:3px solid #bde58c;padding-left:15px;margin-top:20px}.notice{border-left:3px solid #bde58c;padding:12px 16px;background:#222d1b}.error{border-color:#ec9f7b;color:#ffc5ab}#status{position:sticky;top:0;background:#12190e;z-index:2;margin:0;padding:8px 0;min-height:36px}dl{margin:0}dl>div{display:grid;grid-template-columns:1fr 1fr;border-top:1px solid #455433;padding:12px 0;gap:20px}dt{color:#b6c3a8}dd{margin:0;font-weight:bold}details{margin-top:28px}footer{border-top:1px solid #455433;padding:20px 0;margin-top:28px;color:#a7b19a;font-size:12px}@media(max-width:600px){main{padding:18px 14px}.grid{grid-template-columns:1fr}h1{font-size:28px}.box{padding:16px}dl>div{grid-template-columns:1fr;gap:3px}nav button{flex:1}} </style>\n<main><header><div class=\"tag\">TESTE INTEGRADO · SÓ DADOS FICTÍCIOS</div><h1>FGS Representações Comerciais</h1><p class=\"muted\">Cópia separada do fluxo de grãos. Não altera seu FGS principal.</p><div id=\"identity\">Conferindo acesso...</div></header><p id=\"status\" role=\"status\" aria-live=\"polite\"></p><nav id=\"nav\"></nav><section id=\"content\"></section><footer>Login real de teste. Dados gravados no banco isolado enquanto o ensaio estiver ativo. Sem sincronização com o app principal, sem importação e sem convites. A conexão será fechada ao terminar.</footer></main>\n<script>\nlet role='',tab='cotacoes',clients=[],quotes=[],busy=false;let requestIds={};\nconst $=id=>document.getElementById(id),esc=x=>String(x??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));\nconst money=x=>Number.isFinite(x)?x.toLocaleString('pt-BR',{style:'currency',currency:'BRL'}):'Pendente';\nconst msg=(t,error=false)=>{$('status').textContent=t;$('status').className=error?'error':''};\nasync function api(path,method='GET',body){const r=await fetch('/appapi/'+path,{method,headers:method==='POST'?{'Content-Type':'application/json'}:{},body:body===undefined?undefined:JSON.stringify(body)});const d=await r.json();if(!r.ok)throw new Error(d.erro||'Falha ao consultar o teste.');return d;}\nfunction input(label,name,value='',type='text',extra=''){return '<label>'+label+'<input name=\"'+name+'\" value=\"'+esc(value)+'\" type=\"'+type+'\" '+extra+' required></label>'}\nfunction options(name,label,vals){return '<label>'+label+'<select name=\"'+name+'\">'+vals.map(v=>'<option value=\"'+esc(v)+'\">'+esc(v)+'</option>').join('')+'</select></label>'}\nconst roles={dono:'Dono fictício',corretora:'Corretora fictícia',analista:'Analista fictício',fornecedor_graos:'Fornecedor de grãos fictício'};\nasync function start(){try{const m=await api('meta');role=m.papel;$('identity').innerHTML='<strong>'+roles[role]+'</strong><p class=\"muted\">Papel confirmado pelo login, não escolhido na tela.</p><form method=\"post\" action=\"/logout\"><button>Sair desta conta de teste</button></form>';await refresh();}catch(e){$('identity').innerHTML='<p>Sem acesso ativo ao teste.</p><a class=\"button\" href=\"/login\">Entrar no teste</a>';msg(e.message,true);}}\nasync function refresh(){try{quotes=await api('cotacoes');if(role!=='fornecedor_graos')clients=await api('clientes');let count=0;if(role!=='fornecedor_graos')count=(await api('novas')).novas;const tabs=['cotacoes',...(role!=='fornecedor_graos'?['clientes']:[]),...(role==='dono'?['ganhos']:[])];$('nav').innerHTML=tabs.map(t=>'<button data-tab=\"'+t+'\" class=\"'+(tab===t?'active':'')+'\">'+({cotacoes:'Cotações',clientes:'Clientes',ganhos:'Ganhos'}[t])+'</button>').join('')+(role!=='fornecedor_graos'?'<span class=\"tag\" style=\"padding:12px\">Sino: '+count+' nova(s) resposta(s)</span>':'');document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{tab=b.dataset.tab;render()});render();}catch(e){msg(e.message,true);}}\nfunction render(){document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));if(tab==='clientes')renderClients();else if(tab==='ganhos')renderGains();else renderQuotes();}\nfunction renderClients(){$('content').innerHTML='<h2>Empresas do teste</h2><p class=\"muted\">'+(role==='dono'?'Você vê todas as empresas deste ensaio e também pode cadastrar.':'Você vê somente as empresas cadastradas por esta conta.')+'</p><form id=\"clientform\" class=\"box\"><h3>Cadastrar empresa fictícia</h3><div class=\"grid\">'+input('Empresa','empresa')+input('UF (duas letras)','uf','SP','text','maxlength=\"2\" pattern=\"[A-Z]{2}\"')+input('Endereço fictício','endereco')+input('CNPJ fictício','cnpj','00000000000000')+'</div><button class=\"primary\">Salvar empresa no banco de teste</button></form><div>'+clients.map(c=>'<article class=\"box\"><h3>'+esc(c.empresa)+'</h3><p>UF: '+esc(c.uf)+'</p><p>'+esc(c.endereco)+' · '+esc(c.cnpj)+'</p></article>').join('')+'</div>';$('clientform').onsubmit=e=>{e.preventDefault();const b=Object.fromEntries(new FormData(e.target));b.id=requestIds.client||(requestIds.client=crypto.randomUUID());submit('clientes',b,'Empresa salva no banco de teste.',()=>{delete requestIds.client})};}\nfunction quoteForm(){return '<form id=\"quoteform\" class=\"box\"><h3>Enviar cotação fictícia</h3><p class=\"muted\">Envia ao fornecedor fictício deste ensaio. Preço e volume usam a mesma unidade, sem conversão.</p><div class=\"grid\"><label>Empresa<select name=\"clienteId\" required><option value=\"\">Escolher empresa cadastrada</option>'+clients.map(c=>'<option value=\"'+esc(c.id)+'\">'+esc(c.empresa)+'</option>').join('')+'</select></label>'+options('produto','Produto',['Milho fictício'])+input('Volume','volume','100','number','min=\"0.01\" step=\"any\"')+options('unidade','Unidade do volume e do preço',['SACAS','TL'])+input('Preço indicado pelo cliente (R$ por unidade)','precoIndicacao','70','number','min=\"0\" step=\"any\"')+options('frete','Condição',['FOB','CIF'])+input('UF do fornecedor','ufFornecedor','SP','text','maxlength=\"2\" pattern=\"[A-Z]{2}\"')+'</div><button class=\"primary\" '+(!clients.length?'disabled':'')+'>Enviar e gravar cotação</button>'+(!clients.length?'<p>Cadastre uma empresa na aba Clientes primeiro.</p>':'')+'</form>'}\nfunction renderQuotes(){$('content').innerHTML='<h2>Cotações de grãos</h2>'+(role!=='fornecedor_graos'?quoteForm():'<p class=\"muted\">Somente cotações destinadas a esta conta de fornecedor.</p>')+(quotes.length?quotes.map(q=>'<article class=\"box quote\"><h3>'+esc(q.produto)+' · '+esc(q.empresa)+'</h3><p>'+esc(q.volume)+' '+esc(q.unidade)+' · '+money(q.precoIndicacao)+' por '+(q.unidade==='TL'?'TL':'saca')+' · '+esc(q.frete)+'</p><p>'+esc(q.endereco)+' · CNPJ '+esc(q.cnpj)+'</p><p class=\"tag\">'+esc(q.classificacao)+'</p><p>Total da venda: '+money(q.volume*q.precoIndicacao)+'</p><div class=\"line\">'+(q.resposta?'<strong>Fornecedor respondeu: '+money(q.resposta.preco)+' por unidade</strong><p>'+esc(q.resposta.condicoes)+'</p>':'<p>Aguardando resposta do fornecedor.</p>')+'</div>'+(role==='fornecedor_graos'?'<form data-reply=\"'+esc(q.id)+'\"><h3>Responder esta cotação</h3><div class=\"grid\">'+input('Preço do fornecedor (R$ por unidade)','preco',q.resposta?.preco??'68','number','min=\"0\" step=\"any\"')+input('Condições da resposta','condicoes',q.resposta?.condicoes??'Condição fictícia')+'</div><button>Enviar resposta ao criador e ao dono</button></form>':q.resposta?'<button data-seen=\"'+esc(q.id)+'\">Marcar resposta como vista</button>':'')+(role==='dono'?financeForm(q):'')+'<small>ID de teste: '+esc(q.id)+'</small></article>').join(''):'<p class=\"notice\">Nenhuma cotação neste acesso de teste.</p>')+(role==='dono'?'<details><summary>Administração do ensaio</summary><p>Limpa somente os registros desta rodada na cópia integrada.</p><button id=\"cleanup\">Limpar fictícios desta rodada</button></details>':'');\n if($('quoteform'))$('quoteform').onsubmit=e=>{e.preventDefault();const b=Object.fromEntries(new FormData(e.target));b.volume=Number(b.volume);b.precoIndicacao=Number(b.precoIndicacao);b.id=requestIds.quote||(requestIds.quote=crypto.randomUUID());submit('cotacoes',b,'Cotação enviada e salva no banco de teste.',()=>delete requestIds.quote)};\n document.querySelectorAll('[data-reply]').forEach(f=>f.onsubmit=e=>{e.preventDefault();const b=Object.fromEntries(new FormData(f));b.preco=Number(b.preco);submit('cotacoes/'+f.dataset.reply+'/resposta',b,'Resposta salva e disponível para os destinatários.')});\n document.querySelectorAll('[data-seen]').forEach(b=>b.onclick=()=>submit('cotacoes/'+b.dataset.seen+'/vista',{},'Resposta marcada como vista para esta conta.'));\n document.querySelectorAll('[data-finance]').forEach(f=>f.onsubmit=e=>{e.preventDefault();const b=Object.fromEntries(new FormData(f));b.comissao=Number(b.comissao);b.repasse=Number(b.repasse);b.fechado=b.fechado==='on';submit('cotacoes/'+f.dataset.finance+'/finance',b,'Dados privados salvos no banco de teste.')});\n if($('cleanup'))$('cleanup').onclick=async()=>{if(!confirm('Apagar somente os fictícios desta rodada integrada?'))return;try{const r=await api('limpeza','POST',{});msg('Limpeza concluída: '+r.clientesApagados+' empresas e '+r.cotacoesApagadas+' cotações apagadas. Restantes: '+r.clientesRestantes+'/'+r.cotacoesRestantes+'.');await refresh()}catch(e){msg(e.message,true)}};\n}\nfunction financeForm(q){const f=q.finance||{};return '<form class=\"finance\" data-finance=\"'+esc(q.id)+'\"><h3>Minha comissão · só dono</h3><div class=\"grid\">'+input('Minha comissão (R$ por unidade)','comissao',f.comissao??'','number','min=\"0\" step=\"any\"')+'<label>Base da comissão<select name=\"base\"><option '+(f.base!=='TL'?'selected':'')+' value=\"SACAS\">R$/Saca</option><option '+(f.base==='TL'?'selected':'')+' value=\"TL\">R$/TL</option></select></label>'+input('Repasse à corretora (R$ por mesma unidade)','repasse',f.repasse??0,'number','min=\"0\" step=\"any\"')+input('Data de fechamento','dataFechamento',f.dataFechamento||'2026-11-09','date')+'</div><label><input name=\"fechado\" type=\"checkbox\" '+(f.fechado?'checked':'')+'>Negócio fechado</label><p>'+((f.base&&f.base===q.unidade)?'Comissão bruta: '+money(f.comissao*q.volume)+' · Fica comigo: '+money((f.comissao-f.repasse)*q.volume):'Total privado pendente até salvar comissão com unidade compatível.')+'</p><button>Salvar comissão e fechamento</button></form>'}\nfunction renderGains(){const month=window.testMonth||'2026-11';const closed=quotes.filter(q=>q.finance?.fechado&&q.finance.dataFechamento.slice(0,7)===month);let sales=0,commission=0,repasse=0,partial=false;for(const q of closed){sales+=q.volume*q.precoIndicacao;if(q.finance.base!==q.unidade)partial=true;else{commission+=q.finance.comissao*q.volume;repasse+=q.finance.repasse*q.volume}}\nconst rows=[['Valor das vendas fechadas',closed.length?money(sales):'Sem vendas fechadas'],['Minha comissão bruta',closed.length?money(commission)+(partial?' (parcial, unidade pendente)':''):'Não informada'],['Repasse à corretora',closed.length?money(repasse)+(partial?' (parcial)':''):'Sem vendas fechadas'],['Fica comigo',closed.length?money(commission-repasse)+(partial?' (parcial)':''):'Pendente'],['A receber: previsão bruta das comissões',closed.length?money(commission)+(partial?' (parcial)':''):'Pendente'],['Recebido efetivamente','Não informado']];$('content').innerHTML='<h2>Ganhos do mês · só dono</h2><label>Mês de fechamento<input id=\"month\" type=\"month\" value=\"'+month+'\"></label><p class=\"muted\">Somente negócios fechados, pela data de fechamento. Cotações abertas ficam fora.</p><div class=\"box\"><dl>'+rows.map(([k,v])=>'<div><dt>'+k+'</dt><dd>'+v+'</dd></div>').join('')+'</dl></div><p class=\"notice\">A receber é previsão, não saldo conciliado. Não há baixa de recebimentos neste teste. Sem outros descontos ou conversões.</p>';$('month').onchange=e=>{window.testMonth=e.target.value;renderGains()};}\nasync function submit(path,b,success,after){if(busy)return;busy=true;document.querySelectorAll('button').forEach(x=>x.disabled=true);msg('Gravando no banco de teste...');try{await api(path,'POST',b);if(after)after();await refresh();msg(success)}catch(e){msg(e.message,true);document.querySelectorAll('button').forEach(x=>x.disabled=false)}finally{busy=false}}\nstart();\n</script></html>\n";
http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const path = u.pathname;
  if (path.startsWith('/appapi/')) return uiApi(req,res,path,session(req)).catch(()=>send(res,503,{erro:'Conexão do ensaio indisponível. Nada foi confirmado como salvo.'}));
  if (path==='/app' || path==='/') { res.writeHead(200, {'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"});return res.end(integratedUi); }
  if (path.startsWith('/biz/')) return business(req, res, path, session(req)).catch(() => send(res, 503, { erro: 'falha no ensaio' }));
  if (path === '/ensaio') return session(req) ? html(res, 200, bench) : send(res, 401, { erro: 'sem sessao' });
  if (path === '/health') return send(res, 200, { ok: true, auth: !!(ISSUER && CLIENT_ID && BASE), versao: UI_VERSION });
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
