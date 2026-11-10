const FULL_JS=require('fs').readFileSync(__dirname+'/1-fgs-full-app.js','utf8');
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
const ttlValue=Number(process.env.SESSION_TTL_SECONDS||1800);
const TTL=(Number.isFinite(ttlValue)?Math.max(300,Math.min(7200,ttlValue)):1800)*1000;
const TEST_ROLE = 'papel-ficticio-de-teste'; // definido no servidor, so para este teste
const b64u = (b) => Buffer.from(b).toString('base64url');
const rnd = (n = 32) => crypto.randomBytes(n).toString('base64url');
const txns = new Map();
const sessions = new Map();
let meta = null,metaExpires=0;
let jwks = null,jwksExpires=0;

const SECURITY_HEADERS={'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Strict-Transport-Security':'max-age=31536000','Permissions-Policy':'camera=(), microphone=(), geolocation=()','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src data: 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"};
function pruneAuth(){const now=Date.now();for(const[k,v]of txns)if(v.exp<=now)txns.delete(k);for(const[k,v]of sessions)if(v.exp<=now)sessions.delete(k);}
const requestWindows=new Map();
function allowRequest(key,limit,period=60000){const now=Date.now();for(const[k,v]of requestWindows)if(now-v.at>=period)requestWindows.delete(k);let w=requestWindows.get(key);if(!w){if(requestWindows.size>=2000)return false;w={at:now,n:0};requestWindows.set(key,w)}return ++w.n<=limit;}
async function authFetch(url,options={}){const origin=new URL(ISSUER).origin;const u=new URL(url);if(u.protocol!=='https:'||u.origin!==origin)throw Error('endpoint');const r=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(10000)});return r;}
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
  if(!meta||Date.now()>=metaExpires){const r=await authFetch(ISSUER+'/.well-known/openid-configuration');if(!r.ok)throw Error('discovery');const m=await r.json();if(m.issuer!==ISSUER)throw Error('issuer');for(const k of ['authorization_endpoint','token_endpoint','jwks_uri']){const u=new URL(m[k]);if(u.protocol!=='https:'||u.origin!==new URL(ISSUER).origin)throw Error('endpoint')}meta=m;metaExpires=Date.now()+3600000;}
  return meta;
}
async function getKey(kid) {
  if (!jwks || Date.now()>=jwksExpires || !jwks.keys.find((k) => k.kid === kid)) {const r=await authFetch((await discover()).jwks_uri);if(!r.ok)throw Error('jwks');jwks=await r.json();if(!Array.isArray(jwks.keys)||jwks.keys.length>30)throw Error('jwks');jwksExpires=Date.now()+300000;}
  const jwk = jwks.keys.find((k) => k.kid === kid);
  if (!jwk) throw new Error('chave desconhecida');
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}
async function verifyIdToken(tok, nonce) {
  if(typeof tok!=='string'||tok.length>16000||tok.split('.').length!==3)throw Error('token');
  const [h, p, s] = tok.split('.');
  const head = JSON.parse(Buffer.from(h, 'base64url'));
  if(head.crit||typeof head.kid!=='string'||head.kid.length>200)throw Error('header');
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
  if(!Number.isFinite(c.exp)||c.exp<=now-30||!Number.isFinite(c.iat)||c.iat>now+30||c.iat<c.exp-86400)throw Error('exp');if(c.nbf!==undefined&&(!Number.isFinite(c.nbf)||c.nbf>now+30))throw Error('nbf');if(typeof c.sub!=='string'||!c.sub||c.sub.length>200)throw Error('sub');if(Array.isArray(c.aud)&&c.aud.length>1&&c.azp!==CLIENT_ID)throw Error('azp');
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
  pruneAuth();if(!RUN||!ALLOWED.length||!Object.keys(testUsers).length)return html(res,403,'<h1>Teste encerrado</h1>');if(txns.size>=1000)return html(res,429,'<p>Tente mais tarde.</p>');
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
    const r = await authFetch(m.token_endpoint, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: BASE + '/callback', client_id: CLIENT_ID, code_verifier: t.verifier }),
    });
    const tok = await r.json();
    if (!r.ok || !tok.id_token) throw new Error('token');
    const c = await verifyIdToken(tok.id_token, t.nonce);
    const email = String(c.email || '').toLowerCase();
    if (!c.email || !ALLOWED.includes(email) || !roleFor(c.sub)) return html(res, 403, '<h1>Acesso negado</h1><p>Usuario nao autorizado.</p>', { 'Set-Cookie': clear });
    pruneAuth();if(sessions.size>=1000)throw Error('limite');sessions.delete(cookies(req)['__Host-sid']);
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
function only(d,fields){return !!d&&!Array.isArray(d)&&typeof d==='object'&&Object.keys(d).every(k=>fields.includes(k));}

// Isolated full-copy document. Atomic revision check, no production data.
const FULL_VERSION='full-copy-20261109-v2';
const FULL_CATALOG=[{"nome":"DDG","grupo":"Grãos"},{"nome":"Milho","grupo":"Grãos"},{"nome":"Farelo de Soja","grupo":"Grãos"},{"nome":"Óleo de palma RBD","grupo":"Óleos"},{"nome":"Óleo de soja degomado","grupo":"Óleos"},{"nome":"Soja em grãos","grupo":"Grãos"},{"nome":"Azeite de oliva","grupo":"Óleos"},{"nome":"Estearina de palma RBD","grupo":"Óleos"},{"nome":"Óleo de algodão refinado","grupo":"Óleos"},{"nome":"Óleo de amendoim","grupo":"Óleos"},{"nome":"Óleo de arroz","grupo":"Óleos"},{"nome":"Óleo de babaçu","grupo":"Óleos"},{"nome":"Óleo de girassol","grupo":"Óleos"},{"nome":"Óleo de mamona","grupo":"Óleos"},{"nome":"Óleo de palma bruto","grupo":"Óleos"},{"nome":"Óleo de palmiste RBD","grupo":"Óleos"},{"nome":"Óleo de soja bruto","grupo":"Óleos"},{"nome":"Óleo de soja hidrogenado","grupo":"Óleos"},{"nome":"Óleo de soja refinado","grupo":"Óleos"},{"nome":"Algodão","grupo":"Grãos"},{"nome":"Arroz padrão exportação","grupo":"Grãos"},{"nome":"Café","grupo":"Grãos"},{"nome":"Caroço de algodão","grupo":"Grãos"},{"nome":"Milheto","grupo":"Grãos"},{"nome":"Sementes em geral","grupo":"Grãos"},{"nome":"Sorgo","grupo":"Grãos"},{"nome":"Milho em grãos padrão exportação","grupo":"Grãos"},{"nome":"Gordura de palma","grupo":"Gorduras Vegetais"},{"nome":"Gordura vegetal hidrogenada para sorvetes","grupo":"Gorduras Vegetais"},{"nome":"Gorduras vegetais para biscoitos","grupo":"Gorduras Vegetais"},{"nome":"Gorduras vegetais para frituras","grupo":"Gorduras Vegetais"},{"nome":"Gorduras vegetais para chocolates, coberturas, granulados, balas","grupo":"Gorduras Vegetais"},{"nome":"Gorduras vegetais para sorvetes e lácteos","grupo":"Gorduras Vegetais"},{"nome":"Gorduras vegetais para panificação e bolos","grupo":"Gorduras Vegetais"},{"nome":"Açúcar","grupo":"Outros"},{"nome":"Biodiesel","grupo":"Outros"},{"nome":"Casquinha de soja","grupo":"Outros"},{"nome":"Crédito de carbono","grupo":"Outros"},{"nome":"Etanol","grupo":"Outros"},{"nome":"Glicerina bidestilada","grupo":"Outros"},{"nome":"Glicerina bruta","grupo":"Outros"},{"nome":"Lecitina de soja","grupo":"Outros"},{"nome":"Methyil Esther","grupo":"Outros"},{"nome":"Óleo recuperado","grupo":"Outros"},{"nome":"Pluma de algodão","grupo":"Outros"}];
const FULL_UFS=["AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"];
const FULL_PRIVATE=['comissao','comissao_base','repasse','repasse_base','sem_corretora','fechado_em','fechado_em_anterior'];
const fullError=(message,status=400)=>Object.assign(new Error(message),{status});
const fullDate=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(x)&&!isNaN(Date.parse(x))&&new Date(x).toISOString().slice(0,10)===x;
const fullText=(x,max=160)=>typeof x==='string'&&x.trim().length>0&&x.length<=max;
const fullId=x=>typeof x==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(x);
const fullNum=x=>typeof x==='number'&&Number.isFinite(x)&&x>=0&&x<=1e10;
const FULL_SUPPLIER_FIXTURES={'161awl3ftyrg':{nome:'Fornecedor fictício 1',uf:'SP'},s:{nome:'Fornecedor fictício 1',uf:'SP'},t:{nome:'Fornecedor fictício 2',uf:'MG'}};
function fullSuppliers(){return Object.entries(testUsers).filter(([,r])=>r==='fornecedor_graos').map(([sub])=>({id:'fornecedor-'+crypto.createHash('sha256').update(sub).digest('hex').slice(0,16),sub,...(FULL_SUPPLIER_FIXTURES[sub]||{nome:'Fornecedor fictício sem UF configurada',uf:''})}));}
function fullQuote(s,q){const a={...q};if(s.role!=='dono')delete a.creator;delete a.supplier;delete a.seen;if(s.role!=='dono')for(const k of FULL_PRIVATE)delete a[k];a.nova=s.role!=='fornecedor_graos'&&!!q.resposta&&!q.seen?.includes(s.sub);return a;}
function fullView(s,d){const supplier=s.role==='fornecedor_graos';return{version:FULL_VERSION,run:RUN,revision:d.revision,papel:s.role,quotes:d.quotes.filter(q=>s.role==='dono'||(supplier?q.supplier===s.sub:q.creator===s.sub)).map(q=>fullQuote(s,q)),clientes:supplier?[]:d.clientes.filter(c=>s.role==='dono'||c.creator===s.sub).map(({creator,...c})=>s.role==='dono'?{...c,creator}:c),extras:d.extras,suppliers:fullSuppliers().map(({sub,...a})=>a)};}
function validateFullClient(c,owner){if(!c||!fullId(c.id)||!fullText(c.nome)||!fullText(c.uf,2)||!fullText(c.endereco,240)||!fullText(c.cnpj,30))throw fullError('Empresa fictícia exige nome, UF, endereço e CNPJ.');if(!Object.keys(c).every(k=>['id','nome','cidade','segmento','contato','telefone','email','endereco','cnpj','empresa','validado','uf',...owner?['creator']:[]].includes(k)))throw fullError('Campo de empresa não permitido.');for(const[k,v]of Object.entries(c))if(k!=='validado'&&(typeof v!=='string'||v.length>500))throw fullError('Campo de empresa inválido.');if(c.validado!==undefined&&typeof c.validado!=='boolean')throw fullError('Marcador de cadastro inválido.');if(!FULL_UFS.includes(c.uf))throw fullError('UF inválida.');}
function fullValidateQuote(q,owner){const keys=['id','data','produto','grupo','fornecedor','venda','unidade','condicao','empresa','fornecedorNome','quantidade','quantidadeUnidade','prazo_dias','uf_fornecedor','uf_cliente','clienteId','supplierId',...owner?[...FULL_PRIVATE,'creator']:[]];if(!q||!Object.keys(q).every(k=>keys.includes(k)))throw fullError('Campo de cotação não permitido.');if(!fullId(q.id)||!fullDate(q.data)||!fullText(q.produto)||!fullNum(q.venda)||!fullNum(q.quantidade)||q.quantidade<=0||!['Grãos','Óleos','Gorduras Vegetais','Outros'].includes(q.grupo)||!['FOB','CIF'].includes(q.condicao))throw fullError('Confira produto, data, volume e preço.');const units={'R$/saca':'SACAS','R$/ton':'TL','R$/litro':'Litros','R$/kg':'KG'};if(units[q.unidade]!==q.quantidadeUnidade)throw fullError('Preço e volume precisam da mesma base. Sem conversão.');if(q.grupo==='Grãos'&&!['R$/saca','R$/ton'].includes(q.unidade)||q.grupo==='Óleos'&&!['R$/litro','R$/ton'].includes(q.unidade))throw fullError('Unidade incompatível com categoria.');if(q.uf_fornecedor!==undefined&&q.uf_fornecedor!==''&&!FULL_UFS.includes(q.uf_fornecedor))throw fullError('UF do fornecedor inválida.');if(q.prazo_dias!==undefined&&!Number.isInteger(q.prazo_dias))throw fullError('Prazo deve ser inteiro.');for(const k of ['fornecedor','repasse','comissao','prazo_dias'])if(q[k]!==undefined&&!fullNum(q[k]))throw fullError('Número inválido.');for(const k of ['fechado_em','fechado_em_anterior'])if(q[k]!==undefined&&!fullDate(q[k]))throw fullError('Data de fechamento inválida.');if(q.comissao!==undefined&&!(q.grupo==='Grãos'?['R$/saca','R$/ton']:q.grupo==='Óleos'?['%venda']:['%']).includes(q.comissao_base))throw fullError('Base da comissão inválida.');if(q.repasse!==undefined&&!['R$/saca','R$/ton','R$/litro','R$/kg'].includes(q.repasse_base))throw fullError('Base de repasse inválida.');if(q.sem_corretora!==undefined&&typeof q.sem_corretora!=='boolean')throw fullError('Marcador inválido.');}
function fullMerge(s,doc,patch){const next=structuredClone(doc);const owner=s.role==='dono';if(!patch||Array.isArray(patch)||typeof patch!=='object'||!Object.keys(patch).length||!Object.keys(patch).every(k=>['quotes','clientes','extras','reply','seen'].includes(k)))throw fullError('Operação inválida.');if(('reply'in patch||'seen'in patch)&&Object.keys(patch).length!==1)throw fullError('Operação combinada inválida.');if('reply'in patch&&(!patch.reply||Array.isArray(patch.reply)||typeof patch.reply!=='object'))throw fullError('Resposta inválida.');for(const k of ['clientes','quotes','extras'])if(k in patch&&!Array.isArray(patch[k]))throw fullError('Lista inválida.');
 if(patch.clientes){if(s.role==='fornecedor_graos')throw fullError('Área privada.',403);if(!Array.isArray(patch.clientes)||patch.clientes.length>150)throw fullError('Lista de clientes inválida.');const old=doc.clientes.filter(c=>owner||c.creator===s.sub);if(old.some(c=>!patch.clientes.some(n=>n.id===c.id)))throw fullError('Exclusão em lote não permitida neste teste.');const ids=new Set();for(const c of patch.clientes){validateFullClient(c,owner);if(c.creator!==undefined&&(!owner||!testUsers[c.creator]||testUsers[c.creator]==='fornecedor_graos'))throw fullError('Criador do cadastro inválido.');if(ids.has(c.id))throw fullError('Empresa repetida.');ids.add(c.id);const original=doc.clientes.find(x=>x.id===c.id);if(original&&!owner&&original.creator!==s.sub)throw fullError('Empresa não disponível.',404);if(!original&&doc.clientes.some(x=>x.creator===s.sub&&x.nome.toLowerCase()===c.nome.toLowerCase()))throw fullError('Nome de empresa já cadastrado.');next.clientes=next.clientes.filter(x=>x.id!==c.id);next.clientes.push({...c,creator:original?.creator||(owner?c.creator:undefined)||s.sub});}}
 if(patch.extras){if(!owner)throw fullError('Catálogo exclusivo do dono.',403);if(!Array.isArray(patch.extras)||patch.extras.length>100||patch.extras.some(p=>!p||Array.isArray(p)||!fullText(p.nome)||!['Grãos','Óleos','Gorduras Vegetais','Outros'].includes(p.grupo)||!Array.isArray(p.unidades)||p.unidades.some(u=>!['R$/saca','R$/ton','R$/litro','R$/kg'].includes(u))))throw fullError('Produtos inválidos.');const names=new Set(FULL_CATALOG.map(p=>p.nome.toLocaleLowerCase('pt-BR')));for(const p of patch.extras){if(Object.keys(p).some(k=>!['nome','grupo','unidades','condicao','unidadeDemo','serie','margem'].includes(k))||p.condicao!==''||p.margem!==0||!Array.isArray(p.serie)||p.serie.length!==0||p.unidadeDemo!==p.unidades[0]||!p.unidades.length||new Set(p.unidades).size!==p.unidades.length)throw fullError('Produto extra inválido.');const n=p.nome.trim().toLocaleLowerCase('pt-BR');if(names.has(n))throw fullError('Nome de produto já cadastrado.');names.add(n);const prior=doc.extras.find(x=>x.nome===p.nome);if(prior&&JSON.stringify(prior)!==JSON.stringify(p))throw fullError('Não altere produto de catálogo já usado nesta cópia.');}if(doc.extras.some(p=>!patch.extras.some(n=>n.nome===p.nome)))throw fullError('Exclusão de produto não permitida.');next.extras=patch.extras;}
 if(patch.quotes){if(s.role==='fornecedor_graos')throw fullError('Fornecedor apenas responde.',403);if(!Array.isArray(patch.quotes)||patch.quotes.length>250)throw fullError('Lista de cotações inválida.');const visible=doc.quotes.filter(q=>owner||q.creator===s.sub);if(visible.some(q=>!patch.quotes.some(n=>n.id===q.id)))throw fullError('Exclusão em lote não permitida.');const ids=new Set();for(const incoming of patch.quotes){const q={...incoming};if(!['Grãos','Óleos'].includes(q.grupo))throw fullError('Envio desta categoria ainda sem destino aprovado.');const restoredReply=q.resposta;for(const k of ['resposta','nova','cnpj','endereco','destino'])delete q[k];if(restoredReply&&(!fullNum(restoredReply.preco)||restoredReply.preco!==q.fornecedor||!fullText(restoredReply.condicoes,500)||typeof restoredReply.data!=='string'||!Number.isFinite(Date.parse(restoredReply.data))||Object.keys(restoredReply).some(k=>!['preco','condicoes','data'].includes(k))))throw fullError('Resposta de backup inválida.');fullValidateQuote(q,owner);const prod=[...FULL_CATALOG,...next.extras].find(p=>p.nome===q.produto);if(!prod||prod.grupo!==q.grupo)throw fullError('Produto e categoria precisam existir no catálogo.');if(q.creator!==undefined&&(!owner||!testUsers[q.creator]||testUsers[q.creator]==='fornecedor_graos'))throw fullError('Criador da cotação inválido.');if(ids.has(q.id))throw fullError('Cotação repetida.');ids.add(q.id);const old=doc.quotes.find(x=>x.id===q.id);if(restoredReply&&!owner&&(!old||JSON.stringify(restoredReply)!==JSON.stringify(old.resposta)))throw fullError('Resposta só pode ser dada pelo fornecedor.',403);if(old&&!owner&&old.creator!==s.sub)throw fullError('Cotação não disponível.',404);const c=next.clientes.find(x=>x.id===q.clienteId&&(owner||x.creator===s.sub));const oil=q.grupo==='Óleos';if(oil&&!owner&&s.role!=='analista')throw fullError('Fluxo de óleos desta cópia: analista para o dono.',403);const sup=oil?{id:'dono-oleos',sub:null,nome:'Fabiano · recebimento de óleos',uf:q.uf_fornecedor||''}:fullSuppliers().find(x=>x.id===q.supplierId);if(c&&(!owner||(q.creator&&q.creator!==s.sub))&&c.creator!==(old?.creator||(owner?q.creator:undefined)||s.sub))throw fullError('Empresa não pertence ao criador da cotação.');if(oil&&q.creator&&testUsers[q.creator]!=='analista'&&testUsers[q.creator]!=='dono')throw fullError('Criador de óleo não permitido.');if(!c||!sup||oil&&q.supplierId!=='dono-oleos')throw fullError('Escolha empresa e fornecedor cadastrados.');if(!owner&&q.fornecedor!==undefined&&q.fornecedor!==old?.fornecedor)throw fullError('Preço do fornecedor só na resposta.',403);if(old&&(q.clienteId!==old.clienteId||q.supplierId!==old.supplierId||q.venda!==old.venda||q.produto!==old.produto||q.quantidade!==old.quantidade||q.unidade!==old.unidade||q.grupo!==old.grupo||q.fornecedor!==old.fornecedor||q.data!==old.data||q.quantidadeUnidade!==old.quantidadeUnidade||q.condicao!==old.condicao||q.prazo_dias!==old.prazo_dias||q.uf_fornecedor!==old.uf_fornecedor))throw fullError('Não altere a base de uma cotação enviada. Crie outra.');const original={...old};if(owner)for(const k of FULL_PRIVATE)delete original[k];const merged={...original,...q,...(!old&&restoredReply?{resposta:restoredReply}:{}),creator:old?.creator||(owner?q.creator:undefined)||s.sub,supplier:sup.sub,destino:oil?'dono':'fornecedor',empresa:old?.empresa??c.nome,endereco:old?.endereco??c.endereco,cnpj:old?.cnpj??c.cnpj,uf_cliente:old?.uf_cliente??c.uf,uf_fornecedor:old?.uf_fornecedor??sup.uf,fornecedorNome:old?.fornecedorNome??sup.nome,seen:old?.seen||[]};next.quotes=next.quotes.filter(x=>x.id!==q.id);next.quotes.push(merged);}}
 if(patch.reply){const{id,preco,condicoes}=patch.reply;const q=next.quotes.find(x=>x.id===id);if(s.role!=='fornecedor_graos'||!q||q.supplier!==s.sub)throw fullError('Apenas fornecedor destinatário responde.',403);if(!fullNum(preco)||!fullText(condicoes,500)||Object.keys(patch.reply).some(k=>!['id','preco','condicoes'].includes(k)))throw fullError('Resposta inválida.');q.resposta={preco,condicoes,data:new Date().toISOString()};q.fornecedor=preco;q.seen=[];}
 if(patch.seen){const q=next.quotes.find(x=>x.id===patch.seen);if(s.role==='fornecedor_graos'||!q||!(owner||q.creator===s.sub))throw fullError('Resposta não disponível.',404);q.seen=[...new Set([...(q.seen||[]),s.sub])];}
 if(Buffer.byteLength(JSON.stringify(next))>180000)throw fullError('Limite seguro desta cópia atingido.');return next;}
async function fullApi(req,res,path,s){if(!s||testUsers[s.sub]!==s.role)return send(res,401,{erro:'Entre com um login fictício autorizado.'});if(!RUN)return send(res,503,{erro:'Teste encerrado.'});if(!['/fullapi/state','/fullapi/commit','/fullapi/cleanup'].includes(path))return send(res,404,{erro:'Não encontrado.'});if(path==='/fullapi/state'&&req.method!=='GET')return send(res,405,{erro:'Método inválido.'});if(path!=='/fullapi/state'&&(req.method!=='POST'||req.headers.origin!==BASE||!String(req.headers['content-type']||'').startsWith('application/json')))return send(res,403,{erro:'Origem ou método inválido.'});try{const col=(await testDb()).collection('full_copy');const key='full:'+RUN;let d=await col.findOne({_id:key});if(!d){await col.updateOne({_id:key},{$setOnInsert:{revision:0,quotes:[],clientes:[],extras:[],operations:[]}},{upsert:true});d=await col.findOne({_id:key});}if(path==='/fullapi/state'&&req.method==='GET')return send(res,200,fullView(s,d));if(req.method!=='POST'||req.headers.origin!==BASE||!String(req.headers['content-type']||'').startsWith('application/json'))return send(res,403,{erro:'Origem ou método inválido.'});let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>190000)throw fullError('Pedido acima do limite.',413);}let b;try{b=JSON.parse(raw||'{}')}catch(_){throw fullError('JSON inválido.');}if(path==='/fullapi/cleanup'){if(s.role!=='dono'||!only(b,['confirm'])||b.confirm!==RUN)return send(res,403,{erro:'Confirmação inválida.'});const r=await col.deleteMany({_id:key});return send(res,200,{removed:r.deletedCount});}if(path!=='/fullapi/commit'||!only(b,['revision','operationId','patch'])||!Number.isInteger(b.revision)||!fullId(b.operationId))return send(res,400,{erro:'Operação inválida.'});const past=d.operations.find(x=>x.id===b.operationId&&x.sub===s.sub);if(past){if(past.hash!==crypto.createHash('sha256').update(JSON.stringify(b.patch)).digest('hex'))return send(res,409,{erro:'Identificador já usado para outros dados.'});return send(res,200,{...fullView(s,d),repeated:true});}if(d.revision!==b.revision)return send(res,409,{erro:'Outra sessão alterou a base. Atualize e confira antes de repetir. Seu formulário foi mantido.'});const next=fullMerge(s,d,b.patch);next.revision=d.revision+1;next.operations=[...d.operations,{id:b.operationId,sub:s.sub,hash:crypto.createHash('sha256').update(JSON.stringify(b.patch)).digest('hex')}].slice(-60);const r=await col.updateOne({_id:key,revision:d.revision},{$set:{revision:next.revision,quotes:next.quotes,clientes:next.clientes,extras:next.extras,operations:next.operations}});if(r.matchedCount!==1)return send(res,409,{erro:'Conflito de revisão. Nada desta operação foi salvo.'});return send(res,200,fullView(s,next));}catch(e){return send(res,e.status||503,{erro:e.status?e.message:'Banco indisponível. Nada foi confirmado; preserve o formulário.'});}}

const server=http.createServer((req, res) => {
  for(const[k,v]of Object.entries(SECURITY_HEADERS))res.setHeader(k,v);res.setHeader('Cache-Control','no-store');
  pruneAuth();if(!allowRequest('all',600)||!allowRequest('peer:'+req.socket.remoteAddress,300))return send(res,429,{erro:'Limite temporário de pedidos.'});
  const u = new URL(req.url, 'http://x');
  const path = u.pathname;
  if(!['GET','POST'].includes(req.method))return send(res,405,{erro:'Método não permitido.'});
  if((path==='/login'||path==='/callback')&&!allowRequest('auth:'+req.socket.remoteAddress,30))return send(res,429,{erro:'Limite de login. Aguarde.'});
  if(req.method==='POST'&&Number(req.headers['content-length']||0)>190000)return send(res,413,{erro:'Pedido acima do limite.'});
  if (path.startsWith('/fullapi/')) return fullApi(req,res,path,session(req));
  if(path==='/full.js') {res.writeHead(200,{'Content-Type':'text/javascript','Cache-Control':'no-store'});return res.end(FULL_JS);}
  if(path==='/full.css') {res.writeHead(200,{'Content-Type':'text/css','Cache-Control':'no-store'});return res.end(FULL_CSS);}
  if(path.startsWith('/biz/')) return send(res,410,{erro:'Rota antiga desativada.'});
  if(path==='/ensaio')return send(res,410,{erro:'Rota antiga desativada.'});if (false) return session(req) ? html(res, 200, bench) : send(res, 401, { erro: 'sem sessao' });
  if (path === '/health') return send(res, 200, { ok: true, auth: !!(ISSUER && CLIENT_ID && BASE) });
  if(path==='/' && req.method==='GET'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src data: 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"});return res.end('<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FGS · cópia completa de teste</title><link rel="stylesheet" href="/full.css"><div id="root"></div><script src="/full.js"></script></html>');}
  if (path === '/login') return login(req, res).catch(() => html(res, 500, '<p>Erro.</p>'));
  if (path === '/callback') return callback(req, res, u);
  if (path === '/me') { const s = session(req); return s ? send(res, 200, { email: s.email, papel: s.role }) : send(res, 401, { erro: 'sem sessao' }); }
  if (path === '/logout' && req.method === 'POST') {
    if(req.headers.origin!==BASE)return send(res,403,{erro:'Origem inválida.'});
    sessions.delete(cookies(req)['__Host-sid']);
    res.writeHead(302, { Location: '/', 'Set-Cookie': ck('sid', '', 0) });
    return res.end();
  }
  if (path === '/mongo-teste') return send(res, session(req) ? 410 : 401, { erro: 'diagnostico antigo desativado' });
  if (path === '/itens' && !session(req)) return send(res, 401, { erro: 'sem sessao' });
  if (path === '/itens') return send(res, 410, { erro: 'rota antiga desativada' });
  send(res, 404, { erro: 'nao encontrado' });
});server.requestTimeout=15000;server.headersTimeout=10000;server.maxHeadersCount=60;server.listen(PORT,()=>console.log('ok '+PORT));
