// Servico de teste sintetico: sem dados reais, sem segredos.
const http = require('http');
const items = [];
const PORT = process.env.PORT || 3000;

function send(res, code, body) {
      res.writeHead(code, {
              'Content-Type': 'application/json; charset=utf-8',
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Headers': 'content-type',
              'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      });
      res.end(JSON.stringify(body));
}

http.createServer((req, res) => {  if (req.method === 'OPTIONS') return send(res, 204, {});
                                   if (req.url === '/health') return send(res, 200, { ok: true, itens: items.length });
                                   if (req.url === '/itens' && req.method === 'GET') return send(res, 200, items);
                                   if (req.url === '/itens' && req.method === 'POST') {
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
