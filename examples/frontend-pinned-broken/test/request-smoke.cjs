// Exercises every transitive dep of `request` we might pin:
//   form-data (multipart), qs (querystring), tough-cookie (cookie jar), uuid (multipart boundary).
// Run before/after adding npm `overrides` to prove the pin didn't break anything.
const http = require('node:http');
const assert = require('node:assert');

let request;
try {
  request = require('request');
} catch (err) {
  console.error('FAIL: request could not even load ->', err.code || err.message);
  process.exit(1);
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    res.setHeader('Set-Cookie', 'session=abc123; Path=/');
    res.end(JSON.stringify({ url: req.url, ct: req.headers['content-type'] || '', cookie: req.headers.cookie || '', body }));
  });
});

server.listen(0, async () => {
  const base = `http://127.0.0.1:${server.address().port}`;
  const jar = request.jar();
  const call = (opts) => new Promise((ok, fail) =>
    request({ jar, json: true, ...opts }, (e, _r, b) => (e ? fail(e) : ok(b))));
  try {
    const q = await call({ url: `${base}/q`, qs: { a: [1, 2], b: { c: 'd' } } });
    assert.match(decodeURIComponent(q.url), /a\[0\]=1&a\[1\]=2&b\[c\]=d/);
    console.log('ok  qs            ', q.url);

    const c = await call({ url: `${base}/c` });
    assert.equal(c.cookie, 'session=abc123');
    console.log('ok  tough-cookie  ', c.cookie);

    const f = await call({ url: `${base}/f`, method: 'POST', formData: { field: 'value' } });
    assert.match(f.ct, /^multipart\/form-data; boundary=/);
    assert.match(f.body, /name="field"/);
    console.log('ok  form-data     ', f.ct.slice(0, 40) + '…');

    const m = await call({ url: `${base}/m`, method: 'POST', multipart: [{ body: 'x' }], json: false });
    assert.match(JSON.parse(m).ct, /boundary=[0-9a-f-]{36}/);
    console.log('ok  uuid          ', 'multipart boundary generated');
    console.log('PASS');
  } catch (err) {
    console.error('FAIL:', err.message);
    process.exitCode = 1;
  } finally {
    server.close();
  }
});
