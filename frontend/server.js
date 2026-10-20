// Tiny backend-for-frontend: serves the built SPA and proxies /api to Python.
// `request` is deprecated and is here on purpose: its transitive deps
// (tough-cookie, form-data) are vulnerable and request will never ship a fix.
import express from 'express';
import axios from 'axios';
import request from 'request';

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';
const app = express();

app.use(express.static('dist'));

app.get('/api/hello', async (_req, res) => {
  const { data } = await axios.get(`${BACKEND}/hello`);
  res.json({ via: 'axios', ...data });
});

// Legacy endpoint still using `request`.
app.get('/api/legacy', (req, res) => {
  request(`${BACKEND}/hello`).pipe(res);
});

app.listen(3000, () => console.log('frontend on :3000'));
