const express = require('express');
const app = express();

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'sample-app', version: '0.1.0' });
});

app.get('/', (req, res) => {
  res.send('Hello from sample-app with OpenTelemetry!');
});

app.listen(3000, () => {
  console.log('sample-app listening on :3000');
});
