'use strict';
require('./config/load-env');
const { getSecrets } = require('./config/secrets');
const { createApp } = require('./app');

// Falla al arrancar si falta un secreto (el mensaje solo nombra variables, nunca valores).
try {
  getSecrets();
} catch (err) {
  console.error(`[arranque] ${err.message}`);
  process.exit(1);
}

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);

if (!['127.0.0.1', 'localhost', '::1'].includes(HOST)) {
  console.error('[arranque] Este laboratorio solo puede escuchar en localhost.');
  process.exit(1);
}

const app = createApp();
app.listen(PORT, HOST, () => {
  console.log(`[arranque] API en http://${HOST}:${PORT}  (LAB_VULN=${process.env.LAB_VULN === '1' ? '1' : '0'})`);
});
