'use strict';
require('./config/load-env');
const http = require('node:http');
const { initSecrets } = require('./config/secrets');
const { createApp } = require('./app');
const { crearServidorHttps, crearRedireccionHttps, hayCertificados } = require('./https');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 3443);
const LAB = process.env.LAB_VULN === '1' ? '1' : '0';

async function main() {
  // Falla al arrancar si falta un secreto (el mensaje solo nombra variables, nunca valores).
  // Con SECRETS_PROVIDER=vault, los secretos se leen primero de HashiCorp Vault.
  try {
    const { fuente } = await initSecrets();
    console.log(`[arranque] secretos cargados desde: ${fuente}`);
  } catch (err) {
    console.error(`[arranque] ${err.message}`);
    process.exit(1);
  }

  if (!['127.0.0.1', 'localhost', '::1'].includes(HOST)) {
    console.error('[arranque] Este laboratorio solo puede escuchar en localhost.');
    process.exit(1);
  }

  const app = createApp();

  if (!hayCertificados()) {
    console.warn('[arranque] Sin certificado TLS (ejecute "npm run cert"). Sirviendo SOLO HTTP.');
    http.createServer(app).listen(PORT, HOST, () => {
      console.log(`[arranque] API en http://${HOST}:${PORT}  (LAB_VULN=${LAB})`);
    });
    return;
  }

  crearServidorHttps(app).listen(HTTPS_PORT, HOST, () => {
    console.log(`[arranque] API en https://localhost:${HTTPS_PORT}  (TLS >= 1.2, LAB_VULN=${LAB})`);
  });

  // El puerto HTTP ya no sirve datos: redirige permanentemente a HTTPS (ver https.js).
  http.createServer(crearRedireccionHttps(HTTPS_PORT)).listen(PORT, HOST, () => {
    console.log(`[arranque] http://${HOST}:${PORT} -> redirige a HTTPS`);
  });
}

main();
