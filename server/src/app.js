'use strict';
const express = require('express');

/**
 * Construye la aplicación Express. No abre puertos ni conexiones:
 * así las pruebas (Supertest) pueden usarla directamente.
 */
function createApp({ labVuln = process.env.LAB_VULN === '1' } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '20kb' }));

  app.get('/api/health', (_req, res) => res.json({ ok: true }));

  // Rutas vulnerables: SOLO con LAB_VULN=1
  if (labVuln) {
    app.use('/vuln', require('./routes/vuln'));
  }

  app.use((_req, res) => res.status(404).json({ error: 'ERR_NO_ENCONTRADO' }));

  return app;
}

module.exports = { createApp };
