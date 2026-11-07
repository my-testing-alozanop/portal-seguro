'use strict';
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

/**
 * Construye la aplicación Express. No abre puertos ni conexiones:
 * así las pruebas (Supertest) pueden usarla directamente.
 */
function createApp({ labVuln = process.env.LAB_VULN === '1' } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '20kb' }));
  app.use(cookieParser());

  // Rutas vulnerables: SOLO con LAB_VULN=1, y montadas ANTES de helmet para que la demostración
  // no quede enmascarada por la CSP (se ve el fallo "puro").
  if (labVuln) {
    app.use('/vuln', require('./routes/vuln'));
  }

  // Fase I-C · Cabeceras de seguridad. La CSP impide ejecutar scripts en línea o de otros
  // orígenes aunque se cuele HTML (defensa en profundidad frente a XSS).
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"],
          'img-src': ["'self'", 'data:'],
          'object-src': ["'none'"],
          'base-uri': ["'self'"],
          'frame-ancestors': ["'none'"],
          'form-action': ["'self'"],
        },
      },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );

  app.get('/api/health', (_req, res) => res.json({ ok: true }));
  app.use('/api/auth', require('./routes/auth'));
  app.use('/api/estudiantes', require('./routes/estudiantes'));
  app.use('/api/notas', require('./routes/notas'));
  app.use('/api/comentarios', require('./routes/comentarios'));
  app.use('/api/reportes', require('./routes/reportes'));

  app.use((_req, res) => res.status(404).json({ error: 'ERR_NO_ENCONTRADO' }));

  // Manejador de errores: nunca devuelve stack, mensajes SQL ni rutas internas.
  // (En la Fase II-E se agrega id de correlación y registro con pino.)
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'ERR_JSON' });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'ERR_TAMANO' });
    if (err.status >= 400 && err.status < 500 && err.code) return res.status(err.status).json({ error: err.code });
    return res.status(500).json({ error: 'ERR_INTERNO' });
  });

  return app;
}

module.exports = { createApp };
