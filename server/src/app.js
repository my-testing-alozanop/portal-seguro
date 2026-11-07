'use strict';
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { rateLimit } = require('express-rate-limit');
const requestId = require('./middleware/request-id');
const { auditar } = require('./lib/logger');

/**
 * Construye la aplicación Express. No abre puertos ni conexiones:
 * así las pruebas (Supertest) pueden usarla directamente.
 *
 * @param {object}  opciones
 * @param {boolean} opciones.labVuln   monta /vuln (solo LAB_VULN=1)
 * @param {number}  opciones.loginMax  intentos FALLIDOS de login permitidos por IP en 15 min
 */
function createApp({
  labVuln = process.env.LAB_VULN === '1',
  loginMax = Number(process.env.LOGIN_RATE_MAX || 5),
} = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(requestId);
  app.use(express.json({ limit: '20kb' }));
  app.use(cookieParser());

  // Rutas vulnerables: SOLO con LAB_VULN=1, y montadas ANTES de helmet para que la demostración
  // no quede enmascarada por la CSP (se ve el fallo "puro").
  if (labVuln) {
    app.use('/vuln', require('./routes/vuln'));
  }

  // Fase I-C · Cabeceras de seguridad. La CSP impide ejecutar scripts en línea o de otros
  // orígenes aunque se cuele HTML (defensa en profundidad frente a XSS).
  // HSTS: tras la primera visita por HTTPS el navegador no vuelve a usar HTTP (Fase II-B).
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

  // Fase II-A · Límite de intentos de login: 5 fallos por IP cada 15 minutos (solo cuentan los
  // fallidos). Frena fuerza bruta y relleno de credenciales; el mensaje sigue siendo genérico.
  const limiteLogin = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: loginMax,
    skipSuccessfulRequests: true,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: (req, res) => {
      auditar('login_fallido', { req_id: req.id, ip: req.ip, motivo: 'limite_intentos' }, 'warn');
      res.status(429).json({ error: 'ERR_DEMASIADOS_INTENTOS' });
    },
  });

  app.get('/api/health', (_req, res) => res.json({ ok: true }));
  app.use('/api/auth/login', limiteLogin);
  app.use('/api/auth', require('./routes/auth'));
  app.use('/api/estudiantes', require('./routes/estudiantes'));
  app.use('/api/notas', require('./routes/notas'));
  app.use('/api/comentarios', require('./routes/comentarios'));
  app.use('/api/reportes', require('./routes/reportes'));

  app.use((_req, res) => res.status(404).json({ error: 'ERR_NO_ENCONTRADO' }));

  // Fase II-E · Manejador de errores. Al cliente: SOLO un código y el id de correlación.
  // Nunca stack, mensajes SQL, rutas internas, claves ni tokens. El detalle técnico mínimo
  // (tipo y código del error) va al log interno, ligado por el mismo id.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'ERR_JSON', id: req.id });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'ERR_TAMANO', id: req.id });
    if (err.status >= 400 && err.status < 500 && err.code) {
      return res.status(err.status).json({ error: err.code, id: req.id });
    }
    auditar('error_interno', {
      req_id: req.id,
      metodo: req.method,
      ruta: req.baseUrl + (req.route?.path ?? ''), // sin query string (puede llevar datos personales)
      error: { tipo: err.name, codigo: err.code ?? null, sql_state: err.sqlState ?? null },
    }, 'error');
    return res.status(500).json({ error: 'ERR_INTERNO', id: req.id });
  });

  return app;
}

module.exports = { createApp };
