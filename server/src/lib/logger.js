'use strict';
/**
 * Fase II-E · Registro seguro (secure logging) con pino.
 *
 *  - Formato JSON (una línea por evento): fácil de enviar a un SIEM y de filtrar.
 *  - redact: pino reemplaza por "[REDACTADO]" cualquier campo sensible ANTES de serializar,
 *    aunque un desarrollador lo pase por error (password, token, cookie, authorization, dpi...).
 *  - Correos seudonimizados con HMAC-SHA256 (clave LOG_HMAC_KEY): permite correlacionar los
 *    eventos de una misma cuenta sin guardar el correo. Sin la clave no se puede revertir ni
 *    probar correos por fuerza bruta (a diferencia de un hash simple).
 *  - Nunca se registran: contraseñas, tokens de sesión, claves, credenciales de BD, DPI.
 *
 * Destino: stdout + server/logs/app.log (archivo fuera del repositorio, ver .gitignore).
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const pino = require('pino');
const { getSecrets } = require('../config/secrets');

const CAMPOS_SENSIBLES = ['password', 'password_hash', 'token', 'cookie', 'authorization', 'dpi', 'dpi_cifrado', 'secret'];

const REDACT_PATHS = [
  ...CAMPOS_SENSIBLES,
  ...CAMPOS_SENSIBLES.map((c) => `*.${c}`),
  ...CAMPOS_SENSIBLES.map((c) => `*.*.${c}`),
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
];

const LOG_DIR = path.resolve(__dirname, '..', '..', 'logs');

function crearLogger(destino) {
  return pino(
    {
      level: process.env.LOG_LEVEL || 'info',
      base: { app: 'portal-lab' },
      timestamp: pino.stdTimeFunctions.isoTime,
      redact: { paths: REDACT_PATHS, censor: '[REDACTADO]' },
      formatters: { level: (label) => ({ level: label }) },
    },
    destino,
  );
}

function destinoPorDefecto() {
  if (process.env.NODE_ENV === 'test') return { write: () => {} }; // pruebas: descarta (capturarLogs() redirige)
  fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });
  return pino.multistream([
    { stream: process.stdout },
    { stream: pino.destination({ dest: path.join(LOG_DIR, 'app.log'), mkdir: true, sync: false, mode: 0o600 }) },
  ]);
}

let logger;
const getLogger = () => (logger ??= crearLogger(destinoPorDefecto()));

/** Solo para pruebas: redirige los logs a un stream en memoria. */
function _setLoggerParaPruebas(stream) {
  logger = crearLogger(stream);
  return logger;
}

/** Seudónimo estable del correo: HMAC-SHA256(LOG_HMAC_KEY, correo) truncado. */
function seudonimo(email) {
  if (typeof email !== 'string' || !email) return null;
  const h = crypto.createHmac('sha256', getSecrets().logHmacKey).update(email.trim().toLowerCase()).digest('hex');
  return `u_${h.slice(0, 16)}`;
}

/**
 * Registra un evento de auditoría. Solo se aceptan los eventos definidos (evita que se
 * registren cosas arbitrarias) y los datos pasan por redact.
 */
const EVENTOS = new Set([
  'login_exitoso',
  'login_fallido',
  'consulta_expediente',
  'modificacion_nota',
  'error_interno',
  'acceso_admin',
]);

function auditar(evento, datos = {}, nivel = 'info') {
  if (!EVENTOS.has(evento)) throw new Error(`evento de auditoría desconocido: ${evento}`);
  getLogger()[nivel]({ evento, ...datos }, evento);
}

module.exports = { getLogger, crearLogger, auditar, seudonimo, EVENTOS, REDACT_PATHS, LOG_DIR, _setLoggerParaPruebas };
