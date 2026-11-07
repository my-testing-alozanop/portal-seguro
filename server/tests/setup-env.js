'use strict';
/**
 * Entorno de PRUEBA. Ningún secreto está escrito en el repositorio:
 *  - DB_* y DATA_KEY_* se toman de server/.env si existe (pruebas de integración).
 *  - SESSION_SECRET y LOG_HMAC_KEY se generan aleatoriamente en cada ejecución.
 *  - Sin .env, todo es aleatorio/ficticio y las pruebas de integración se omiten.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const rnd = () => crypto.randomBytes(32).toString('base64');

// DATA_KEY_* se necesita para descifrar los DPI cargados por el seed.
const envFile = path.join(__dirname, '..', '.env');
if (fs.existsSync(envFile)) {
  const parsed = require('dotenv').parse(fs.readFileSync(envFile));
  for (const [k, v] of Object.entries(parsed)) {
    if (/^(DB_|DATA_KEY_)/.test(k) && process.env[k] === undefined) process.env[k] = v;
  }
}

process.env.NODE_ENV = 'test';
process.env.DB_HOST ??= '127.0.0.1';
process.env.DB_PORT ??= '3306';
process.env.DB_USER ??= 'portal_app';
process.env.DB_PASSWORD ??= 'sin-bd-en-pruebas-unitarias';
process.env.DB_NAME ??= 'portal_lab';
process.env.SESSION_SECRET = rnd();
process.env.DATA_KEY_V1 ??= rnd();
process.env.DATA_KEY_CURRENT ??= 'v1';
process.env.LOG_HMAC_KEY = rnd();
