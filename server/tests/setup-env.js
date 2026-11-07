'use strict';
/**
 * Entorno de PRUEBA: no lee server/.env. Las claves se generan aleatoriamente
 * en cada ejecución, así no existe ningún secreto fijo en el repositorio.
 * Las credenciales de BD de prueba solo se toman si ya existen en el entorno
 * (ver tests/helpers/db.js para las pruebas de integración).
 */
const crypto = require('node:crypto');

const rnd = () => crypto.randomBytes(32).toString('base64');

process.env.NODE_ENV = 'test';
process.env.DB_HOST ??= '127.0.0.1';
process.env.DB_PORT ??= '3306';
process.env.DB_USER ??= 'portal_app';
process.env.DB_PASSWORD ??= 'sin-bd-en-pruebas-unitarias';
process.env.DB_NAME ??= 'portal_lab';
process.env.SESSION_SECRET = rnd();
process.env.DATA_KEY_V1 = rnd();
process.env.DATA_KEY_CURRENT = 'v1';
process.env.LOG_HMAC_KEY = rnd();
