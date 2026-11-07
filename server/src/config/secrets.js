'use strict';
/**
 * Único punto de acceso a secretos de la aplicación.
 *
 * - Ningún secreto vive en el código fuente: todos provienen de una fuente externa
 *   (variables de entorno cargadas desde server/.env; en la Fase II-C, opcionalmente Vault).
 * - Si falta un secreto o tiene formato inválido, se lanza un error que menciona
 *   SOLO el NOMBRE de la variable, jamás su valor.
 */

class SecretConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SecretConfigError';
  }
}

const REQUIRED = [
  'DB_HOST',
  'DB_PORT',
  'DB_USER',
  'DB_PASSWORD',
  'DB_NAME',
  'SESSION_SECRET',
  'DATA_KEY_CURRENT',
  'LOG_HMAC_KEY',
];

const PLACEHOLDER = '__CAMBIAR__';

function readRaw(name, env) {
  const v = env[name];
  if (v === undefined || v === '' || v === PLACEHOLDER) return undefined;
  return v;
}

/** Devuelve el anillo de claves de datos { v1: Buffer(32), v2: ... } */
function loadDataKeys(env) {
  const keys = {};
  for (const name of Object.keys(env)) {
    const m = /^DATA_KEY_V(\d+)$/.exec(name);
    if (!m) continue;
    const raw = readRaw(name, env);
    if (!raw) continue;
    const buf = Buffer.from(raw, 'base64');
    if (buf.length !== 32) {
      throw new SecretConfigError(`${name} debe ser base64 de 32 bytes (AES-256)`);
    }
    keys[`v${m[1]}`] = buf;
  }
  return keys;
}

function loadSecrets(env = process.env) {
  const missing = REQUIRED.filter((k) => readRaw(k, env) === undefined);
  if (missing.length) {
    throw new SecretConfigError(`Configuración incompleta; faltan: ${missing.join(', ')}`);
  }

  const dataKeys = loadDataKeys(env);
  const current = env.DATA_KEY_CURRENT;
  if (!dataKeys[current]) {
    throw new SecretConfigError(`DATA_KEY_CURRENT=${current} no corresponde a ninguna DATA_KEY_V* válida`);
  }

  for (const name of ['SESSION_SECRET', 'LOG_HMAC_KEY']) {
    if (Buffer.from(env[name], 'base64').length < 32) {
      throw new SecretConfigError(`${name} debe tener al menos 32 bytes de entropía (base64)`);
    }
  }

  return Object.freeze({
    db: Object.freeze({
      host: env.DB_HOST,
      port: Number(env.DB_PORT),
      user: env.DB_USER,
      password: env.DB_PASSWORD,
      database: env.DB_NAME,
    }),
    sessionSecret: env.SESSION_SECRET,
    logHmacKey: Buffer.from(env.LOG_HMAC_KEY, 'base64'),
    dataKeys: Object.freeze(dataKeys),
    dataKeyCurrent: current,
  });
}

let cache;
/** Secretos cargados una sola vez (lazy). */
function getSecrets() {
  if (!cache) cache = loadSecrets();
  return cache;
}

/** Solo para pruebas. */
function _resetSecretsCache() {
  cache = undefined;
}

module.exports = { getSecrets, loadSecrets, SecretConfigError, _resetSecretsCache };
