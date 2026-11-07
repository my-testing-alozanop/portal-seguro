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

// ------------------------------------------------------------------------------------------
// Proveedor opcional: HashiCorp Vault (motor KV v2) con node-vault.
//   SECRETS_PROVIDER=vault
//   VAULT_ADDR=http://127.0.0.1:8200
//   VAULT_TOKEN=...            (o VAULT_ROLE_ID + VAULT_SECRET_ID para AppRole)
//   VAULT_KV_MOUNT=secret      VAULT_KV_PATH=portal-lab
// Los valores de Vault tienen prioridad sobre el entorno; .env solo conserva la configuración
// de acceso a Vault (no las credenciales de BD ni las claves).
// ------------------------------------------------------------------------------------------
const SECRETOS_VAULT = [...REQUIRED, 'DATA_KEY_V1', 'DATA_KEY_V2', 'DATA_KEY_V3'];

async function leerDeVault(env, crearCliente = require('node-vault')) {
  if (!env.VAULT_ADDR) throw new SecretConfigError('SECRETS_PROVIDER=vault requiere VAULT_ADDR');
  const cliente = crearCliente({ apiVersion: 'v1', endpoint: env.VAULT_ADDR, token: env.VAULT_TOKEN });
  const mount = env.VAULT_KV_MOUNT || 'secret';
  const ruta = env.VAULT_KV_PATH || 'portal-lab';
  try {
    if (!env.VAULT_TOKEN && env.VAULT_ROLE_ID && env.VAULT_SECRET_ID) {
      await cliente.approleLogin({ role_id: env.VAULT_ROLE_ID, secret_id: env.VAULT_SECRET_ID });
    }
    const resp = await cliente.read(`${mount}/data/${ruta}`);
    return resp?.data?.data ?? {};
  } catch (err) {
    // Solo el código de estado: el mensaje de Vault podría incluir rutas o metadatos.
    throw new SecretConfigError(`No se pudo leer secretos de Vault (${err.response?.statusCode ?? err.code ?? 'error'})`);
  }
}

let cache;
let fuente = 'entorno (.env / variables del sistema)';
let origenes = {};

/**
 * Inicializa los secretos al arrancar (asíncrono por Vault). Devuelve la fuente usada y,
 * por cada variable, de dónde vino — nunca los valores.
 */
async function initSecrets(env = process.env, { crearClienteVault } = {}) {
  const proveedor = (env.SECRETS_PROVIDER || 'env').toLowerCase();
  let combinado = env;
  origenes = Object.fromEntries(SECRETOS_VAULT.filter((k) => env[k]).map((k) => [k, 'entorno']));
  if (proveedor === 'vault') {
    const deVault = await leerDeVault(env, crearClienteVault);
    combinado = { ...env };
    for (const k of SECRETOS_VAULT) {
      if (deVault[k] !== undefined) {
        combinado[k] = String(deVault[k]);
        origenes[k] = 'vault';
      }
    }
    fuente = `HashiCorp Vault (${env.VAULT_ADDR}, ${env.VAULT_KV_MOUNT || 'secret'}/${env.VAULT_KV_PATH || 'portal-lab'})`;
  } else if (proveedor !== 'env') {
    throw new SecretConfigError(`SECRETS_PROVIDER desconocido: ${proveedor}`);
  }
  cache = loadSecrets(combinado);
  return { fuente, origenes: { ...origenes } };
}

/** Secretos cargados una sola vez (lazy; sin Vault cuando no se llamó initSecrets). */
function getSecrets() {
  if (!cache) cache = loadSecrets();
  return cache;
}

/** Solo para pruebas. */
function _resetSecretsCache() {
  cache = undefined;
}

module.exports = { getSecrets, loadSecrets, initSecrets, leerDeVault, SecretConfigError, _resetSecretsCache };
