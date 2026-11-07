'use strict';
/**
 * Cifrado autenticado de datos en reposo con AES-256-GCM (node:crypto / OpenSSL).
 * No se implementa ningún algoritmo propio: solo se usa la API estándar.
 *
 * Formato almacenado:  <versión>:<iv b64>:<tag b64>:<ciphertext b64>
 *   - versión  -> identifica la clave (v1, v2...) para permitir rotación.
 *   - iv       -> 12 bytes aleatorios, únicos por cifrado.
 *   - tag      -> etiqueta de autenticación GCM (16 bytes): detecta manipulación.
 *   - aad      -> dato asociado opcional (p. ej. el carné) que liga el cifrado a su registro.
 */
const crypto = require('node:crypto');
const { getSecrets } = require('../config/secrets');

const ALG = 'aes-256-gcm';
const IV_LEN = 12;

function encrypt(plaintext, aad) {
  const { dataKeys, dataKeyCurrent } = getSecrets();
  const key = dataKeys[dataKeyCurrent];
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALG, key, iv);
  if (aad) cipher.setAAD(Buffer.from(String(aad), 'utf8'));
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [dataKeyCurrent, iv.toString('base64'), tag.toString('base64'), ct.toString('base64')].join(':');
}

function decrypt(token, aad) {
  const parts = String(token).split(':');
  if (parts.length !== 4) throw new Error('ERR_CIFRADO_FORMATO');
  const [version, ivB64, tagB64, ctB64] = parts;
  const key = getSecrets().dataKeys[version];
  if (!key) throw new Error('ERR_CIFRADO_VERSION');
  const decipher = crypto.createDecipheriv(ALG, key, Buffer.from(ivB64, 'base64'));
  if (aad) decipher.setAAD(Buffer.from(String(aad), 'utf8'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };
