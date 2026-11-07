'use strict';
/**
 * Fase II-B · Protección en tránsito con TLS (node:https / OpenSSL).
 *  - TLS 1.2 como mínimo (TLS 1.0/1.1 están obsoletos: RFC 8996).
 *  - En TLS 1.2 solo suites ECDHE (secreto perfecto hacia adelante) con cifrado autenticado
 *    AEAD (AES-GCM / ChaCha20-Poly1305). TLS 1.3 usa sus suites seguras por defecto.
 *  - Certificado autofirmado generado con OpenSSL (scripts/gen-cert.js) SOLO para laboratorio;
 *    en producción se usaría un certificado emitido por una CA (p. ej. Let's Encrypt).
 */
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');

const CERT_DIR = path.resolve(__dirname, '..', 'certs');
const CERT_FILE = process.env.TLS_CERT_FILE || path.join(CERT_DIR, 'cert.pem');
const KEY_FILE = process.env.TLS_KEY_FILE || path.join(CERT_DIR, 'key.pem');

const TLS_OPCIONES = Object.freeze({
  minVersion: 'TLSv1.2',
  ciphers: [
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
  ].join(':'),
  honorCipherOrder: true,
});

const hayCertificados = (cert = CERT_FILE, key = KEY_FILE) => fs.existsSync(cert) && fs.existsSync(key);

function crearServidorHttps(app, { cert = CERT_FILE, key = KEY_FILE } = {}) {
  return https.createServer({ ...TLS_OPCIONES, cert: fs.readFileSync(cert), key: fs.readFileSync(key) }, app);
}

/**
 * Manejador del puerto HTTP: no sirve datos, redirige a HTTPS con 308 (conserva método y
 * cuerpo). El host de destino es FIJO (localhost): usar la cabecera Host del cliente
 * permitiría redirecciones abiertas.
 */
const crearRedireccionHttps = (httpsPort) => (req, res) => {
  res.writeHead(308, { Location: `https://localhost:${httpsPort}${req.url}` });
  res.end();
};

module.exports = { crearServidorHttps, crearRedireccionHttps, hayCertificados, TLS_OPCIONES, CERT_FILE, KEY_FILE, CERT_DIR };
