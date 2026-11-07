'use strict';
/**
 * Fase II-B · Certificados TLS de LABORATORIO generados con OpenSSL.   npm run cert
 *
 * Se crea una mini-PKI de laboratorio (equivalente local a lo que hace una CA real):
 *   1) CA raíz AUTOFIRMADA (ca.pem)  -> basicConstraints CA:TRUE, keyUsage keyCertSign.
 *   2) Certificado del servidor (cert.pem) firmado por esa CA -> CA:FALSE, serverAuth,
 *      SAN = DNS:localhost, IP:127.0.0.1 (los clientes validan el SAN, no el CN).
 *   3) Se BORRA la clave privada de la CA: nadie (ni un atacante con acceso al disco) puede
 *      emitir más certificados con ella. Para renovar se regenera todo.
 * Los clientes confían SOLO en ca.pem (curl --cacert, proxy de Vite, o importándola en Windows),
 * sin desactivar la verificación TLS.
 *
 * Comandos equivalentes:
 *   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca-key.pem
 *       -out ca.pem -days 365 -subj "/CN=Portal Lab CA"
 *       -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign"
 *   openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem
 *       -out server.csr -subj "/CN=localhost"
 *   openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -set_serial 0x<aleatorio>
 *       -days 365 -sha256 -extfile server-ext.cnf -out cert.pem
 *
 * openssl se invoca con execFileSync y un ARREGLO de argumentos (sin shell), como en la Fase I-D.
 * certs/ está en .gitignore: las claves privadas nunca se versionan.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const CERT_DIR = path.resolve(__dirname, '..', 'certs');
const CURVA = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes'];

function buscarOpenssl() {
  const candidatos = [
    process.env.OPENSSL_BIN,
    'openssl',
    'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
    'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
    'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe',
  ].filter(Boolean);
  for (const bin of candidatos) {
    try {
      execFileSync(bin, ['version'], { stdio: 'ignore' });
      return bin;
    } catch {
      /* siguiente candidato */
    }
  }
  return null;
}

function generarCertificados(destino = CERT_DIR, { dias = 365 } = {}) {
  const openssl = buscarOpenssl();
  if (!openssl) throw new Error('No se encontró openssl (instale Git for Windows o defina OPENSSL_BIN)');
  fs.mkdirSync(destino, { recursive: true, mode: 0o700 });
  const p = (f) => path.join(destino, f);
  const run = (args) => execFileSync(openssl, args, { stdio: 'pipe' });

  // 1) CA raíz de laboratorio
  run(['req', '-x509', ...CURVA, '-keyout', p('ca-key.pem'), '-out', p('ca.pem'), '-days', String(dias),
    '-subj', '/CN=Portal Lab CA (solo laboratorio)',
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);

  // 2) Clave y solicitud del servidor
  run(['req', ...CURVA, '-keyout', p('key.pem'), '-out', p('server.csr'), '-subj', '/CN=localhost']);

  // 3) Firma del certificado del servidor por la CA
  fs.writeFileSync(p('server-ext.cnf'), [
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=serverAuth',
    'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '',
  ].join('\n'));
  run(['x509', '-req', '-in', p('server.csr'), '-CA', p('ca.pem'), '-CAkey', p('ca-key.pem'),
    '-set_serial', `0x${crypto.randomBytes(16).toString('hex')}`, '-days', String(dias), '-sha256',
    '-extfile', p('server-ext.cnf'), '-out', p('cert.pem')]);

  // 4) Limpieza: sin clave de la CA ni archivos intermedios
  for (const f of ['ca-key.pem', 'server.csr', 'server-ext.cnf']) fs.rmSync(p(f), { force: true });
  try { fs.chmodSync(p('key.pem'), 0o600); } catch { /* Windows: ACL del perfil de usuario */ }

  return { ca: p('ca.pem'), cert: p('cert.pem'), key: p('key.pem'), openssl };
}

if (require.main === module) {
  const r = generarCertificados();
  console.log(`CA de laboratorio:      ${r.ca}`);
  console.log(`Certificado servidor:   ${r.cert}`);
  console.log(`Clave privada servidor: ${r.key}`);
  console.log('Clave privada de la CA: eliminada tras firmar.');
  console.log('\nInspeccionar: openssl x509 -in certs/cert.pem -noout -subject -issuer -ext subjectAltName -dates');
}

module.exports = { generarCertificados, buscarOpenssl };
