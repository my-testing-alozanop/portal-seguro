'use strict';
/**
 * Fase II-B · Evidencia de TLS contra la API en ejecución.   npm run tls:check
 * Se conecta a https://localhost:3443 confiando SOLO en la CA de laboratorio (certs/ca.pem) e
 * imprime protocolo, suite de cifrado y certificado. Luego intenta TLS 1.1 (debe fallar).
 * Si un antivirus intercepta TLS (p. ej. Norton Web Shield), lo detecta y lo informa.
 */
const fs = require('node:fs');
const path = require('node:path');
const tls = require('node:tls');

const PUERTO = Number(process.env.HTTPS_PORT || 3443);
const CA = path.resolve(__dirname, '..', 'certs', 'ca.pem');

function conectar(opciones) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host: 'localhost', port: PUERTO, servername: 'localhost', ca: fs.readFileSync(CA), ...opciones }, () => {
      const r = { protocolo: s.getProtocol(), cifrado: s.getCipher(), cert: s.getPeerX509Certificate(), autorizado: s.authorized, error: s.authorizationError };
      s.end();
      resolve(r);
    });
    s.on('error', reject);
  });
}

async function main() {
  console.log(`Conectando a https://localhost:${PUERTO} (confiando solo en certs/ca.pem)\n`);
  const r = await conectar({ rejectUnauthorized: false });
  console.log(`Protocolo negociado : ${r.protocolo}`);
  console.log(`Suite de cifrado    : ${r.cifrado.standardName || r.cifrado.name}`);
  console.log(`Certificado sujeto  : ${r.cert.subject}`);
  console.log(`Emitido por         : ${r.cert.issuer.replace(/\n/g, ', ')}`);
  console.log(`SAN                 : ${r.cert.subjectAltName}`);
  console.log(`Válido hasta        : ${r.cert.validTo}`);
  console.log(`Certificado válido  : ${r.autorizado ? 'SÍ (cadena verificada contra la CA de laboratorio)' : `NO (${r.error})`}`);

  if (/norton|avast|kaspersky|eset|bitdefender|avg/i.test(r.cert.issuer)) {
    console.log('\n⚠ El certificado recibido NO es el del servidor: un antivirus está interceptando TLS');
    console.log('  (inspección HTTPS). Agregue una excepción para localhost/127.0.0.1 en su antivirus.');
    process.exitCode = 2;
    return;
  }

  try {
    await conectar({ minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0' });
    console.log('\nCliente TLS 1.1     : ACEPTADO  ✗ (no debería)');
    process.exitCode = 1;
  } catch (err) {
    console.log(`\nCliente TLS 1.1     : RECHAZADO ✓ (${err.code || err.message})`);
  }
}

main().catch((err) => {
  console.error(`No se pudo conectar: ${err.code || err.message}. ¿Está la API corriendo con certificados (npm run cert)?`);
  process.exitCode = 1;
});
