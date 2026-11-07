'use strict';
/**
 * Utilidades TLS para pruebas.
 * Se genera una PKI de laboratorio temporal con OpenSSL y el servidor HTTPS escucha en un
 * NAMED PIPE (Windows) o socket Unix: así la prueba verifica NUESTRA configuración TLS aunque un
 * antivirus intercepte las conexiones TCP de loopback (caso detectado con Norton Web Shield).
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const tls = require('node:tls');
const crypto = require('node:crypto');
const { generarCertificados, buscarOpenssl } = require('../scripts/gen-cert');
const { crearServidorHttps } = require('../src/https');

const hayOpenssl = Boolean(buscarOpenssl());

function rutaSocket() {
  const id = crypto.randomBytes(6).toString('hex');
  return process.platform === 'win32' ? `\\\\.\\pipe\\portal-lab-tls-${id}` : path.join(os.tmpdir(), `portal-lab-tls-${id}.sock`);
}

async function levantarHttps(app) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-lab-certs-'));
  const certs = generarCertificados(dir, { dias: 1 });
  const server = crearServidorHttps(app, { cert: certs.cert, key: certs.key });
  const socketPath = rutaSocket();
  await new Promise((r) => server.listen(socketPath, r));
  const ca = fs.readFileSync(certs.ca);

  const get = (ruta, extra = {}) => new Promise((resolve, reject) => {
    const req = https.get({ socketPath, path: ruta, host: 'localhost', servername: 'localhost', ca, agent: false, ...extra }, (res) => {
      // Datos TLS leídos al recibir la respuesta (al terminar, el socket se libera).
      const tlsInfo = {
        protocolo: res.socket.getProtocol(), cifrado: res.socket.getCipher(),
        certificado: res.socket.getPeerX509Certificate(),
      };
      let cuerpo = '';
      res.on('data', (c) => { cuerpo += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, cuerpo, ...tlsInfo }));
    });
    req.on('error', reject);
  });

  const conectarTls = (opciones) => new Promise((resolve, reject) => {
    const s = tls.connect({ path: socketPath, host: 'localhost', servername: 'localhost', ca, ...opciones }, () => {
      const r = { protocolo: s.getProtocol(), autorizado: s.authorized };
      s.end();
      resolve(r);
    });
    s.on('error', reject);
  });

  const cerrar = () => new Promise((r) => {
    server.close(() => { fs.rmSync(dir, { recursive: true, force: true }); r(); });
  });

  return { get, conectarTls, cerrar, certs };
}

module.exports = { hayOpenssl, levantarHttps };
