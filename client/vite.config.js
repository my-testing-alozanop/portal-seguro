import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// El cliente solo escucha en localhost y reenvía /api y /vuln a la API local.
// Fase II-B: si existe server/certs/cert.pem, la API corre en HTTPS (3443) y el proxy la
// contacta por TLS VALIDANDO el certificado contra la CA de laboratorio (certs/ca.pem),
// no se desactiva la verificación).
const CERT = fileURLToPath(new URL('../server/certs/ca.pem', import.meta.url));
const hayTls = fs.existsSync(CERT);

const target = hayTls
  ? { protocol: 'https:', host: 'localhost', port: Number(process.env.API_HTTPS_PORT || 3443), ca: fs.readFileSync(CERT) }
  : `http://127.0.0.1:${process.env.API_PORT || 3000}`;

const proxy = {
  '/api': { target, changeOrigin: true, secure: true },
  '/vuln': { target, changeOrigin: true, secure: true },
};

// CSP del build de producción (npm run build && npm run preview). Sin 'unsafe-inline':
// aunque un componente Vuln* inserte <img onerror=...>, el navegador NO ejecuta el manejador.
// En "npm run dev" no se aplica porque Vite inyecta un script en línea para recarga en caliente.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ');

export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
    proxy,
    headers: {
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  },
});
