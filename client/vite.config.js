import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// El cliente solo escucha en localhost y reenvía /api y /vuln a la API local.
// En la Fase II-B el destino pasa a https://localhost:3443 (certificado autofirmado).
const API = process.env.VITE_API_TARGET || 'http://127.0.0.1:3000';

const proxy = {
  '/api': { target: API, changeOrigin: true, secure: false },
  '/vuln': { target: API, changeOrigin: true, secure: false },
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
