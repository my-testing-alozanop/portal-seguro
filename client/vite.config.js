import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// El cliente solo escucha en localhost y reenvía /api y /vuln a la API local.
// En la Fase II-B el destino pasa a https://localhost:3443 (certificado autofirmado).
const API = process.env.VITE_API_TARGET || 'http://127.0.0.1:3000';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: API, changeOrigin: true, secure: false },
      '/vuln': { target: API, changeOrigin: true, secure: false },
    },
  },
});
