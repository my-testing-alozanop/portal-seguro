# Portal Universitario · Laboratorio de Seguridad en Aplicaciones (MASI 2026)

Portal **deliberadamente vulnerable y su versión corregida**. Solo localhost, solo datos ficticios.
La guía completa de instalación y reproducción se completa al final del proyecto.

## Inicio rápido (Fase 0)

```bash
cd server
npm install
cp .env.example .env        # completar valores (ver abajo)
npm run db:reset            # migraciones + seed de 8 estudiantes ficticios
npm test
npm run dev                 # API en http://127.0.0.1:3000

cd ../client
npm install
npm run dev                 # UI en http://127.0.0.1:5173
```

Generar cada clave de `server/.env` (SESSION_SECRET, DATA_KEY_V1, LOG_HMAC_KEY):

```bash
openssl rand -base64 32
```
