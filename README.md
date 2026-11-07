# Portal Universitario · Laboratorio de Seguridad en Aplicaciones (MASI 2026)

Portal **deliberadamente vulnerable y su versión corregida**. Solo localhost, solo datos ficticios.
La guía completa de instalación y reproducción se completa al final del proyecto.

## Inicio rápido

```bash
cd server
npm install
cp .env.example .env        # completar valores (ver abajo)
npm run db:reset            # migraciones + seed de 8 estudiantes ficticios
npm run cert                # CA de laboratorio + certificado TLS (OpenSSL) -> HTTPS
npm test
npm run dev                 # API en https://localhost:3443  (http://127.0.0.1:3000 redirige)

cd ../client
npm install
npm run dev                 # UI en http://127.0.0.1:5173 (proxy TLS hacia la API)

cd ..
npm install                 # activa el hook pre-commit de Husky + gitleaks
```

Generar cada clave de `server/.env` (SESSION_SECRET, DATA_KEY_V1, LOG_HMAC_KEY):

```bash
openssl rand -base64 32
```

## Scripts útiles (`server/`)
| Comando | Qué hace |
|---|---|
| `npm run cert` | Genera la CA de laboratorio y el certificado de `localhost` (borra la clave de la CA) |
| `npm run tls:check` | Muestra protocolo, cifrado y certificado de la API en ejecución; prueba que TLS 1.1 se rechace |
| `npm run secrets:check` | Muestra de dónde vino cada secreto (entorno o Vault) sin revelar valores |
| `npm run rotar-clave` | Re-cifra los DPI con la clave activa (`DATA_KEY_CURRENT`) |

> **Antivirus con inspección HTTPS (p. ej. Norton Web Shield):** re-firma las conexiones TLS de
> localhost con su propia CA y los clientes rechazan la conexión. Agregue una excepción para
> `localhost` / `127.0.0.1`. `npm run tls:check` detecta esta situación.
