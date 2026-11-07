# CLAUDE.md — Portal universitario de laboratorio (MASI · Seguridad en Aplicaciones)

Proyecto académico: portal universitario **deliberadamente vulnerable + versión corregida** para la
tarea integradora de las semanas 4 y 5 (`tarea.pdf.pdf`). Todo corre **solo en localhost**, con
**datos y credenciales ficticios**.

## Reglas no negociables
1. **Solo laboratorio.** Servidor escuchando en `127.0.0.1`. Ningún dato o credencial real.
2. **Ningún secreto en el código.** Todo secreto se lee de `server/.env` (no versionado) a través de
   `server/src/config/secrets.js`, que falla sin revelar valores. Solo se versiona `.env.example`
   con placeholders. Nunca escribir ni pedir credenciales reales del usuario.
3. **No implementar criptografía propia.** Usar `node:crypto` (AES-256-GCM, HMAC, randomBytes),
   `argon2` (Argon2id) y OpenSSL para certificados.
4. **Cada vulnerabilidad existe en dos versiones:**
   - Vulnerable → `server/src/routes/vuln.js`, montada en `/vuln/...` **solo si `LAB_VULN=1`**.
   - Segura → rutas normales `/api/...` (siempre activas).
   - En el cliente, los componentes vulnerables se marcan claramente como `Vuln*` y solo se
     muestran en el modo laboratorio.
5. **Cada corrección lleva una prueba automatizada** (Jest + Supertest) que la verifique.
6. La clave AWS de ejemplo de la documentación de AWS (`AKIA…EXAMPLE`) solo se usa en `../lab-fuga`, nunca en este repo.

## Stack
- `server/`: Node.js + Express + mysql2 (BD `portal_lab`, usuario `portal_app`), helmet,
  express-validator, express-rate-limit, argon2, pino, archiver.
- `client/`: React + Vite (+ DOMPurify).
- Pruebas: Jest + Supertest (`server/tests/`).
- Pre-commit: Husky + gitleaks.

## Forma de trabajo
1. Avanzar **fase por fase** según el plan aprobado.
2. Al terminar cada fase: ejecutar tests → corregir fallos → `git commit` descriptivo →
   explicar en español, **máximo 8 líneas**, qué se hizo y por qué es seguro.
3. Documentación en español: `README.md`, `EVIDENCIAS.md` (comandos exactos + captura a tomar
   por inciso), `MATRIZ.md` (vulnerabilidad / causa raíz / corrección / prueba).

## Convenciones
- Consultas SQL siempre con `pool.execute(sql, [params])` en rutas seguras.
- Validación: express-validator + normalización Unicode NFKC antes de validar.
- Errores al cliente: solo `{ "error": "<código>", "id": "<correlationId>" }`.
- Logs: JSON con pino, `redact` de password/token/cookie/authorization/dpi; correo seudonimizado
  con HMAC.
