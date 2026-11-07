# EVIDENCIAS — Fase II · Criptografía aplicada y almacenamiento seguro

**Una captura por inciso** (la que mejor demuestra el control), más una captura final con las
9 pruebas obligatorias. Guarde cada imagen en `evidencias/capturas/` con el código indicado.
Todos los comandos son para **cmd** y se ejecutan desde `C:\Users\Abdiel\Desktop\portal-seguro\evidencias`
salvo que se indique otra carpeta.

---

## 0. Preparación (una sola vez)

### 0.1 Reiniciar la API y el cliente
La API ahora usa HTTPS. En la ventana de la API: `Ctrl + C` y luego
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\server
npm run migrate
npm run dev
```
Debe mostrar:
```
[arranque] secretos cargados desde: entorno (.env / variables del sistema)
[arranque] API en https://localhost:3443  (TLS >= 1.2, LAB_VULN=1)
[arranque] http://127.0.0.1:3000 -> redirige a HTTPS
```
(`LAB_VULN=1` en `server\.env` para las demostraciones vulnerables.) Reinicie también el cliente
(`Ctrl + C` y `npm run dev` en `client`).

### 0.2 Comprobar que el antivirus no intercepta TLS ⚠️
En este equipo **Norton (Web/Mail Shield)** inspecciona HTTPS incluso en localhost: reemplaza el
certificado del servidor por uno propio y los clientes (curl, el navegador, el proxy de Vite)
rechazan la conexión. Compruébelo:
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\server
npm run tls:check
```
- Si dice `Emitido por: ... Norton Web/Mail Shield Untrusted Root` → abra Norton y, en la
  configuración de protección web / análisis de tráfico HTTPS (cifrado), agregue una
  **excepción para `localhost` y `127.0.0.1`** (o desactive temporalmente el análisis HTTPS
  mientras toma las evidencias). Repita `npm run tls:check`.
- Listo cuando diga `Emitido por: CN=Portal Lab CA (solo laboratorio)` y `Certificado válido: SÍ`.

> Si no puede cambiar Norton: renombre `server\certs` a `server\certs-off` y reinicie API y
> cliente para volver a HTTP (sirve para A, C y E con `http://127.0.0.1:3000`), y use como
> evidencia de TLS la prueba automatizada del final (corre sobre un *named pipe* que el antivirus
> no intercepta).

### 0.3 Variables de atajo para curl (en la consola de evidencias)
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\evidencias
set API=https://localhost:3443
set TLS=--cacert ..\server\certs\ca.pem --ssl-no-revoke
```
`--cacert` hace que curl confíe **solo** en la CA del laboratorio (no se usa `-k`, que
desactivaría la verificación). `--ssl-no-revoke` evita que Windows busque una lista de
revocación que una CA de laboratorio no publica.

---

## II-A · Almacenamiento seguro de contraseñas

**Qué pide el PDF:** reemplazar el mecanismo inseguro por una KDF, demostrar generación y
almacenamiento del hash, uso de sal, verificación en el login y explicar por qué SHA-256 simple
no es adecuado.

### Pasos
1. Registre **dos** usuarios en la versión **vulnerable** (SHA-256) y **dos** en la **segura**
   (Argon2id), **todos con la misma contraseña**:
   ```cmd
   curl -s %TLS% -H "Content-Type: application/json" -d "{\"email\":\"lab-sha1@universidad.example\",\"password\":\"ClaveRepetida-2026\"}" %API%/vuln/registro
   curl -s %TLS% -H "Content-Type: application/json" -d "{\"email\":\"lab-sha2@universidad.example\",\"password\":\"ClaveRepetida-2026\"}" %API%/vuln/registro
   curl -s %TLS% -H "Content-Type: application/json" -d "{\"email\":\"lab-argon1@universidad.example\",\"password\":\"ClaveRepetida-2026\"}" %API%/api/auth/registro
   curl -s %TLS% -H "Content-Type: application/json" -d "{\"email\":\"lab-argon2@universidad.example\",\"password\":\"ClaveRepetida-2026\"}" %API%/api/auth/registro
   ```
2. En **MySQL Workbench**:
   ```sql
   SELECT email, password_algo, password_hash
   FROM portal_lab.usuarios
   WHERE email LIKE 'lab-%'
   ORDER BY password_algo DESC, email;
   ```

### 📸 II-A-01 — resultado de la consulta en Workbench
Lo que debe verse:
- `sha256`: los dos hashes son **idénticos** (64 caracteres hexadecimales, sin sal).
- `argon2id`: los dos hashes son **distintos** aunque la contraseña es la misma, y cada uno
  muestra el algoritmo y sus parámetros: `$argon2id$v=19$m=19456,t=2,p=1$<SAL>$<HASH>`.

**Pie de figura:** *"Misma contraseña para cuatro cuentas. Con SHA-256 los hashes son iguales
(sin sal); con Argon2id cada hash incluye una sal aleatoria de 16 bytes y los parámetros de costo,
por lo que son distintos."*

### Texto para el informe
> **¿Por qué SHA-256 simple no es adecuado?** SHA-256 es una función hash criptográfica diseñada
> para ser **rápida**: una GPU calcula miles de millones por segundo, así que probar diccionarios
> completos contra un hash filtrado es trivial. Además, sin sal, la misma contraseña produce el
> mismo hash en todas las cuentas y en todos los sistemas: se detectan contraseñas repetidas a
> simple vista (captura II-A-01) y sirven las tablas precalculadas (arcoíris).
> **Corrección:** Argon2id (ganador de la Password Hashing Competition y recomendado por OWASP)
> es una KDF **lenta y con alto consumo de memoria** (19 MiB por intento), lo que encarece la
> fuerza bruta en GPU/ASIC; genera una **sal aleatoria por usuario** que se guarda dentro del
> propio hash. En el login, `argon2.verify()` vuelve a derivar con la sal y los parámetros
> almacenados y compara en tiempo constante. Complementos: mensaje genérico
> (`ERR_CREDENCIALES`) que no revela si el correo existe, hash señuelo para igualar tiempos, y
> límite de 5 intentos fallidos por IP cada 15 minutos (express-rate-limit → 429).

---

## II-B · Protección criptográfica (reposo, tránsito y claves)

**Qué pide el PDF:** cifrado de datos en reposo, TLS en tránsito, manejo de claves y
justificación de algoritmos (sin algoritmos propios).

### Pasos — una sola captura con dos ventanas lado a lado
1. **Izquierda — cmd:**
   ```cmd
   cd C:\Users\Abdiel\Desktop\portal-seguro\server
   npm run tls:check
   ```
2. **Derecha — Workbench:**
   ```sql
   SELECT carne, dpi_cifrado, dpi_plano
   FROM portal_lab.estudiantes
   WHERE carne LIKE '2026-%'
   ORDER BY carne;
   ```

### 📸 II-B-01 — `tls:check` + DPI cifrado en la base
Lo que debe verse:
- **cmd:** `Protocolo negociado: TLSv1.3`, `Suite de cifrado: TLS_AES_256_GCM_SHA384` (o
  similar AEAD), `Emitido por: CN=Portal Lab CA (solo laboratorio)`, `SAN: DNS:localhost, IP
  Address:127.0.0.1`, `Certificado válido: SÍ` y `Cliente TLS 1.1: RECHAZADO ✓`.
- **Workbench:** cada `dpi_cifrado` con formato `v1:<iv>:<tag>:<cifrado>` (ningún número de 13
  dígitos visible) y `dpi_plano` en `NULL`.

**Pie de figura:** *"En tránsito: TLS 1.3 con cifrado autenticado y certificado verificado contra
la CA de laboratorio; TLS 1.1 rechazado. En reposo: el DPI se almacena cifrado con AES-256-GCM y
versión de clave (v1)."*

### Texto para el informe
> **Dato protegido:** el DPI (identificador personal) se cifra antes de guardarse; en pantalla
> solo se muestran los últimos 4 dígitos (`*********0101`).
> **Algoritmo en reposo:** AES-256-GCM de `node:crypto` (OpenSSL): cifrado **autenticado**
> (confidencialidad + integridad: si alguien altera el valor en la BD, el descifrado falla), IV
> aleatorio de 12 bytes por registro y el carné como dato asociado (AAD), lo que impide copiar
> el DPI cifrado de un estudiante a otro. Se cifra (y no se aplica hash) porque el dato debe poder
> recuperarse.
> **Manejo de claves:** clave de 256 bits generada con `openssl rand -base64 32`, fuera del código
> (`server/.env` o Vault) y **versionada** (`v1:` en cada valor). Rotación: se agrega
> `DATA_KEY_V2`, se cambia `DATA_KEY_CURRENT=v2`, `npm run rotar-clave` re-cifra los datos y, sin
> registros `v1`, se **retira** `DATA_KEY_V1` (revocación).
> **En tránsito:** HTTPS con `minVersion: TLSv1.2` (TLS 1.0/1.1 obsoletos, RFC 8996), solo suites
> ECDHE (secreto perfecto hacia adelante) con AEAD, HSTS, y el puerto HTTP redirige con 308. El
> certificado (ECDSA P-256, SAN `localhost`/`127.0.0.1`) lo firma una CA de laboratorio creada con
> OpenSSL cuya clave privada se borra tras firmar. En producción se usaría una CA pública.

---

## II-C · Gestión de secretos

**Qué pide el PDF:** retirar credenciales del código, usar variables de entorno o bóveda,
documentar permisos y proponer rotación y revocación.

### Pasos
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\server
npm run secrets:check
cd ..
git ls-files | findstr /i "\.env"
git check-ignore -v server/.env
```

### 📸 II-C-01 — salida de los tres comandos
Lo que debe verse:
- Tabla `VARIABLE / ORIGEN / ESTADO` con cada secreto marcado `entorno` y `presente (valor oculto)`
  (ningún valor impreso), y `Conexión a MySQL OK como portal_app@...`.
- `git ls-files` lista solo `server/.env.example` (el `.env` real **no** está versionado).
- `git check-ignore` muestra la regla de `.gitignore` que excluye `server/.env`.

**Pie de figura:** *"La aplicación obtiene las credenciales de una fuente externa (variables de
entorno) y funciona; ningún valor se imprime y el archivo con los secretos no forma parte del
repositorio."*

### Texto para el informe
> **Antes:** credenciales escritas en el código (ver `../lab-fuga/config.js` del primer commit).
> **Después:** `server/src/config/secrets.js` es el único punto de acceso: lee del entorno
> (`server/.env`, no versionado) o, con `SECRETS_PROVIDER=vault`, de **HashiCorp Vault** (KV v2
> mediante `node-vault`, con token o AppRole). Si falta un secreto, la aplicación no arranca y el
> mensaje nombra la variable, nunca su valor.
> **Control de permisos:** `server/.env` solo legible por la cuenta que ejecuta el servicio
> (en Windows: `icacls server\.env /inheritance:r /grant:r "%USERNAME%:R"`); el usuario de BD
> `portal_app` tiene permisos solo sobre `portal_lab` (sin acceso a otras bases ni privilegios
> globales); en Vault, una política de solo lectura sobre `secret/data/portal-lab`.
> **Rotación:** periódica (p. ej. cada 90 días) y ante cualquier sospecha: generar el nuevo valor
> (`openssl rand -base64 32` / `ALTER USER 'portal_app'@'localhost' IDENTIFIED BY '...'`),
> actualizar la fuente (`.env` o `vault kv put`), reiniciar el servicio y verificar con
> `npm run secrets:check`. **Revocación:** invalidar el valor anterior de inmediato (cambiar la
> contraseña de BD, retirar la versión de clave, revocar el token de Vault con
> `vault token revoke`); al rotar `SESSION_SECRET` se cierran todas las sesiones.

---

## II-D · Detección de secretos en Git

**Qué pide el PDF:** simular la fuga de una credencial ficticia, detectarla con Gitleaks, explicar
por qué borrarla del último commit no basta y describir revocación, investigación y corrección.

### Requisito
Instale gitleaks (no requiere consola de administrador):
```cmd
winget install --id Gitleaks.Gitleaks -e
```
(Si `winget` no encuentra ese id, use `winget search gitleaks` y repita con el id que muestre.)
Cierre y abra la consola y compruebe: `gitleaks version`.

### Pasos
```cmd
cd C:\Users\Abdiel\Desktop\lab-fuga
"C:\Program Files\Git\bin\bash.exe" simular-fuga.sh
```

### 📸 II-D-01 — salida del script (pasos 3, 4 y 5)
Lo que debe verse:
- Paso 3: `No: config.js ya no contiene la clave.` (el código actual está "limpio").
- Paso 4: `git log -p` muestra la línea `+  aws_access_key_id: 'AKIA...'` en el primer commit:
  **sigue en el historial**.
- Paso 5: gitleaks reporta un **Finding** con `RuleID: aws-access-key-id-laboratorio`,
  `File: config.js` y el **Commit** del primer commit, y termina con
  `RESULTADO: gitleaks DETECTÓ la credencial (código de salida 1)`.

**Pie de figura:** *"La credencial ficticia se eliminó del código en un segundo commit, pero
gitleaks la encuentra en el historial de Git."*

### Texto para el informe
> **¿Por qué borrar el secreto del último commit no basta?** Git guarda instantáneas completas:
> el commit anterior sigue conteniendo el archivo con la clave, y cualquiera con acceso al
> repositorio (clones, forks, copias en CI, cachés del proveedor) puede recuperarla con
> `git log -p` o `git show <commit>:config.js`. Si ya se hizo *push*, debe asumirse comprometida.
> **Respuesta:** (1) **revocar/rotar** primero la credencial en el proveedor (AWS IAM →
> desactivar y eliminar la clave, emitir una nueva en el gestor de secretos); (2) **investigar**
> su uso desde la fecha del commit (CloudTrail, registros de acceso) y quién tuvo acceso al
> repositorio; (3) **corregir el repositorio** reescribiendo el historial (`git filter-repo
> --replace-text` o BFG), `push --force` y re-clonado por parte del equipo; (4) **prevenir**:
> hook *pre-commit* con gitleaks (configurado en este proyecto con Husky, política
> *fail-closed*), escaneo en CI y *push protection* del proveedor.
> **Activar el hook del proyecto:** con gitleaks ya instalado, ejecute `npm install` en la raíz de
> `portal-seguro`; desde entonces cada `git commit` se escanea y se bloquea si contiene secretos.

---

## II-E · Registro seguro (Secure Logging)

**Qué pide el PDF:** registros para inicios de sesión, fallos, consultas de expedientes,
modificaciones, errores y accesos administrativos, sin contraseñas, tokens, claves ni datos
personales innecesarios, e **incluir un registro inseguro y su versión corregida**.

### Pasos
```cmd
curl -s %TLS% -H "Content-Type: application/json" -d "{\"email\":\"lab-argon1@universidad.example\",\"password\":\"ClaveEquivocada-999\"}" %API%/api/auth/login
curl -s %TLS% -H "Content-Type: application/json" -d "{\"email\":\"lab-sha1@universidad.example\",\"password\":\"ClaveEquivocada-999\"}" %API%/vuln/login
cls
echo ===== REGISTRO INSEGURO (logs\inseguro.log) =====
findstr "ClaveEquivocada" ..\server\logs\inseguro.log
echo ===== REGISTRO SEGURO (logs\app.log) =====
findstr "login_fallido" ..\server\logs\app.log
findstr "ClaveEquivocada lab-argon1" ..\server\logs\app.log || echo (la contrasena y el correo NO aparecen en app.log)
```
(Use las cuentas `lab-*` creadas en II-A. El primer `curl` responde `ERR_CREDENCIALES`; el
segundo, `Contraseña incorrecta`.)

### 📸 II-E-01 — los dos registros, uno debajo del otro
Lo que debe verse:
- **Inseguro:** una línea JSON con `"password":"ClaveEquivocada-999"`, el correo
  `lab-sha1@...` en claro y todas las cabeceras HTTP.
- **Seguro:** una línea JSON
  `{"level":"warn","time":"...","evento":"login_fallido","req_id":"...","ip":"...","usuario":"u_3f9a...","motivo":"password_incorrecta"}`
  sin contraseña ni correo (el usuario aparece como seudónimo HMAC), y el mensaje
  `(la contrasena y el correo NO aparecen en app.log)`.

**Pie de figura:** *"Mismo evento registrado de forma insegura (contraseña y correo en claro) y
corregida (JSON con evento, id de correlación y seudónimo HMAC del correo; sin secretos)."*

### Texto para el informe
> **Diseño:** pino escribe una línea JSON por evento con nivel, hora ISO, `evento` y `req_id`
> (id de correlación que también recibe el cliente en `X-Request-Id`). Eventos: `login_exitoso`,
> `login_fallido` (con el motivo real solo en el log), `consulta_expediente` (permitida o
> denegada), `modificacion_nota` (quién, qué nota, valor anterior y nuevo), `error_interno` y
> `acceso_admin`. `redact` reemplaza por `[REDACTADO]` password, token, cookie, authorization y
> dpi aunque se pasen por error; el correo se **seudonimiza** con HMAC-SHA256 y una clave
> propia (`LOG_HMAC_KEY`), lo que permite correlacionar eventos de una misma cuenta sin guardar
> el correo y sin que se pueda revertir por diccionario. No se registra la *query string* ni el
> cuerpo de las peticiones.
> **Errores:** el cliente recibe solo `{"error":"ERR_INTERNO","id":"<uuid>"}`; el detalle mínimo
> (tipo y código del error) queda en el log con el mismo id. La versión vulnerable
> (`/vuln/expediente/x`) devuelve el mensaje, el *stack* con rutas internas y la configuración de
> conexión.
> **¿Por qué no registrar todas las peticiones HTTP?** Porque las URL, cabeceras y cuerpos
> contienen contraseñas, cookies de sesión, tokens y datos personales; el log se convierte en un
> segundo almacén de secretos con controles más débiles que la base de datos.

---

## Captura final (recomendada) · Las 9 pruebas obligatorias
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\server
npx jest tests/pruebas-obligatorias.test.js --verbose
```
### 📸 II-99 — las 9 filas de la tabla de la sección 4 del PDF en verde
(La prueba 5, gitleaks, se ejecuta cuando gitleaks está instalado.)

---

## Limpieza al terminar
```sql
DELETE FROM portal_lab.usuarios WHERE email LIKE 'lab-%';
```
Y vuelva a poner `LAB_VULN=0` en `server\.env`.
