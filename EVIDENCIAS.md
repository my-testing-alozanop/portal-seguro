# EVIDENCIAS — Portal universitario de laboratorio

Guía para **reproducir cada prueba y saber qué captura tomar**. Todo se ejecuta en localhost con
datos ficticios. Las capturas se guardan en `evidencias/capturas/` con el código indicado
(p. ej. `I-B-03.png`) para referenciarlas en el informe.

> **Desde la Fase II la API corre en HTTPS.** Si ya generó certificados (`npm run cert`), en los
> comandos de esta guía reemplace `http://127.0.0.1:3000` por `https://localhost:3443` y agregue
> `--cacert ..\server\certs\ca.pem --ssl-no-revoke` a cada `curl`. Las evidencias de la Fase II
> están en `EVIDENCIAS-FASE2.md`.

> Para cada vulnerabilidad el PDF pide: **código vulnerable → evidencia del ataque → código
> corregido → evidencia de que ya no funciona**. Por eso casi todas las secciones tienen el par
> "VULNERABLE (/vuln)" y "SEGURO (/api)".

---

## 0. Preparación (una sola vez por sesión de evidencias)

### 0.1 Activar el modo laboratorio
1. Abra `server\.env` y cambie `LAB_VULN=0` por `LAB_VULN=1`. Guarde.
2. En la ventana donde corre la API pulse `Ctrl + C` y vuelva a ejecutar:
   ```cmd
   cd C:\Users\Abdiel\Desktop\portal-seguro\server
   npm run dev
   ```
   Debe decir `(LAB_VULN=1)`.
3. El cliente sigue con `npm run dev` en `client` (http://127.0.0.1:5173).

> 📸 **0-01** — Consola de la API mostrando `API en http://127.0.0.1:3000 (LAB_VULN=1)`.

### 0.2 Iniciar sesión con curl (guarda la cookie en un archivo)
Abra **otra** ventana de cmd (será la "consola de evidencias"):
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\evidencias
curl -s -c cookies.txt -H "Content-Type: application/json" -d "{\"email\":\"admin@universidad.example\",\"password\":\"SU_SEED_ADMIN_PASSWORD\"}" http://127.0.0.1:3000/api/auth/login
```
Reemplace `SU_SEED_ADMIN_PASSWORD` por el valor que puso en `server\.env`.
Respuesta esperada: `{"ok":true,"rol":"admin"}`. Todos los comandos siguientes usan `-b cookies.txt`.

> `cookies.txt` contiene su token de sesión: está en `.gitignore` y **no** debe aparecer en capturas.

### 0.3 Registro de consultas en MySQL (para la evidencia de SQLi)
En **MySQL Workbench**, conectado como `root`, ejecute:
```sql
SET GLOBAL log_output = 'TABLE';
SET GLOBAL general_log = 'ON';
```
(Al terminar las evidencias: `SET GLOBAL general_log = 'OFF';`)

---

## Fase I-A · Validación de entradas

**Qué pide el PDF:** validar correos, identificadores (carné), nombres, calificaciones y búsquedas,
y explicar por qué validar no significa que un dato sea seguro para SQL, HTML o comandos.

### Código a mostrar
| Captura | Archivo | Qué mostrar |
|---|---|---|
| 📸 **I-A-01** | `server/src/middleware/validators.js` | Objeto `reglas` (expresiones regulares y rangos) y la función `nfkc` |
| 📸 **I-A-02** | `server/src/routes/estudiantes.js` | La ruta `POST /` con la cadena de reglas `reglas.carne(), reglas.nombre(...)...` |

### Pruebas
**1. Alta de estudiante con todos los campos inválidos** (carné, nombre con `<script>`, correo y DPI):
```cmd
curl -s -b cookies.txt -H "Content-Type: application/json" -d @payloads\estudiante-invalido.json http://127.0.0.1:3000/api/estudiantes
```
Esperado: `{"error":"ERR_VALIDACION","campos":["carne","nombres","email","dpi"]}` — nótese que
**no se refleja** el `<script>` en la respuesta.
> 📸 **I-A-03** — comando + respuesta.

**2. Nota fuera de rango (0-100):**
```cmd
curl -s -b cookies.txt -X PUT -H "Content-Type: application/json" -d @payloads\nota-invalida.json http://127.0.0.1:3000/api/notas/1
curl -s -b cookies.txt -X PUT -H "Content-Type: application/json" -d @payloads\nota-valida.json http://127.0.0.1:3000/api/notas/1
```
Esperado: primero `ERR_VALIDACION` con `["nota"]`; después `{"ok":true}`.
> 📸 **I-A-04**

**3. Registro con correo inválido y contraseña corta:**
```cmd
curl -s -H "Content-Type: application/json" -d @payloads\registro-invalido.json http://127.0.0.1:3000/api/auth/registro
```
> 📸 **I-A-05**

**4. Normalización NFKC** — el carné va escrito con dígitos de ancho completo `２０２６－０９９９`
y el apellido contiene una comilla (`O'Connor`):
```cmd
curl -s -b cookies.txt -H "Content-Type: application/json" -d @payloads\estudiante-nfkc.json http://127.0.0.1:3000/api/estudiantes
```
Esperado: `{"ok":true,"carne":"2026-0999"}` → NFKC lo convirtió a ASCII **antes** de validar.
Verifíquelo en Workbench: `SELECT carne, apellidos FROM portal_lab.estudiantes WHERE carne = '2026-0999';`
> 📸 **I-A-06** — respuesta de curl + resultado en Workbench.

**5. "Validar no es lo mismo que seguro":** búsqueda con una carga SQL que **solo usa caracteres
permitidos** (letras, espacios y comilla):
```cmd
curl -s -b cookies.txt -G http://127.0.0.1:3000/api/estudiantes/buscar --data-urlencode "q=x' OR 'a' LIKE 'a"
```
Esperado: `{"resultados":[]}` (200, **no 400**): la validación la dejó pasar; lo que la neutraliza
es la consulta parametrizada (ver I-B).
> 📸 **I-A-07**

**6. Pruebas automatizadas:**
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\server
npx jest tests/fase1a-validacion.test.js --verbose
```
> 📸 **I-A-08** — lista de pruebas en verde.

### Texto para el informe
> Validar comprueba que un dato tiene la **forma** esperada, pero no lo vuelve inocuo en todos
> los contextos. `O'Connor` es un apellido válido y contiene `'`, que en SQL cierra una cadena;
> `<b>hola</b>` puede ser un comentario válido y en HTML es marcado; `x" & whoami` es un nombre
> de archivo "aceptable" para algunos filtros y en la shell es un segundo comando. Por eso, además
> de validar, cada contexto aplica su propio control: **SQL parametrizado**, **codificación de
> salida HTML** y **argumentos sin shell**. NFKC se aplica antes de validar para que caracteres
> visualmente equivalentes (ancho completo, ligaduras) no evadan las listas blancas.

---

## Fase I-B · SQL Injection

**Qué pide el PDF:** consulta vulnerable controlada, evidencia del ataque, código corregido con
consultas parametrizadas y evidencia de que la entrada **ya no altera la estructura SQL**.
→ Corresponde a la **Prueba obligatoria 1** (sección 4 del PDF).

### Código a mostrar
| Captura | Archivo | Qué mostrar |
|---|---|---|
| 📸 **I-B-01** | `server/src/routes/vuln.js` | Ruta `/buscar`: la concatenación `"... LIKE '%" + q + "%'"` |
| 📸 **I-B-02** | `server/src/db/estudiantes.repo.js` | `buscarEstudiantes`: `pool.execute(... LIKE ? ..., [patron, ...])` y `escaparLike` |

### VULNERABLE — ataque
**1. Tautología (devuelve todos los estudiantes):**
```cmd
curl -s -b cookies.txt -G http://127.0.0.1:3000/vuln/buscar --data-urlencode "q=x' OR 'a' LIKE 'a"
```
Observe el campo `sql`: la condición quedó `LIKE '%x' OR 'a' LIKE 'a%'` → **la estructura cambió**.
> 📸 **I-B-03**

**2. UNION (extrae correos y hashes de contraseñas de otra tabla):**
```cmd
curl -s -b cookies.txt -G http://127.0.0.1:3000/vuln/buscar --data-urlencode "q=' UNION SELECT email, password_hash, rol, id FROM usuarios -- -"
```
> 📸 **I-B-04** — se ven filas con `$argon2id$...` (impacto: fuga de credenciales).

**3. Error SQL filtrado al usuario:**
```cmd
curl -s -b cookies.txt -G http://127.0.0.1:3000/vuln/buscar --data-urlencode "q=O'Connor"
```
> 📸 **I-B-05** — mensaje `You have an error in your SQL syntax...` (además, un apellido legítimo rompe la app).

También desde la interfaz: **Laboratorio → SQLi + XSS reflejado**, botones de ejemplo.
> 📸 **I-B-06** — tabla con todos los estudiantes / hashes en el navegador.

### SEGURO — misma entrada, sin efecto
```cmd
curl -s -b cookies.txt -G http://127.0.0.1:3000/api/estudiantes/buscar --data-urlencode "q=x' OR 'a' LIKE 'a"
curl -s -b cookies.txt -G http://127.0.0.1:3000/api/estudiantes/buscar --data-urlencode "q=O'Connor"
curl -s -b cookies.txt -G http://127.0.0.1:3000/api/estudiantes/buscar --data-urlencode "q=' UNION SELECT email, password_hash, rol, id FROM usuarios -- -"
```
Esperado: `[]` · exactamente 1 resultado (Diego O'Connor) · `ERR_VALIDACION`.
> 📸 **I-B-07** — los tres comandos con sus respuestas.

### Evidencia de que la estructura SQL no cambia (registro de MySQL)
En Workbench (con el general_log activado en 0.3):
```sql
SELECT event_time, command_type, LEFT(CAST(argument AS CHAR), 250) AS sentencia
FROM mysql.general_log
WHERE argument LIKE '%FROM estudiantes%'
ORDER BY event_time DESC
LIMIT 8;
```
Lo que debe verse:
- Vulnerable → `command_type = Query` con la carga **dentro** del texto SQL.
- Seguro → `command_type = Prepare` con `LIKE ?` (estructura fija) y luego `Execute` donde la carga
  aparece como **un literal entre comillas escapado** (`'%x\' OR \'a\' LIKE \'a%'`).
> 📸 **I-B-08** — **captura clave** de esta sección.

### Pruebas automatizadas
```cmd
npx jest tests/fase1b-sqli.test.js --verbose
```
> 📸 **I-B-09**

### Texto para el informe
> **Causa raíz:** construir SQL concatenando cadenas mezcla código y datos en el mismo canal.
> **Corrección:** `pool.execute()` envía la sentencia como *prepared statement*: el servidor
> compila primero la estructura con marcadores `?` y después recibe los valores, que nunca se
> reinterpretan como SQL. Se agregaron: escape de comodines `%`/`_` de LIKE, validación de la
> búsqueda, `multipleStatements: false` en el pool (impide sentencias apiladas), mensajes de
> error genéricos y un usuario de BD con permisos solo sobre `portal_lab`.

---

## Fase I-C · Cross-Site Scripting (XSS)

**Qué pide el PDF:** identificar dónde los comentarios o datos pueden interpretarse como
HTML/JS, implementar salida segura y explicar XSS **reflejado, almacenado y basado en DOM**.
→ Corresponde a la **Prueba obligatoria 2**.

### Código a mostrar
| Captura | Archivo | Qué mostrar |
|---|---|---|
| 📸 **I-C-01** | `client/src/components/vuln/VulnComentarios.jsx` | `dangerouslySetInnerHTML={{ __html: c.contenido }}` |
| 📸 **I-C-02** | `client/src/components/Comentarios.jsx` | `<span>{c.contenido}</span>` y `DOMPurify.sanitize(...)` |
| 📸 **I-C-03** | `server/src/routes/vuln.js` | `/buscar-html` con `res.send(\`...${q}...\`)` |
| 📸 **I-C-04** | `client/src/components/vuln/VulnBienvenida.jsx` vs `Bienvenida.jsx` | `innerHTML` vs `textContent` |
| 📸 **I-C-05** | `server/src/app.js` y `server/src/middleware/auth.js` | Configuración de helmet (CSP) y `cookieOptions` |

### 1. XSS almacenado
1. Navegador → http://127.0.0.1:5173 → inicie sesión → **Laboratorio → XSS almacenado** →
   **Publicar** (el campo ya trae `<img src=x onerror=...>`).
2. Aparece un `alert("XSS almacenado: 127.0.0.1")`.
   > 📸 **I-C-06** — la ventana de alerta sobre el portal.
3. Vaya a **Comentarios** (versión segura): el mismo comentario se ve como **texto literal**
   `<img src=x onerror=...>` y no se ejecuta nada.
   > 📸 **I-C-07**
4. Active "Permitir formato básico (DOMPurify)": sigue sin ejecutarse (el `<img onerror>` se elimina).
   > 📸 **I-C-08**
5. DevTools (`F12`) → **Elements**: en la versión segura el contenido aparece como `&lt;img ...`.
   > 📸 **I-C-09**
6. Evidencia de que el dato almacenado es el mismo (la corrección está en la **salida**):
   ```sql
   SELECT id, contenido FROM portal_lab.comentarios ORDER BY id DESC LIMIT 3;
   ```
   > 📸 **I-C-10**

Por API (el comentario se devuelve como dato JSON, no como HTML):
```cmd
curl -s -b cookies.txt -H "Content-Type: application/json" -d @payloads\comentario-xss.json http://127.0.0.1:3000/api/comentarios
curl -s -i http://127.0.0.1:3000/api/comentarios
```
> 📸 **I-C-11** — cabeceras `Content-Type: application/json` y `Content-Security-Policy: ... script-src 'self' ...`.

### 2. XSS reflejado
1. **Laboratorio → SQLi + XSS reflejado** → enlace "abrir /vuln/buscar-html con &lt;script&gt;".
   Se ejecuta el `alert` → > 📸 **I-C-12**
2. Comparación con curl:
   ```cmd
   curl -s -i -b cookies.txt -G http://127.0.0.1:3000/vuln/buscar-html --data-urlencode "q=<script>alert(1)</script>"
   curl -s -i -b cookies.txt -G http://127.0.0.1:3000/api/estudiantes/buscar --data-urlencode "q=<script>alert(1)</script>"
   ```
   Vulnerable: `Content-Type: text/html` y el `<script>` **tal cual** en el cuerpo, sin CSP.
   Seguro: `Content-Type: application/json`, `ERR_VALIDACION`, sin reflejar la entrada, con CSP.
   > 📸 **I-C-13**

### 3. XSS basado en DOM
1. **Laboratorio → XSS basado en DOM** → "Inyectar payload en #hash" → se ejecuta el `alert`.
   Muestre la URL con `#<img src=x onerror=...>` en la barra de direcciones. > 📸 **I-C-14**
2. Sin cambiar la URL, vaya a **Inicio**: la bienvenida muestra el mismo texto **literal**
   (usa `textContent`). > 📸 **I-C-15**
3. En la consola de la API **no aparece ninguna petición** con el payload: el fragmento `#` nunca
   viaja al servidor. > 📸 **I-C-16** (opcional, DevTools → Network)

### 4. Defensa en profundidad: CSP y cookie
1. Cookie: DevTools → **Application → Cookies → http://127.0.0.1:5173** → cookie `sid` con
   `HttpOnly ✓`, `Secure ✓`, `SameSite Strict`. > 📸 **I-C-17**
2. En **Console** escriba `document.cookie` → devuelve `""`: un script inyectado no puede robar la sesión.
   > 📸 **I-C-18**
3. CSP bloqueando el XSS aun en el componente vulnerable (build de producción):
   ```cmd
   cd C:\Users\Abdiel\Desktop\portal-seguro\client
   npm run build
   npm run preview
   ```
   Abra http://127.0.0.1:4173, inicie sesión → Laboratorio → XSS almacenado. **No** aparece el
   alert y la consola de DevTools muestra `Refused to execute inline event handler because it
   violates the following Content Security Policy directive...`. > 📸 **I-C-19**

### Pruebas automatizadas
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\server
npx jest tests/fase1c-xss.test.js --verbose
```
> 📸 **I-C-20**

### Texto para el informe
| Tipo | Dónde vive la carga | Quién la inserta en la página | Ejemplo en el portal | Corrección |
|---|---|---|---|---|
| **Reflejado** | En la petición (URL/parámetro); no se guarda | El **servidor** la refleja en la respuesta HTML | `/vuln/buscar-html?q=<script>` | Responder JSON / codificar salida + CSP |
| **Almacenado** | En la **base de datos** | El servidor la entrega y la página la inserta a **cada visitante** | Comentarios con `dangerouslySetInnerHTML` | Insertar como texto (React `{}`) o sanear con DOMPurify + CSP |
| **Basado en DOM** | En el navegador (`location.hash`), **nunca llega al servidor** | El **JavaScript del cliente** (`innerHTML`) | Bienvenida con `#<img onerror>` | `textContent` en lugar de `innerHTML` |

> El dato se guarda tal cual; la defensa es **codificar según el contexto de salida**. La CSP sin
> `'unsafe-inline'` y la cookie `HttpOnly` limitan el impacto si algún punto fallara.

---

## Fase I-D · Inyección de comandos

**Qué pide el PDF:** identificar una funcionalidad que ejecute comandos del SO (generación o
compresión de reportes) y proponer una implementación que **no concatene cadenas**, use
**argumentos controlados** y aplique **privilegios mínimos**.

### Código a mostrar
| Captura | Archivo | Qué mostrar |
|---|---|---|
| 📸 **I-D-01** | `server/src/routes/vuln.js` | `/reporte`: `` exec(`tar -a -c -f "${nombre}.zip" ...`) `` y `/reporte/descargar` con `path.join` |
| 📸 **I-D-02** | `server/src/lib/reportes.js` | `TIPOS` (lista blanca), `randomUUID`, `rutaSegura`, uso de `archiver` |
| 📸 **I-D-03** | `server/src/routes/reportes.js` | `requireRol('admin')` y `body('tipo').isIn(...)` |

### VULNERABLE — ataque
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\evidencias
curl -s -b cookies.txt -H "Content-Type: application/json" -d @payloads\reporte-inyeccion.json http://127.0.0.1:3000/vuln/reporte
```
Esperado: el campo `comando` muestra `tar -a -c -f "x" & whoami & echo ".zip" ...` y `stdout`
contiene **su usuario de Windows** (resultado de `whoami`): la shell ejecutó un comando inyectado.
> 📸 **I-D-04** — **captura clave**.

Desde la interfaz: **Laboratorio → Inyección de comandos** (inicie sesión como admin). > 📸 **I-D-05**

**Path traversal en la descarga:**
```cmd
curl -s -b cookies.txt "http://127.0.0.1:3000/vuln/reporte/descargar?archivo=../package.json"
```
Devuelve el `package.json` del servidor, que está **fuera** de `reports/`. > 📸 **I-D-06**

### SEGURO — mismas cargas
```cmd
curl -s -b cookies.txt -H "Content-Type: application/json" -d @payloads\reporte-tipo-malicioso.json http://127.0.0.1:3000/api/reportes
curl -s -b cookies.txt -H "Content-Type: application/json" -d @payloads\reporte-seguro-con-nombre.json http://127.0.0.1:3000/api/reportes
```
Esperado: el primero `ERR_VALIDACION` (tipo fuera de la lista blanca); el segundo genera el reporte
e **ignora** el campo `nombre`: el archivo se llama `<uuid>.zip`.
> 📸 **I-D-07**

Descargar el ZIP (copie el valor de `descarga` de la respuesta anterior):
```cmd
curl -s -b cookies.txt -o reporte.zip http://127.0.0.1:3000/api/reportes/PEGUE-AQUI-EL-UUID.zip
tar -tf reporte.zip
```
Esperado: `reporte-notas.csv`. Ábralo en Excel. > 📸 **I-D-08**

Path traversal bloqueado:
```cmd
curl -s -b cookies.txt "http://127.0.0.1:3000/api/reportes/..%2Fpackage.json"
```
Esperado: `ERR_VALIDACION`. > 📸 **I-D-09**

Privilegio mínimo — un estudiante no puede generar reportes:
```cmd
curl -s -c est.txt -H "Content-Type: application/json" -d "{\"email\":\"ana.perez@universidad.example\",\"password\":\"SU_SEED_USER_PASSWORD\"}" http://127.0.0.1:3000/api/auth/login
curl -s -b est.txt -H "Content-Type: application/json" -d @payloads\reporte-seguro.json http://127.0.0.1:3000/api/reportes
```
Esperado: `{"error":"ERR_PROHIBIDO"}`. > 📸 **I-D-10**

### Pruebas automatizadas
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\server
npx jest tests/fase1d-comandos.test.js --verbose
```
Incluye una prueba que **espía** `child_process` y verifica que el reporte seguro no invoca
`exec`, `execFile`, `spawn` ni `execSync`. > 📸 **I-D-11**

### Texto para el informe
> **Causa raíz:** `exec()` entrega una **cadena** a `cmd.exe`/`sh`, que interpreta metacaracteres
> (`&`, `|`, `;`, `$( )`); poner comillas no protege porque el atacante las cierra.
> **Corrección:** (1) eliminar la shell: la compresión la hace `archiver` dentro de Node; si se
> necesitara una herramienta externa se usaría `execFile('tar', [argumentos fijos], {shell:false})`;
> (2) argumentos controlados: el usuario solo elige un `tipo` de una lista blanca y el nombre lo
> genera el servidor (UUID); (3) control de rutas: `path.resolve` + comprobación de que el destino
> queda dentro de `reports/`; (4) privilegios mínimos: solo el rol admin, archivos con permisos
> 0600/0700, y el proceso Node debe correr con una cuenta sin privilegios de administrador; el
> usuario de BD `portal_app` solo tiene permisos sobre `portal_lab`. Adicionalmente, el CSV
> neutraliza la inyección de fórmulas (`=`, `+`, `-`, `@`).

---

## Prueba global de la Fase I
```cmd
cd C:\Users\Abdiel\Desktop\portal-seguro\server
npm test
```
> 📸 **I-99** — resumen `Tests: 70 passed`.

## Limpieza al terminar
```sql
SET GLOBAL general_log = 'OFF';
DELETE FROM portal_lab.estudiantes WHERE carne = '2026-0999';
```
Y vuelva a poner `LAB_VULN=0` en `server\.env` (o ejecute `npm run db:reset` para dejar los datos como al inicio).
