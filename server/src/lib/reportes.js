'use strict';
/**
 * Fase I-D · Generación SEGURA de reportes CSV comprimidos en ZIP.
 *
 * - No se invoca ningún comando del sistema operativo: la compresión la hace la biblioteca
 *   archiver dentro del proceso Node. Sin shell no hay metacaracteres (&, |, ;, $( )) que inyectar.
 * - El usuario solo elige el TIPO de reporte de una lista blanca; el nombre del archivo lo genera
 *   el servidor (UUID aleatorio). Ningún dato del usuario llega a una ruta o a un comando.
 * - Toda ruta se resuelve y se comprueba que quede DENTRO de REPORTS_DIR (anti path traversal).
 * - CSV: celdas que empiezan con = + - @ se prefijan con ' para evitar inyección de fórmulas
 *   al abrir el archivo en Excel/LibreOffice.
 *
 * Alternativa equivalente si se necesitara una herramienta externa: execFile('tar', [args...],
 * { shell: false }) con argumentos fijos en un arreglo, nunca exec() con una cadena concatenada.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const archiver = require('archiver');
const { getPool } = require('../db/pool');

const REPORTS_DIR = path.resolve(__dirname, '..', '..', 'reports');

const TIPOS = Object.freeze({
  estudiantes: {
    sql: 'SELECT carne, nombres, apellidos, carrera FROM estudiantes ORDER BY carne',
    columnas: ['carne', 'nombres', 'apellidos', 'carrera'],
  },
  notas: {
    sql: `SELECT e.carne, n.curso, n.semestre, n.nota
            FROM notas n JOIN estudiantes e ON e.id = n.estudiante_id
           ORDER BY e.carne, n.curso`,
    columnas: ['carne', 'curso', 'semestre', 'nota'],
  },
});

const RE_ARCHIVO = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.zip$/;

function celdaCsv(valor) {
  let s = String(valor ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

function aCsv(columnas, filas) {
  const lineas = [columnas.map(celdaCsv).join(',')];
  for (const f of filas) lineas.push(columnas.map((c) => celdaCsv(f[c])).join(','));
  return `${lineas.join('\r\n')}\r\n`;
}

/** Devuelve la ruta absoluta solo si queda dentro de REPORTS_DIR; si no, null. */
function rutaSegura(nombre) {
  if (typeof nombre !== 'string' || !RE_ARCHIVO.test(nombre)) return null;
  const ruta = path.resolve(REPORTS_DIR, nombre);
  return ruta.startsWith(REPORTS_DIR + path.sep) ? ruta : null;
}

async function generarReporte(tipo) {
  const def = Object.hasOwn(TIPOS, tipo) ? TIPOS[tipo] : null;
  if (!def) throw Object.assign(new Error('tipo no permitido'), { status: 400, code: 'ERR_VALIDACION' });

  const [filas] = await getPool().execute(def.sql);
  const csv = aCsv(def.columnas, filas);

  fs.mkdirSync(REPORTS_DIR, { recursive: true, mode: 0o700 });
  const archivo = `${crypto.randomUUID()}.zip`;
  const destino = rutaSegura(archivo);

  await new Promise((resolve, reject) => {
    const salida = fs.createWriteStream(destino, { flags: 'wx', mode: 0o600 }); // wx: nunca sobrescribe
    const zip = archiver('zip', { zlib: { level: 9 } });
    salida.on('close', resolve);
    salida.on('error', reject);
    zip.on('error', reject);
    zip.pipe(salida);
    zip.append(csv, { name: `reporte-${tipo}.csv` }); // nombre interno fijo, no proviene del usuario
    zip.finalize();
  });

  return { archivo, filas: filas.length };
}

module.exports = { generarReporte, rutaSegura, aCsv, celdaCsv, TIPOS, REPORTS_DIR };
