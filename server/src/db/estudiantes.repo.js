'use strict';
/**
 * Acceso a datos SEGURO (Fase I-B): toda consulta usa pool.execute(sql, [params]).
 * Con execute, mysql2 envía la sentencia como prepared statement: la estructura SQL viaja
 * por separado y los valores nunca se interpretan como código SQL.
 */
const { getPool } = require('./pool');

/** Escapa los comodines de LIKE para que '%' o '_' se busquen literalmente. */
const escaparLike = (s) => s.replace(/[\\%_]/g, (c) => `\\${c}`);

async function buscarEstudiantes(texto) {
  const patron = `%${escaparLike(texto)}%`;
  const [rows] = await getPool().execute(
    `SELECT carne, nombres, apellidos, carrera
       FROM estudiantes
      WHERE nombres LIKE ? OR apellidos LIKE ? OR carne LIKE ?
      ORDER BY apellidos, nombres
      LIMIT 50`,
    [patron, patron, patron],
  );
  return rows;
}

async function obtenerExpediente(carne) {
  const pool = getPool();
  const [[est]] = await pool.execute(
    'SELECT id, carne, nombres, apellidos, email, carrera, dpi_cifrado FROM estudiantes WHERE carne = ?',
    [carne],
  );
  if (!est) return null;
  const [notas] = await pool.execute(
    'SELECT id, curso, semestre, nota FROM notas WHERE estudiante_id = ? ORDER BY semestre, curso',
    [est.id],
  );
  return { ...est, notas };
}

module.exports = { buscarEstudiantes, obtenerExpediente, escaparLike };
