import { useState } from 'react';
import { api } from '../api.js';

/** Reportes SEGUROS: el usuario solo elige el tipo (lista blanca); el servidor nombra el archivo. */
export default function Reportes() {
  const [tipo, setTipo] = useState('notas');
  const [res, setRes] = useState(null);
  const [error, setError] = useState('');

  async function generar(e) {
    e.preventDefault();
    const r = await api('/api/reportes', { method: 'POST', body: { tipo } });
    if (r.ok) { setRes(r.data); setError(''); } else { setRes(null); setError(r.data?.error ?? 'Error'); }
  }

  return (
    <section>
      <h2>Reportes (CSV en ZIP)</h2>
      <form className="fila" onSubmit={generar}>
        <select value={tipo} onChange={(e) => setTipo(e.target.value)}>
          <option value="notas">Notas</option>
          <option value="estudiantes">Estudiantes</option>
        </select>
        <button>Generar</button>
      </form>
      {error && <p className="error">{error}</p>}
      {res && (
        <p>
          Reporte con {res.filas} filas: <a href={res.descarga}>descargar ZIP</a>
        </p>
      )}
    </section>
  );
}
