import { useState } from 'react';
import { api } from '../api.js';

/** Búsqueda SEGURA: /api/estudiantes/buscar (validación + consulta parametrizada, JSON). */
export default function Busqueda() {
  const [q, setQ] = useState('');
  const [res, setRes] = useState(null);
  const [error, setError] = useState('');

  async function buscar(e) {
    e.preventDefault();
    const r = await api(`/api/estudiantes/buscar?q=${encodeURIComponent(q)}`);
    if (r.ok) { setRes(r.data.resultados); setError(''); }
    else { setRes(null); setError(r.data?.error ?? 'Error'); }
  }

  return (
    <section>
      <h2>Búsqueda de estudiantes</h2>
      <form className="fila" onSubmit={buscar}>
        <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={50} placeholder="Nombre, apellido o carné" />
        <button>Buscar</button>
      </form>
      {error && <p className="error">{error}</p>}
      {res && <TablaEstudiantes filas={res} />}
    </section>
  );
}

export function TablaEstudiantes({ filas }) {
  if (!filas.length) return <p>Sin resultados.</p>;
  const cols = Object.keys(filas[0]);
  return (
    <table>
      <thead><tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
      <tbody>
        {filas.map((f, i) => <tr key={i}>{cols.map((c) => <td key={c}>{String(f[c])}</td>)}</tr>)}
      </tbody>
    </table>
  );
}
