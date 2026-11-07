import { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';

export default function Expediente({ usuario }) {
  const esAdmin = usuario.rol === 'admin';
  const [carne, setCarne] = useState(usuario.carne ?? '2026-0001');
  const [exp, setExp] = useState(null);
  const [error, setError] = useState('');

  const cargar = useCallback(async (c) => {
    setError('');
    const r = await api(`/api/estudiantes/${encodeURIComponent(c)}/expediente`);
    if (r.ok) setExp(r.data);
    else { setExp(null); setError(r.data?.error ?? 'Error'); }
  }, []);

  useEffect(() => {
    if (usuario.carne || esAdmin) cargar(usuario.carne ?? carne);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [usuario]);

  async function cambiarNota(id, valor) {
    const r = await api(`/api/notas/${id}`, { method: 'PUT', body: { nota: Number(valor) } });
    if (!r.ok) setError(`${r.data?.error}${r.data?.campos ? ` (${r.data.campos.join(', ')})` : ''}`);
    await cargar(exp.carne);
  }

  if (!usuario.carne && !esAdmin) {
    return <p>Su cuenta no está vinculada a un expediente académico.</p>;
  }

  return (
    <section>
      <h2>Expediente académico</h2>
      {esAdmin && (
        <form className="fila" onSubmit={(e) => { e.preventDefault(); cargar(carne); }}>
          <input value={carne} onChange={(e) => setCarne(e.target.value)} placeholder="####-####" maxLength={9} />
          <button>Consultar</button>
        </form>
      )}
      {error && <p className="error">{error}</p>}
      {exp && (
        <>
          <dl className="datos">
            <dt>Carné</dt><dd>{exp.carne}</dd>
            <dt>Nombre</dt><dd>{exp.nombres} {exp.apellidos}</dd>
            <dt>Correo</dt><dd>{exp.email}</dd>
            <dt>Carrera</dt><dd>{exp.carrera}</dd>
            <dt>DPI</dt><dd>{exp.dpi ?? '—'} <small>(enmascarado; cifrado en BD)</small></dd>
          </dl>
          <table>
            <thead><tr><th>Curso</th><th>Semestre</th><th>Nota</th></tr></thead>
            <tbody>
              {exp.notas.map((n) => (
                <tr key={n.id}>
                  <td>{n.curso}</td>
                  <td>{n.semestre}</td>
                  <td>
                    {esAdmin ? (
                      <input type="number" min={0} max={100} defaultValue={n.nota} className="nota"
                        onBlur={(e) => e.target.value !== String(n.nota) && cambiarNota(n.id, e.target.value)} />
                    ) : n.nota}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
