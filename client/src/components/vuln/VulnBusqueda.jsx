import { useState } from 'react';
import { api } from '../../api.js';
import { TablaEstudiantes } from '../Busqueda.jsx';

/** ⚠️ VULNERABLE: usa /vuln/buscar (SQL concatenado) y enlaza /vuln/buscar-html (XSS reflejado). */
const EJEMPLOS = [
  "x' OR 'a' LIKE 'a",
  "' UNION SELECT email, password_hash, rol, id FROM usuarios -- -",
  "O'Connor",
];

export default function VulnBusqueda() {
  const [q, setQ] = useState(EJEMPLOS[0]);
  const [res, setRes] = useState(null);

  async function buscar(e) {
    e.preventDefault();
    const r = await api(`/vuln/buscar?q=${encodeURIComponent(q)}`);
    setRes(r.data);
  }

  const xssReflejado = `/vuln/buscar-html?q=${encodeURIComponent('<script>alert("XSS reflejado: " + document.domain)</script>')}`;

  return (
    <div>
      <h3>SQL Injection (vulnerable)</h3>
      <form className="fila" onSubmit={buscar}>
        <input value={q} onChange={(e) => setQ(e.target.value)} className="ancho" />
        <button>Buscar en /vuln/buscar</button>
      </form>
      <p>Ejemplos: {EJEMPLOS.map((x) => <button key={x} className="chip" onClick={() => setQ(x)}>{x}</button>)}</p>
      {res?.sql && <pre className="sql">{res.sql}</pre>}
      {res?.error && <p className="error">Error SQL filtrado: {res.error}</p>}
      {res?.resultados && <TablaEstudiantes filas={res.resultados} />}

      <h3>XSS reflejado (vulnerable)</h3>
      <p>
        El servidor inserta <code>q</code> sin codificar en HTML:{' '}
        <a href={xssReflejado} target="_blank" rel="noreferrer">abrir /vuln/buscar-html con &lt;script&gt;</a>
      </p>
    </div>
  );
}
