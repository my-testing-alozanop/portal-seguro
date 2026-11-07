import { useState } from 'react';
import { api } from '../../api.js';

/** ⚠️ VULNERABLE (inyección de comandos): el "nombre" del archivo llega a exec() en el servidor. */
export default function VulnReportes({ usuario }) {
  const [nombre, setNombre] = useState('x" & whoami & echo "');
  const [res, setRes] = useState(null);

  if (usuario?.rol !== 'admin') return <p>Inicie sesión como admin para esta demostración.</p>;

  async function generar(e) {
    e.preventDefault();
    const r = await api('/vuln/reporte', { method: 'POST', body: { tipo: 'notas', nombre } });
    setRes(r.data);
  }

  return (
    <div>
      <h3>Inyección de comandos (vulnerable)</h3>
      <form className="fila" onSubmit={generar}>
        <input value={nombre} onChange={(e) => setNombre(e.target.value)} className="ancho" />
        <button>Generar en /vuln/reporte</button>
      </form>
      {res && (
        <>
          <p>Comando ejecutado por la shell:</p>
          <pre className="sql">{res.comando}</pre>
          <p>Salida (stdout):</p>
          <pre className="sql">{res.stdout || '(vacía)'}</pre>
          {res.stderr && <pre className="sql">{res.stderr}</pre>}
        </>
      )}
      <p>
        Path traversal:{' '}
        <a href="/vuln/reporte/descargar?archivo=../package.json" target="_blank" rel="noreferrer">
          /vuln/reporte/descargar?archivo=../package.json
        </a>
      </p>
    </div>
  );
}
