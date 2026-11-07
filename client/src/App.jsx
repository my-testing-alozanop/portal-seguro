import { useEffect, useState } from 'react';
import { api } from './api.js';

// Las secciones (login, expediente, comentarios, búsqueda, reportes) se agregan en la Fase I.
const SECCIONES = ['Inicio'];

export default function App() {
  const [seccion, setSeccion] = useState('Inicio');
  const [estado, setEstado] = useState('comprobando…');

  useEffect(() => {
    api('/api/health')
      .then((r) => setEstado(r.ok ? 'API disponible' : `API respondió ${r.status}`))
      .catch(() => setEstado('API no disponible'));
  }, []);

  return (
    <div className="app">
      <header>
        <h1>Portal Universitario</h1>
        <span className="badge">LABORATORIO · datos ficticios</span>
      </header>
      <nav>
        {SECCIONES.map((s) => (
          <button key={s} className={s === seccion ? 'activo' : ''} onClick={() => setSeccion(s)}>
            {s}
          </button>
        ))}
      </nav>
      <main>
        <p>Estado de la API: {estado}</p>
      </main>
    </div>
  );
}
