import { useState } from 'react';
import VulnBusqueda from './VulnBusqueda.jsx';
import VulnComentarios from './VulnComentarios.jsx';
import VulnBienvenida from './VulnBienvenida.jsx';
import VulnReportes from './VulnReportes.jsx';

/**
 * ⚠️ Panel de laboratorio: agrupa los componentes Vuln*. Solo se muestra cuando el servidor
 * expone /vuln (LAB_VULN=1). Cada uno tiene su contraparte segura en la sección normal.
 */
const DEMOS = {
  'SQLi + XSS reflejado': VulnBusqueda,
  'XSS almacenado': VulnComentarios,
  'XSS basado en DOM': VulnBienvenida,
  'Inyección de comandos': VulnReportes,
};

export default function Laboratorio({ usuario }) {
  const [demo, setDemo] = useState(Object.keys(DEMOS)[0]);
  const Demo = DEMOS[demo];
  return (
    <section className="lab">
      <p className="alerta">
        ⚠️ Versiones <strong>deliberadamente vulnerables</strong> para demostración. Solo localhost, datos ficticios.
      </p>
      <nav className="subnav">
        {Object.keys(DEMOS).map((d) => (
          <button key={d} className={d === demo ? 'activo' : ''} onClick={() => setDemo(d)}>{d}</button>
        ))}
      </nav>
      <Demo usuario={usuario} />
    </section>
  );
}
