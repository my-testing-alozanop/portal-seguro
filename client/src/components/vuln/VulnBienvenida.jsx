import { useEffect, useRef } from 'react';

/**
 * ⚠️ VULNERABLE (XSS basado en DOM): toma location.hash (fuente controlada por el atacante)
 * y lo escribe con innerHTML (sumidero peligroso). El servidor nunca ve el fragmento #...,
 * por eso este XSS ocurre 100 % en el navegador y no aparece en los logs del servidor.
 */
const PAYLOAD = '#<img src=x onerror="alert(\'XSS DOM: \' + document.domain)">';

export default function VulnBienvenida() {
  const ref = useRef(null);

  useEffect(() => {
    const pintar = () => {
      let texto;
      try { texto = decodeURIComponent(window.location.hash.slice(1)); } catch { texto = ''; }
      ref.current.innerHTML = `Bienvenido, ${texto || 'visitante'}`;
    };
    pintar();
    window.addEventListener('hashchange', pintar);
    return () => window.removeEventListener('hashchange', pintar);
  }, []);

  return (
    <div>
      <h3>XSS basado en DOM (vulnerable)</h3>
      <p ref={ref} className="bienvenida" />
      <p>
        <button onClick={() => { window.location.hash = PAYLOAD.slice(1); }}>Inyectar payload en #hash</button>{' '}
        <button onClick={() => { window.location.hash = ''; }}>Limpiar</button>
      </p>
      <p><small>Compare con la sección Inicio, que pinta el mismo #hash con <code>textContent</code>.</small></p>
    </div>
  );
}
