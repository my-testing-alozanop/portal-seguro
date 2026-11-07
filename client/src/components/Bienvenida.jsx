import { useEffect, useRef } from 'react';

/**
 * Mensaje de bienvenida personalizable vía URL: http://127.0.0.1:5173/#Hola%20Ana
 * SEGURO (Fase I-C · XSS basado en DOM corregido): el fragmento se inserta con textContent,
 * por lo que "<img src=x onerror=...>" se muestra literalmente y nunca se interpreta como HTML.
 * (Contraparte vulnerable: components/vuln/VulnBienvenida.jsx con innerHTML.)
 */
export default function Bienvenida() {
  const ref = useRef(null);

  useEffect(() => {
    const pintar = () => {
      let texto;
      try { texto = decodeURIComponent(window.location.hash.slice(1)); } catch { texto = ''; }
      ref.current.textContent = texto || 'Bienvenido al portal';
    };
    pintar();
    window.addEventListener('hashchange', pintar);
    return () => window.removeEventListener('hashchange', pintar);
  }, []);

  return <p className="bienvenida" ref={ref} />;
}
