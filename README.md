# LexGuard PII-Scanner

[![CI/CD](https://github.com/HC-ONLINE/LexGuard/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/HC-ONLINE/LexGuard/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

LexGuard es un motor de detección y correlación de Información de Identificación Personal (PII) diseñado para determinar la exposición de datos sensibles y evaluar riesgos de fuga en repositorios y archivos planos.

Aunque su arquitectura facilita el cumplimiento de normativas estrictas como la **Ley 1581 de Colombia**, su enfoque principal es la seguridad operativa. Construido bajo una filosofía **CLI-first**, LexGuard permite realizar auditorías de datos automatizadas, explicables y listas para integrarse directamente en sus flujos de trabajo de CI/CD, asegurando la gobernanza de datos desde el código hasta producción.

## Qué problema resuelve

Las organizaciones enfrentan hoy desafíos críticos en la protección de datos: auditorías manuales lentas, herramientas genéricas con altas tasas de falsos positivos y una visión fragmentada del riesgo. **Los escáneres basados únicamente en regex fallan al evaluar impacto real; LexGuard evalúa exposición, no coincidencias.**

## Principios de diseño

Nuestra arquitectura se basa en decisiones técnicas pragmáticas para garantizar confianza y operatividad:

- **Rules first, IA como apoyo:** La base de la detección son reglas deterministas y validaciones algorítmicas (Luhn, prefijos, entropía). La Inteligencia Artificial se utiliza como una capa secundaria para reducir falsos positivos, no como una caja negra.
- **Riesgo explicable > Score mágico:** No entregamos un número arbitrario. Cada hallazgo incluye un desglose claro de por qué se considera riesgoso y su nivel de confianza.
- **Fail-safe por defecto:** Ante ambigüedad, LexGuard prefiere clasificar como UNCERTAIN antes que generar falsos positivos críticos.
- **CLI integrable:** Diseñado para ejecutarse en pipelines, scripts de automatización y entornos desatendidos sin dependencias gráficas pesadas.
- **Modularidad:** Arquitectura extensible que permite agregar nuevos validadores y tipos de PII sin afectar el núcleo del sistema.

## Arquitectura en una frase

El flujo del motor sigue un pipeline determinista: ingestión → detección → validación → scoring → correlación cross-PII → reporte.

## Qué detecta hoy

El motor actual incluye validaciones robustas y específicas para:

- **Riesgo Agregado + Cross-PII:** Detección de múltiples tipos de datos sensibles coexistiendo en el mismo contexto.
- **Cédula de Ciudadanía (Colombia):** Validación de formato y patrones contextuales.
- **Teléfono Móvil (Colombia):** Verificación de prefijos y longitudes estándar.
- **Correo Electrónico:** Detección de patrones y filtrado de falsos positivos comunes.
- **Tarjetas de Crédito:** Validación algorítmica (Luhn) para múltiples emisores.

## Qué NO hace

Para mantener la claridad en el alcance y transmitir madurez técnica:

- **No reemplaza un DLP:** LexGuard es una herramienta de auditoría y escaneo, no un sistema de prevención de pérdida de datos en tiempo real.
- **No cifra datos:** Su función es identificar la exposición, no remediarla mediante ofuscación o encriptación.
- **No es un SIEM:** Genera reportes de hallazgos, no monitorea eventos de seguridad de la infraestructura en tiempo real.
- **No exfiltra datos:** El escaneo y análisis se ejecutan localmente. La IA, cuando se habilita, es opcional y desacoplada del motor.

## Ejemplo mínimo de uso

Escanee un directorio completo buscando exposición de datos y obtenga un reporte en formato JSON:

```bash
lexguard scan --target ./data --format json --output reporte_auditoria.json
```

**Output resumido:**

```json
{
  "summary": {
    "total_files": 15,
    "risky_files": 2,
    "execution_time": "0.45s"
  },
  "findings": [
    {
      "file": "data/clientes_2024.csv",
      "risk_level": "CRITICAL",
      "risk_score": 0.85,
      "found": ["CREDIT_CARD", "CEDULA_CO", "EMAIL"],
      "cross_pii": true
    }
  ]
}
```

## Licencia

Este proyecto está bajo la Licencia Apache-2.0 (Apache License 2.0). Ver [LICENSE](LICENSE) para más detalles.

---

## Hecho con ❤️ por HC-ONLINE

⭐ **Si te resulta útil, deja una estrella en GitHub** ⭐
