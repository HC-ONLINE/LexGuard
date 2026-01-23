"""
Prompts para clasificación de sensibilidad contextual.

Diseño:
- Prompts cortos y directos
- Sin términos técnicos innecesarios
- Enfocados en contexto humano vs técnico
- Respuesta estructurada obligatoria
"""


def build_classification_prompt(snippet: str, pii_type: str) -> str:
    """
    Construir prompt para clasificación de sensibilidad.

    Args:
        snippet: Fragmento de texto (1-2 líneas máximo)
        pii_type: Tipo de PII sospechado (email, phone, cedula, etc.)

    Returns:
        Prompt estructurado
    """
    return f"""Analiza si este fragmento contiene información personal sensible.

FRAGMENTO:
{snippet}

TIPO DETECTADO: {pii_type}

CONTEXTO:
- ¿Es información de una persona real?
- ¿Está en un contexto de datos personales?
- ¿O es técnico/ejemplo/placeholder?

Responde ÚNICAMENTE en este formato JSON:
{{
  "is_sensitive": true/false,
  "confidence": "low/medium/high",
  "reason": "Explicación corta y directa"
}}

REGLAS:
- NO uses lenguaje probabilístico ("parece", "podría ser")
- NO inventes información que no está en el fragmento
- SÉ DIRECTO: es sensible o no lo es

Respuesta JSON:"""


def build_system_prompt() -> str:
    """
    System prompt para el clasificador.

    Define el rol y límites del modelo.
    """
    return """Eres un clasificador de sensibilidad contextual para un escáner de PII.

TU ROL:
- Clasificar si un fragmento contiene información personal sensible
- Distinguir datos reales de ejemplos/placeholders/datos técnicos

NO DEBES:
- Detectar PII desde cero (ya está detectado)
- Calcular niveles de riesgo
- Decidir el resultado final
- Inventar información no presente

RESPONDE SIEMPRE:
- En formato JSON estricto
- Con razones cortas y directas
- Sin lenguaje vago o probabilístico"""
