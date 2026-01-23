"""
Módulo de clasificación auxiliar con IA.

La IA NO es el centro del sistema.
Es un clasificador auxiliar de ambigüedad.

Flujo:
  Detectar → Validar → Dudar → Consultar IA → Decidir

Si no hay duda, la IA no se ejecuta.
"""

from lexguard.ai.classifier import AIClassifier
from lexguard.ai.result import AIResult, AIConfidence
from lexguard.ai.prompt import build_classification_prompt, build_system_prompt

__all__ = [
    "AIClassifier",
    "AIResult",
    "AIConfidence",
    "build_classification_prompt",
    "build_system_prompt",
]
