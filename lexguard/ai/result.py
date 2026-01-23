"""
Resultado de clasificación de sensibilidad por IA.

La IA NO detecta PII, NO calcula riesgo, NO decide el resultado final.
Solo clasifica sensibilidad contextual de hallazgos ya detectados.
"""

from enum import Enum


class AIConfidence(Enum):
    """
    Nivel de confianza de la clasificación de IA.

    NO confundir con confidence del detector.
    Esto mide cuán segura está la IA de su clasificación contextual.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AIResult:
    """
    Resultado de clasificación de sensibilidad contextual.

    La IA responde ÚNICAMENTE a:
    "¿Este fragmento contiene información personal sensible?"

    NO calcula riesgo (LOW/MEDIUM/HIGH).
    NO decide clasificación final (FOUND/UNCERTAIN/IGNORED).
    """

    def __init__(
        self,
        is_sensitive: bool,
        confidence: AIConfidence,
        reason: str,
    ):
        """
        Args:
            is_sensitive: True si el contexto indica información personal sensible
            confidence: Nivel de confianza de la clasificación (low/medium/high)
            reason: Explicación corta sin lenguaje probabilístico vago
        """
        self.is_sensitive = is_sensitive
        self.confidence = confidence
        self.reason = reason

    def to_dict(self) -> dict:
        """Serializar para logging/reporte"""
        return {
            "is_sensitive": self.is_sensitive,
            "confidence": self.confidence.value,
            "reason": self.reason,
        }

    def __repr__(self) -> str:
        return (
            f"AIResult(is_sensitive={self.is_sensitive}, "
            f"confidence={self.confidence.value}, "
            f"reason='{self.reason}')"
        )
