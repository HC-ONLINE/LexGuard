"""
Clases base y modelos para reglas de detección de PII.
"""

from dataclasses import dataclass, field
from typing import Literal, Optional, Any
from abc import ABC, abstractmethod


@dataclass
class Candidate:
    """
    Una posible coincidencia de PII encontrada en un archivo.
    Esto es SOLO evidencia — sin scoring o decisiones aquí.

    Un Candidate puede ser:
    - DROPPED (no reportado en absoluto — falló validación estricta)
    - Convertido a Finding (evaluado para confianza/riesgo)
    """

    pii_type: str  # e.g., "CREDIT_CARD", "CEDULA_CO"
    raw_value: str  # Texto original coincidente
    masked_value: str  # Versión enmascarada para visualización
    file: str  # Ruta del archivo donde se encontró
    line_number: int  # Número de línea (basado en 1)

    # Resultados de validación
    validators_passed: list[str] = field(default_factory=list)
    validators_failed: list[str] = field(default_factory=list)

    # Pistas de contexto
    context_hits: list[str] = field(default_factory=list)
    context_negative: list[str] = field(default_factory=list)

    # Contexto crudo (para depuración)
    line_context: str = ""


@dataclass
class Finding:
    """
    Un Candidate que ha sido evaluado y puntuado.
    Esto representa una decisión sobre qué reportar.
    """

    candidate: Candidate
    confidence: float  # 0.0 to 1.0
    classification: Literal["FOUND", "IGNORED", "UNCERTAIN"]
    risk: Literal["LOW", "MEDIUM", "HIGH"]

    # Justificación para el scoring
    confidence_reasons: list[str] = field(default_factory=list)
    risk_reasons: list[str] = field(default_factory=list)

    # Clasificación auxiliar de IA (opcional)
    ai_result: Optional[Any] = None  # AIResult cuando está habilitada


class DetectionRule(ABC):
    """
    Clase base para todas las reglas de detección de PII.

    Cada regla implementa:
    1. Coincidencia de patrones (regex)
    2. Validación (verificaciones semánticas)
    3. Análisis de contexto (boost/penalización opcional)
    4. Generación de Candidate

    Las reglas NO puntuan — eso se maneja por separado.
    """

    @property
    @abstractmethod
    def pii_type(self) -> str:
        """Identificador único para este tipo de PII (e.g., 'CREDIT_CARD')"""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Nombre legible para humanos para reportes"""
        pass

    @abstractmethod
    def scan_line(self, line: str, line_number: int, file_path: str) -> list[Candidate]:
        """
        Escanear una sola línea en busca de PII.

        Returns:
            Lista de Candidates (puede estar vacía)
            Candidates que fallan validación estricta deben ser DROPPED (no devueltos)
        """
        pass

    @abstractmethod
    def validate(self, match: str) -> tuple[bool, list[str]]:
        """
        Realizar validación semántica en una coincidencia.

        Returns:
            (es_válido, validadores_pasados)

        Si es_válido es False, la coincidencia debe ser DROPPED.
        """
        pass

    def mask_value(self, value: str) -> str:
        """
        Crear una versión enmascarada para visualización.
        Por defecto: mostrar primeros 4 y últimos 4 caracteres.

        Sobrescribir para diferentes estrategias de enmascaramiento.
        """
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"

    def extract_context(
        self, line: str, match_start: int, match_end: int, window: int = 20
    ) -> str:
        """
        Extraer texto circundante para análisis de contexto.

        Args:
            line: Línea completa de texto
            match_start: Posición de inicio de la coincidencia
            match_end: Posición de fin de la coincidencia
            window: Caracteres a incluir antes/después

        Returns:
            Cadena de contexto
        """
        start = max(0, match_start - window)
        end = min(len(line), match_end + window)
        return line[start:end]

    def analyze_context(self, context: str) -> tuple[list[str], list[str]]:
        """
        Analizar contexto circundante para pistas semánticas.

        Returns:
            (aciertos_positivos, aciertos_negativos)

        Aciertos positivos aumentan la confianza.
        Aciertos negativos bajan la confianza o causan DROP.
        """
        return [], []
