"""
Sistema de puntuación de riesgo.
Asigna niveles de riesgo operacional basándose en tipo de PII,
contexto y ubicación del archivo.
"""

from typing import Literal, Sequence
from pathlib import Path
from lexguard.core.rules.base import Candidate


RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


class RiskScorer:
    """
    Calcular riesgo operacional para hallazgos de PII.

    Diseño:
    - Riesgo base depende de la sensibilidad del PII
    - Ajustado por ubicación/tipo de archivo
    - Ajustado por nivel de confianza
    - Nunca degradado para PII real (solo si está enmascarado/falso)

    Niveles de Riesgo:
    - HIGH: Preocupación inmediata (tarjetas de crédito, IDs en producción)
    - MEDIUM: Debería ser revisado (emails, teléfonos)
    - LOW: Solo informativo (ya enmascarado/datos de prueba)
    """

    # Riesgo base por tipo de PII
    BASE_RISK: dict[str, RiskLevel] = {
        "CREDIT_CARD": "HIGH",
        "CEDULA_CO": "HIGH",
        "PHONE_CO": "MEDIUM",
        "EMAIL": "MEDIUM",
    }

    # Patrones de archivos de alto riesgo
    HIGH_RISK_PATTERNS = {
        "backup",
        "dump",
        "export",
        "archive",
        "production",
        "prod",
        "log",
        "logs",
        ".sql",
        ".db",
        ".csv",
        ".json",
    }

    # Patrones de archivos de riesgo medio
    MEDIUM_RISK_PATTERNS = {"staging", "test", "dev", "debug", "output", "report"}

    def score(
        self, candidate: Candidate, confidence: float
    ) -> tuple[RiskLevel, list[str]]:
        """
        Calcular nivel de riesgo para un hallazgo.

        Args:
            candidate: Candidato de PII
            confidence: Puntaje de confianza (0.0-1.0)

        Returns:
            (risk_level, reasons)
        """
        # Comenzar con riesgo base
        base_risk = self.BASE_RISK.get(candidate.pii_type, "MEDIUM")
        current_risk = base_risk
        reasons = [f"base_risk_{candidate.pii_type}: {base_risk}"]

        # Verificar ubicación del archivo
        file_path = Path(candidate.file)
        file_risk = self._assess_file_risk(file_path)

        if file_risk:
            reasons.append(f"file_location: {file_risk}")
            # Aumentar riesgo si el archivo es sensible
            if file_risk == "HIGH" and current_risk != "HIGH":
                current_risk = self._upgrade_risk(current_risk)
                reasons.append(f"upgraded to {current_risk} due to file location")

        # Alta confianza aumenta riesgo
        if confidence >= 0.90 and current_risk == "MEDIUM":
            current_risk = "HIGH"
            reasons.append(f"high_confidence ({confidence:.2f}) → upgraded to HIGH")

        # Baja confianza puede degradar SOLO si base era MEDIUM
        if confidence < 0.60 and base_risk == "MEDIUM":
            current_risk = "LOW"
            reasons.append(f"low_confidence ({confidence:.2f}) → downgraded to LOW")

        # NUNCA degradar riesgo base HIGH para PII real
        if base_risk == "HIGH":
            current_risk = "HIGH"

        return current_risk, reasons

    def _assess_file_risk(self, file_path: Path) -> RiskLevel | None:
        """
        Evaluar riesgo basándose en ubicación/nombre del archivo.

        Returns:
            Risk level or None if no pattern matches
        """
        file_str = str(file_path).lower()

        # Revisar patrones de alto riesgo
        for pattern in self.HIGH_RISK_PATTERNS:
            if pattern in file_str:
                return "HIGH"

        # Revisar patrones de riesgo medio
        for pattern in self.MEDIUM_RISK_PATTERNS:
            if pattern in file_str:
                return "MEDIUM"

        return None

    def _upgrade_risk(self, current: RiskLevel) -> RiskLevel:
        """Aumentar riesgo en un nivel"""
        if current == "LOW":
            return "MEDIUM"
        elif current == "MEDIUM":
            return "HIGH"
        return "HIGH"

    def should_fail_ci(self, risk: RiskLevel, fail_on_high: bool = False) -> bool:
        """
        Determinar si un hallazgo debería fallar el pipeline de CI/CD.

        Args:
            risk: Nivel de riesgo
            fail_on_high: Si fallar en hallazgos de riesgo HIGH

        Returns:
            True si debe fallar la construcción
        """
        if not fail_on_high:
            return False

        return risk == "HIGH"


class RiskAggregator:
    """
    Agregar riesgo a través de múltiples hallazgos.
    Útil para reportes y decisiones de CI/CD.
    """

    @staticmethod
    def calculate_overall_risk(
        findings: Sequence[tuple[Candidate | None, RiskLevel | str]]
    ) -> RiskLevel:
        """
        Calcular riesgo general desde múltiples hallazgos.

        Lógica:
        - Cualquier HIGH → general HIGH
        - Cualquier MEDIUM (sin HIGH) → general MEDIUM
        - Todos LOW → general LOW

        Args:
            findings: Lista de tuplas (candidate, risk)

        Returns:
            Nivel de riesgo general
        """
        if not findings:
            return "LOW"

        risks = [risk for _, risk in findings]

        if "HIGH" in risks:
            return "HIGH"
        elif "MEDIUM" in risks:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def group_by_risk(
        findings: Sequence[tuple[Candidate | None, RiskLevel | str]]
    ) -> dict[str, list[Candidate]]:
        """
        Agrupar hallazgos por nivel de riesgo.

        Returns:
            Dict mapeando nivel de riesgo → candidatos
        """
        grouped: dict[str, list[Candidate]] = {
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }

        for candidate, risk in findings:
            # Omite candidatos None
            # (las pruebas pueden pasar marcadores de posición None)
            if candidate is not None:
                grouped[risk].append(candidate)

        return grouped
