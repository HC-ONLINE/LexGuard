"""
Sistema de puntuación de riesgo.
Asigna niveles de riesgo operacional basándose en tipo de PII,
contexto y ubicación del archivo.
"""

from enum import Enum
from typing import Literal, Sequence
from pathlib import Path
from lexguard.core.rules.base import Candidate


RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


class ExposureLevel(Enum):
    """
    Nivel de exposición por coexistencia de tipos distintos de PII.

    Cross-PII: Riesgo incrementado cuando múltiples tipos de PII
    aparecen en el mismo scope (archivo o ejecución).

    No es agregación simple, es correlación de exposición.
    """

    SINGLE = "SINGLE"  # Solo 1 tipo de PII presente
    COMBINED = "COMBINED"  # 2 tipos distintos de PII
    CRITICAL = "CRITICAL"  # ≥3 tipos distintos de PII


class RiskScorer:
    """
    Calcular riesgo operacional para hallazgos de PII.

    Diseño:
    - Contexto CRÍTICO (cvv, exp) → HIGH siempre
    - Contexto TRANSACCIONAL
        (1+ señal: payment, transaction, etc.) + confianza alta → HIGH
    - Ubicación sensible (sql/backup) + PII válida → HIGH
    - Test files con contexto crítico → HIGH (no se perdonan CVV/EXP)
    - PII válida sin contexto fuerte → MEDIUM

    Principio: En seguridad, tarjeta válida + contexto operacional = alto riesgo.
    No ser excesivamente conservador con HIGH.

    Niveles de Riesgo:
    - HIGH: Crítico (cvv/exp), O transaccional + confianza, O ubicación sensible + PII
    - MEDIUM: PII válida sin contexto fuerte
    - LOW: Baja confianza
    """

    # Contexto TRANSACCIONAL fuerte (indica uso operacional real)
    TRANSACTIONAL_CONTEXT = {
        "payment",
        "transaction",
        "billing",
        "checkout",
        "purchase",
        "pago",
        "transaccion",
    }

    # Contexto CRÍTICO (señales que valen por sí solas → HIGH siempre)
    CRITICAL_CONTEXT = {
        "cvv",
        "exp",
        "cvc",
        "pin",
    }

    # Contexto descriptivo (débil, genérico - NO eleva a HIGH por sí solo)
    DESCRIPTIVE_CONTEXT = {
        "card",
        "credit",
        "customer",
        "account",
        "cliente",
        "cuenta",
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
    }

    # Patrones de archivos de bajo riesgo (test/dev)
    LOW_RISK_PATTERNS = {
        "test",
        "tests",
        "fixture",
        "fixtures",
        "mock",
        "dummy",
        "sample",
        "example",
        "dev",
        "debug",
    }

    def score(
        self, candidate: Candidate, confidence: float
    ) -> tuple[RiskLevel, list[str]]:
        """
        Calcular nivel de riesgo para un hallazgo.

        Lógica de decisión (ordenada):
        1. Contexto CRÍTICO (cvv, exp, cvc, pin) + alta confianza → HIGH
        - La ubicación NO reduce el riesgo en este caso
        2. Contexto TRANSACCIONAL
            (≥1 señal: payment, transaction, etc.) + alta confianza → HIGH
        3. Ubicación sensible (prod, backup, sql, logs) + PII válida → HIGH
        4. PII válida sin contexto fuerte → MEDIUM
        5. Baja confianza o ambigüedad → LOW

        El riesgo se decide por COMBINACIÓN de:
        - Intensidad del contexto
        - Sensibilidad de la ubicación
        - Nivel de confianza

        Args:
            candidate: Candidato de PII detectado
            confidence: Puntaje de confianza (0.0–1.0)

        Returns:
            (risk_level, reasons)
        """
        reasons = []
        file_path = Path(candidate.file)

        # Detectar contexto CRÍTICO (señales que valen por sí solas)
        critical_hits = set(candidate.context_hits) & self.CRITICAL_CONTEXT
        has_critical_context = len(critical_hits) >= 1

        # Detectar contexto TRANSACCIONAL (1+ señal es suficiente)
        transactional_hits = set(candidate.context_hits) & self.TRANSACTIONAL_CONTEXT
        has_transactional_context = len(transactional_hits) >= 1

        # Detectar ubicación
        file_location = self._assess_file_risk(file_path)

        # ========== REGLAS DE CLASIFICACIÓN (orden importa) ==========

        # REGLA 1: Contexto CRÍTICO (cvv, exp) → HIGH siempre
        # (No se perdonan CVV/EXP, ni en tests)
        if has_critical_context and confidence >= 0.85:
            reasons.append(f"critical_context: {', '.join(list(critical_hits))}")
            reasons.append(f"high_confidence: {confidence:.2f}")
            if file_location == "LOW":
                reasons.append(
                    "note: found in test file but critical context remains HIGH"
                )
            return "HIGH", reasons

        # REGLA 2: Contexto
        #   TRANSACCIONAL (payment, transaction, etc.) + alta confianza → HIGH
        # (Tarjeta válida + palabras clave operacionales = alto riesgo)
        if has_transactional_context and confidence >= 0.85:
            reasons.append(
                f"transactional_context: {', '.join(list(transactional_hits)[:3])}"
            )
            reasons.append(f"high_confidence: {confidence:.2f}")
            if file_location == "HIGH":
                reasons.append(f"sensitive_location: {file_path.name}")
            return "HIGH", reasons

        # REGLA 3: Ubicación sensible (sql/backup/prod) + PII válida → HIGH
        # (Artefactos de producción con tarjetas NO son MEDIUM)
        # Ubicación ya es evidencia, confianza ≥0.80 suficiente para HIGH
        if file_location == "HIGH" and confidence >= 0.80:
            reasons.append("sensitive_artifact_with_valid_pii")
            reasons.append(f"file: {file_path.name}")
            reasons.append(f"confidence: {confidence:.2f}")
            return "HIGH", reasons

        # REGLA 4: PII válida sin contexto fuerte → MEDIUM
        # (Detección técnicamente correcta, pero sin indicadores operacionales)
        if confidence >= 0.80:
            reasons.append(f"valid_pii_without_strong_context: {confidence:.2f}")
            if file_location == "HIGH":
                reasons.append(f"location: {file_path.name}")
            return "MEDIUM", reasons

        # REGLA 5: Baja confianza o incertidumbre → LOW
        reasons.append(f"low_confidence_or_unclear: {confidence:.2f}")
        return "LOW", reasons

    def _assess_file_risk(self, file_path: Path) -> RiskLevel:
        """
        Evaluar SENSIBILIDAD de ubicación (no es riesgo final).

        IMPORTANTE: Retorna RiskLevel pero representa sensibilidad de
        ubicación, no riesgo del hallazgo. El riesgo final se calcula
        combinando esto con contexto y confianza.

        Returns:
            LOW: test/fixture files (baja sensibilidad)
            MEDIUM: neutral location (sensibilidad media)
            HIGH: prod/backup/logs (alta sensibilidad)
        """
        file_str = str(file_path).lower()

        # Primero verificar LOW (test files tienen prioridad)
        for pattern in self.LOW_RISK_PATTERNS:
            if pattern in file_str:
                return "LOW"

        # Luego verificar HIGH (production/backup)
        for pattern in self.HIGH_RISK_PATTERNS:
            if pattern in file_str:
                return "HIGH"

        # Por defecto: neutral
        return "MEDIUM"

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

    Capacidades:
    - Riesgo general (máximo entre hallazgos)
    - Exposición cross-PII (coexistencia de tipos distintos)
    - Agrupación por nivel de riesgo
    """

    @staticmethod
    def calculate_exposure(findings: Sequence[Candidate]) -> ExposureLevel:
        """
        Calcular nivel de exposición por coexistencia de tipos de PII.

        Cross-PII: Riesgo incrementado cuando múltiples tipos distintos
        de PII coexisten en el mismo scope.

        Regla explícita:
        - 1 tipo de PII → SINGLE
        - 2 tipos distintos → COMBINED
        - ≥3 tipos distintos → CRITICAL

        Args:
            findings: Lista de candidatos detectados

        Returns:
            Nivel de exposición

        Ejemplo:
            Solo EMAIL → SINGLE
            EMAIL + PHONE → COMBINED
            EMAIL + PHONE + CEDULA → CRITICAL
        """
        if not findings:
            return ExposureLevel.SINGLE

        # Extraer tipos únicos de PII
        pii_types = {f.pii_type for f in findings}

        # Aplicar regla explícita
        if len(pii_types) >= 3:
            return ExposureLevel.CRITICAL
        if len(pii_types) == 2:
            return ExposureLevel.COMBINED

        return ExposureLevel.SINGLE

    @staticmethod
    def calculate_overall_risk(
        findings: Sequence[tuple[Candidate | None, RiskLevel | str]],
        exposure: ExposureLevel | None = None,
    ) -> RiskLevel:
        """
        Calcular riesgo general desde múltiples hallazgos.

        Lógica:
        - Cualquier HIGH → general HIGH
        - Cualquier MEDIUM (sin HIGH) → general MEDIUM
        - Todos LOW → general LOW

        Ajuste por exposición cross-PII:
        - COMBINED eleva MEDIUM → HIGH
        - CRITICAL eleva MEDIUM → HIGH
        - Nunca baja el riesgo
        - HIGH no se eleva más (ya es máximo)

        Args:
            findings: Lista de tuplas (candidate, risk)
            exposure: Nivel de exposición cross-PII (opcional)

        Returns:
            Nivel de riesgo general
        """
        if not findings:
            return "LOW"

        risks = [risk for _, risk in findings]

        # Calcular riesgo base (sin considerar exposure)
        base_risk: RiskLevel
        if "HIGH" in risks:
            base_risk = "HIGH"
        elif "MEDIUM" in risks:
            base_risk = "MEDIUM"
        else:
            base_risk = "LOW"

        # Aplicar ajuste por exposición cross-PII (solo eleva, nunca baja)
        if exposure and base_risk == "MEDIUM":
            if exposure in (ExposureLevel.COMBINED, ExposureLevel.CRITICAL):
                # MEDIUM + cross-PII → HIGH
                return "HIGH"

        return base_risk

    @staticmethod
    def group_by_risk(
        findings: Sequence[tuple[Candidate | None, RiskLevel | str]],
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
