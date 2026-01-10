"""
Sistema de puntuación de confianza.
Evalúa Candidatos y asigna puntajes de confianza con justificación.
"""

from typing import Literal
from lexguard.core.rules.base import Candidate


class ConfidenceScorer:
    """
    Calcular puntajes de confianza para candidatos de PII.

    Diseño:
    - Puntaje base depende del tipo de PII
    - Ajustado por validadores pasados
    - Ajustado por contexto (positivo/negativo)
    - Umbrales determinan la clasificación

    Clasificación:
    - FOUND: confidence >= 0.80 (alta confianza)
    - UNCERTAIN: 0.50 <= confidence < 0.80 (media)
    - IGNORED: confidence < 0.50 (baja)
    """

    # Puntajes base por tipo de PII
    BASE_SCORES = {
        "CREDIT_CARD": 0.70,
        "CEDULA_CO": 0.60,
        "PHONE_CO": 0.55,
        "EMAIL": 0.50,
    }

    # Pesos de validadores
    VALIDATOR_BOOST = {
        "luhn": 0.20,  # Validación fuerte
        "checksum": 0.20,
        "brand_visa": 0.05,
        "brand_mastercard": 0.05,
        "brand_amex": 0.05,
        "prefix_valid": 0.15,  # Prefijo móvil colombiano
        "length_valid": 0.05,
        "format_valid": 0.05,
    }

    # Ajustes de contexto
    CONTEXT_BOOST = 0.15  # Por palabra clave positiva
    CONTEXT_PENALTY = -0.30  # Por palabra clave negativa

    # Umbrales de clasificación
    THRESHOLD_FOUND = 0.80
    THRESHOLD_UNCERTAIN = 0.50

    def score(
        self, candidate: Candidate
    ) -> tuple[float, Literal["FOUND", "UNCERTAIN", "IGNORED"], list[str]]:
        """
        Calcular puntaje de confianza para un candidato.

        Args:
            candidate: Candidato de PII a evaluar

        Returns:
            (confidence_score, classification, reasons)
        """
        # Comenzar con puntaje base
        base = self.BASE_SCORES.get(candidate.pii_type, 0.50)
        score = base
        reasons = [f"base_{candidate.pii_type.lower()}: {base:.2f}"]

        # Aplicar boosts de validadores
        for validator in candidate.validators_passed:
            boost = self.VALIDATOR_BOOST.get(validator, 0.0)
            if boost > 0:
                score += boost
                reasons.append(f"validator_{validator}: +{boost:.2f}")

        # Aplicar contexto positivo
        if candidate.context_hits:
            context_boost = len(candidate.context_hits) * self.CONTEXT_BOOST
            context_boost = min(context_boost, 0.20)  # Límite en +0.20
            score += context_boost
            keywords = ", ".join(candidate.context_hits[:3])
            reasons.append(f"positive_context({keywords}): +{context_boost:.2f}")

        # Aplicar penalización de contexto negativo
        if candidate.context_negative:
            penalty = len(candidate.context_negative) * self.CONTEXT_PENALTY
            penalty = max(penalty, -0.40)  # Límite en -0.40
            score += penalty
            keywords = ", ".join(candidate.context_negative[:3])
            reasons.append(f"negative_context({keywords}): {penalty:.2f}")

        # Limitar puntaje a [0.0, 1.0]
        score = max(0.0, min(1.0, score))

        # Determinar clasificación
        classification: Literal["FOUND", "UNCERTAIN", "IGNORED"]
        if score >= self.THRESHOLD_FOUND:
            classification = "FOUND"
        elif score >= self.THRESHOLD_UNCERTAIN:
            classification = "UNCERTAIN"
        else:
            classification = "IGNORED"

        reasons.append(f"final_score: {score:.2f} → {classification}")

        return score, classification, reasons

    def score_batch(
        self, candidates: list[Candidate]
    ) -> list[tuple[float, Literal["FOUND", "UNCERTAIN", "IGNORED"], list[str]]]:
        """Score multiple candidates efficiently"""
        return [self.score(c) for c in candidates]


class ConfidenceFilter:
    """
    Filter candidates based on confidence threshold.
    Used for CLI --confidence-threshold option.
    """

    def __init__(self, threshold: float = 0.80):
        """
        Args:
            threshold: Minimum confidence to include in report
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        self.threshold = threshold

    def should_include(self, confidence: float) -> bool:
        """Check if finding meets threshold"""
        return confidence >= self.threshold

    def filter_findings(
        self, findings: list[tuple[Candidate, float]]
    ) -> list[tuple[Candidate, float]]:
        """
        Filter findings by confidence threshold.

        Args:
            findings: List of (candidate, confidence) tuples

        Returns:
            Filtered list
        """
        return [(c, conf) for c, conf in findings if self.should_include(conf)]
