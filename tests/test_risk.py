"""Tests para sistema de puntuación de riesgo"""

import pytest
from lexguard.core.rules.base import Candidate
from lexguard.core.scoring.risk import RiskScorer, RiskAggregator


class TestRiskScorer:
    """Probar cálculo de nivel de riesgo"""

    @pytest.fixture
    def scorer(self):
        """Crear instancia de RiskScorer"""
        return RiskScorer()

    def test_credit_card_with_transactional_context(self, scorer):
        """Probar que tarjeta con contexto transaccional
        (1+ señal) + confianza alta → HIGH"""
        candidate = Candidate(
            pii_type="CREDIT_CARD",
            raw_value="4532015112830366",
            masked_value="4532********0366",
            file="data.txt",
            line_number=1,
            validators_passed=["luhn"],
            context_hits=["payment"],  # 1 señal transaccional es suficiente
        )

        risk, reasons = scorer.score(candidate, confidence=0.85)

        assert risk == "HIGH"
        assert "transactional_context" in " ".join(reasons)

    def test_high_risk_file_location(self, scorer):
        """Probar que ubicación sensible (sql/backup) + PII válida → HIGH"""
        candidate = Candidate(
            pii_type="CREDIT_CARD",
            raw_value="4532015112830366",
            masked_value="4532********0366",
            file="backups/database_dump.sql",
            line_number=1,
            validators_passed=["luhn"],
            context_hits=[],  # Sin contexto, pero ubicación es crítica
        )

        risk, reasons = scorer.score(candidate, confidence=0.95)

        # Artefactos SQL con tarjetas válidas → HIGH
        assert risk == "HIGH"
        assert "sensitive_artifact_with_valid_pii" in " ".join(reasons)

    def test_production_logs_with_transactional_context(self, scorer):
        """Probar que logs de producción con contexto transaccional obtienen HIGH"""
        candidate = Candidate(
            pii_type="CREDIT_CARD",
            raw_value="4532015112830366",
            masked_value="4532********0366",
            file="logs/production.log",
            line_number=1,
            validators_passed=["luhn"],
            context_hits=["payment"],  # 1+ señal transaccional
        )

        risk, reasons = scorer.score(candidate, confidence=0.90)

        assert risk == "HIGH"
        assert "sensitive_location" in " ".join(reasons)

    def test_low_confidence_downgrade(self, scorer):
        """Probar que baja confianza puede degradar MEDIUM a LOW"""
        candidate = Candidate(
            pii_type="EMAIL",
            raw_value="test@example.com",
            masked_value="test@***.com",
            file="test.txt",
            line_number=1,
            validators_passed=[],
        )

        risk, reasons = scorer.score(candidate, confidence=0.55)

        # Email base es MEDIUM, baja confianza degrada a LOW
        assert risk == "LOW"

    def test_valid_pii_neutral_location(self, scorer):
        """Probar que PII válida sin contexto transacciona
        l en ubicación neutral da MEDIUM"""
        candidate = Candidate(
            pii_type="CREDIT_CARD",
            raw_value="4532015112830366",
            masked_value="4532********0366",
            file="config.json",
            line_number=1,
            validators_passed=["luhn"],
            context_hits=[],  # Sin contexto transaccional
        )

        risk, reasons = scorer.score(candidate, confidence=0.85)

        # Alta confianza sin contexto transaccional → MEDIUM
        assert risk == "MEDIUM"
        assert "valid_pii_without_strong_context" in " ".join(reasons)

    def test_test_file_with_critical_context(self, scorer):
        """Probar que contexto crítico en test sigue siendo HIGH"""
        candidate = Candidate(
            pii_type="CREDIT_CARD",
            raw_value="4532015112830366",
            masked_value="4532********0366",
            file="tests/test_data.txt",
            line_number=1,
            validators_passed=["luhn"],
            context_hits=["cvv"],  # Contexto crítico en test
        )

        # Contexto crítico (cvv) siempre es HIGH, incluso en test
        risk, reasons = scorer.score(candidate, confidence=0.90)

        assert risk == "HIGH"
        assert "critical_context" in " ".join(reasons)

    def test_ci_fail_on_high(self, scorer):
        """Probar lógica de fallo de CI/CD"""
        assert scorer.should_fail_ci("HIGH", fail_on_high=True)
        assert not scorer.should_fail_ci("MEDIUM", fail_on_high=True)
        assert not scorer.should_fail_ci("HIGH", fail_on_high=False)


class TestRiskAggregator:
    """Probar agregación de riesgo"""

    def test_overall_risk_any_high(self):
        """Probar riesgo general con cualquier HIGH"""
        findings = [(None, "LOW"), (None, "MEDIUM"), (None, "HIGH")]

        overall = RiskAggregator.calculate_overall_risk(findings)
        assert overall == "HIGH"

    def test_overall_risk_medium_only(self):
        """Probar riesgo general con MEDIUM (sin HIGH)"""
        findings = [(None, "LOW"), (None, "MEDIUM"), (None, "MEDIUM")]

        overall = RiskAggregator.calculate_overall_risk(findings)
        assert overall == "MEDIUM"

    def test_overall_risk_low_only(self):
        """Probar riesgo general con solo LOW"""
        findings = [(None, "LOW"), (None, "LOW")]

        overall = RiskAggregator.calculate_overall_risk(findings)
        assert overall == "LOW"

    def test_empty_findings(self):
        """Test empty findings list"""
        overall = RiskAggregator.calculate_overall_risk([])
        assert overall == "LOW"
