"""
Tests de exposición cross-PII.

Valida detección de riesgo incrementado por coexistencia
de múltiples tipos de PII en el mismo scope.
"""

from lexguard.core.rules.base import Candidate
from lexguard.core.scoring.risk import RiskAggregator, ExposureLevel


class TestCrossPIIExposure:
    """Tests de cálculo de exposure level"""

    def test_single_pii_type(self):
        """Un solo tipo de PII → SINGLE"""
        candidates = [
            Candidate(
                pii_type="EMAIL",
                raw_value="test@example.com",
                masked_value="te**@example.com",
                file="test.txt",
                line_number=1,
            ),
            Candidate(
                pii_type="EMAIL",
                raw_value="other@example.com",
                masked_value="ot**@example.com",
                file="test.txt",
                line_number=2,
            ),
        ]

        exposure = RiskAggregator.calculate_exposure(candidates)
        assert exposure == ExposureLevel.SINGLE

    def test_two_pii_types_combined(self):
        """Dos tipos distintos de PII → COMBINED"""
        candidates = [
            Candidate(
                pii_type="EMAIL",
                raw_value="test@example.com",
                masked_value="te**@example.com",
                file="test.txt",
                line_number=1,
            ),
            Candidate(
                pii_type="PHONE_CO",
                raw_value="3001234567",
                masked_value="300****567",
                file="test.txt",
                line_number=2,
            ),
        ]

        exposure = RiskAggregator.calculate_exposure(candidates)
        assert exposure == ExposureLevel.COMBINED

    def test_three_or_more_pii_types_critical(self):
        """Tres o más tipos distintos de PII → CRITICAL"""
        candidates = [
            Candidate(
                pii_type="EMAIL",
                raw_value="test@example.com",
                masked_value="te**@example.com",
                file="test.txt",
                line_number=1,
            ),
            Candidate(
                pii_type="PHONE_CO",
                raw_value="3001234567",
                masked_value="300****567",
                file="test.txt",
                line_number=2,
            ),
            Candidate(
                pii_type="CEDULA_CO",
                raw_value="1234567890",
                masked_value="12******90",
                file="test.txt",
                line_number=3,
            ),
        ]

        exposure = RiskAggregator.calculate_exposure(candidates)
        assert exposure == ExposureLevel.CRITICAL

    def test_empty_findings(self):
        """Sin hallazgos → SINGLE"""
        candidates = []
        exposure = RiskAggregator.calculate_exposure(candidates)
        assert exposure == ExposureLevel.SINGLE


class TestCrossPIIRiskAdjustment:
    """Tests de ajuste de riesgo por cross-PII"""

    def test_combined_elevates_medium_to_high(self):
        """COMBINED eleva MEDIUM → HIGH"""
        findings = [
            (
                Candidate(
                    pii_type="EMAIL",
                    raw_value="test@example.com",
                    masked_value="te**@example.com",
                    file="test.txt",
                    line_number=1,
                ),
                "MEDIUM",
            ),
            (
                Candidate(
                    pii_type="PHONE_CO",
                    raw_value="3001234567",
                    masked_value="300****567",
                    file="test.txt",
                    line_number=2,
                ),
                "MEDIUM",
            ),
        ]

        exposure = ExposureLevel.COMBINED
        risk = RiskAggregator.calculate_overall_risk(findings, exposure)
        assert risk == "HIGH"

    def test_critical_elevates_medium_to_high(self):
        """CRITICAL eleva MEDIUM → HIGH"""
        findings = [
            (
                Candidate(
                    pii_type="EMAIL",
                    raw_value="test@example.com",
                    masked_value="te**@example.com",
                    file="test.txt",
                    line_number=1,
                ),
                "MEDIUM",
            ),
            (
                Candidate(
                    pii_type="PHONE_CO",
                    raw_value="3001234567",
                    masked_value="300****567",
                    file="test.txt",
                    line_number=2,
                ),
                "MEDIUM",
            ),
            (
                Candidate(
                    pii_type="CEDULA_CO",
                    raw_value="1234567890",
                    masked_value="12******90",
                    file="test.txt",
                    line_number=3,
                ),
                "MEDIUM",
            ),
        ]

        exposure = ExposureLevel.CRITICAL
        risk = RiskAggregator.calculate_overall_risk(findings, exposure)
        assert risk == "HIGH"

    def test_high_risk_not_elevated_further(self):
        """HIGH no se eleva más (ya es máximo)"""
        findings = [
            (
                Candidate(
                    pii_type="CREDIT_CARD",
                    raw_value="4532123456780366",
                    masked_value="4532************0366",
                    file="test.txt",
                    line_number=1,
                ),
                "HIGH",
            ),
            (
                Candidate(
                    pii_type="EMAIL",
                    raw_value="test@example.com",
                    masked_value="te**@example.com",
                    file="test.txt",
                    line_number=2,
                ),
                "MEDIUM",
            ),
        ]

        exposure = ExposureLevel.COMBINED
        risk = RiskAggregator.calculate_overall_risk(findings, exposure)
        assert risk == "HIGH"

    def test_low_risk_not_elevated_by_exposure(self):
        """LOW no se eleva por exposure (solo MEDIUM→HIGH)"""
        findings = [
            (
                Candidate(
                    pii_type="EMAIL",
                    raw_value="test@example.com",
                    masked_value="te**@example.com",
                    file="test.txt",
                    line_number=1,
                ),
                "LOW",
            ),
            (
                Candidate(
                    pii_type="PHONE_CO",
                    raw_value="3001234567",
                    masked_value="300****567",
                    file="test.txt",
                    line_number=2,
                ),
                "LOW",
            ),
        ]

        exposure = ExposureLevel.COMBINED
        risk = RiskAggregator.calculate_overall_risk(findings, exposure)
        assert risk == "LOW"

    def test_single_exposure_does_not_elevate(self):
        """SINGLE no eleva el riesgo"""
        findings = [
            (
                Candidate(
                    pii_type="EMAIL",
                    raw_value="test@example.com",
                    masked_value="te**@example.com",
                    file="test.txt",
                    line_number=1,
                ),
                "MEDIUM",
            ),
        ]

        exposure = ExposureLevel.SINGLE
        risk = RiskAggregator.calculate_overall_risk(findings, exposure)
        assert risk == "MEDIUM"

    def test_without_exposure_parameter(self):
        """Sin exposure, usa solo lógica base (backward compatible)"""
        findings = [
            (
                Candidate(
                    pii_type="EMAIL",
                    raw_value="test@example.com",
                    masked_value="te**@example.com",
                    file="test.txt",
                    line_number=1,
                ),
                "MEDIUM",
            ),
        ]

        risk = RiskAggregator.calculate_overall_risk(findings)
        assert risk == "MEDIUM"
