"""Tests para sistema de puntuación de confianza"""

import pytest
from lexguard.core.rules.base import Candidate
from lexguard.core.scoring.confidence import ConfidenceScorer, ConfidenceFilter


class TestConfidenceScorer:
    """Probar cálculo de confianza"""

    @pytest.fixture
    def scorer(self):
        """Crear instancia de ConfidenceScorer"""
        return ConfidenceScorer()

    def test_credit_card_with_luhn(self, scorer):
        """Probar tarjeta de crédito con validación Luhn"""
        candidate = Candidate(
            pii_type="CREDIT_CARD",
            raw_value="4532015112830366",
            masked_value="4532********0366",
            file="test.txt",
            line_number=1,
            validators_passed=["luhn", "brand_visa"],
            context_hits=["payment"],
        )

        confidence, classification, reasons = scorer.score(candidate)

        # Base 0.70 + Luhn 0.20 + context 0.15 = 1.05 → clamped to 1.0
        assert confidence >= 0.80
        assert classification == "FOUND"

    def test_credit_card_without_context(self, scorer):
        """Probar tarjeta de crédito sin contexto semántico"""
        candidate = Candidate(
            pii_type="CREDIT_CARD",
            raw_value="4532015112830366",
            masked_value="4532********0366",
            file="test.txt",
            line_number=1,
            validators_passed=["luhn", "brand_visa"],
        )

        confidence, classification, reasons = scorer.score(candidate)

        # Base 0.70 + Luhn 0.20 = 0.90
        assert confidence >= 0.80
        assert classification == "FOUND"

    def test_negative_context_penalty(self, scorer):
        """Probar que contexto negativo reduce confianza"""
        candidate = Candidate(
            pii_type="CREDIT_CARD",
            raw_value="4532015112830366",
            masked_value="4532********0366",
            file="test.txt",
            line_number=1,
            validators_passed=["luhn"],
            context_negative=["uuid", "test"],
        )

        confidence, classification, reasons = scorer.score(candidate)

        # Debería ser penalizado
        assert confidence < 0.70

    def test_uncertain_classification(self, scorer):
        """Probar clasificación UNCERTAIN"""
        candidate = Candidate(
            pii_type="EMAIL",
            raw_value="test@example.com",
            masked_value="test@***.com",
            file="test.txt",
            line_number=1,
            validators_passed=["format_valid"],
        )

        confidence, classification, reasons = scorer.score(candidate)

        # Email base 0.50, debería ser UNCERTAIN
        assert 0.50 <= confidence < 0.80
        assert classification == "UNCERTAIN"

    def test_ignored_classification(self, scorer):
        """Probar clasificación IGNORED"""
        candidate = Candidate(
            pii_type="EMAIL",
            raw_value="test@example.com",
            masked_value="test@***.com",
            file="test.txt",
            line_number=1,
            validators_passed=[],
            context_negative=["dummy", "fake"],
        )

        confidence, classification, reasons = scorer.score(candidate)

        # Should be penalized below 0.50
        assert confidence < 0.50
        assert classification == "IGNORED"


class TestConfidenceFilter:
    """Test confidence filtering"""

    def test_default_threshold(self):
        """Test default threshold (0.80)"""
        filter = ConfidenceFilter()

        assert filter.should_include(0.85)
        assert filter.should_include(0.80)
        assert not filter.should_include(0.79)

    def test_custom_threshold(self):
        """Test custom threshold"""
        filter = ConfidenceFilter(threshold=0.90)

        assert filter.should_include(0.95)
        assert not filter.should_include(0.85)

    def test_invalid_threshold(self):
        """Test invalid threshold raises error"""
        with pytest.raises(ValueError):
            ConfidenceFilter(threshold=1.5)

        with pytest.raises(ValueError):
            ConfidenceFilter(threshold=-0.1)
