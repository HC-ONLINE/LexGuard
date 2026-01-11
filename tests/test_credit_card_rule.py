"""Tests para regla de detección de tarjetas de crédito"""

import pytest
from lexguard.core.rules.credit_card import CreditCardRule


class TestCreditCardRule:
    """Probar detección y validación de tarjetas de crédito"""

    @pytest.fixture
    def rule(self):
        """Crear instancia de CreditCardRule"""
        return CreditCardRule()

    def test_detect_valid_visa(self, rule):
        """Probar detección de tarjeta Visa válida"""
        line = "Payment processed with card 4532015112830366"
        candidates = rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert candidates[0].pii_type == "CREDIT_CARD"
        assert "luhn" in candidates[0].validators_passed
        assert "4532" in candidates[0].masked_value

    def test_detect_with_positive_context(self, rule):
        """Probar detección con contexto de pago"""
        line = "credit card: 4532015112830366 exp 12/25"
        candidates = rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert (
            "card" in candidates[0].context_hits
            or "credit" in candidates[0].context_hits
        )

    def test_reject_invalid_luhn(self, rule):
        """Probar rechazo de Luhn inválido"""
        line = "Card number: 1234567812345678"
        candidates = rule.scan_line(line, 1, "test.txt")

        # Debería ser DROPPED (no retornado)
        assert len(candidates) == 0

    def test_reject_uuid_like(self, rule):
        """Probar rechazo de patrones tipo UUID"""
        line = "uuid: 4532-0151-1283-0366-1234-5678"
        candidates = rule.scan_line(line, 1, "test.txt")

        # Debería ser DROPPED por contexto negativo
        assert len(candidates) == 0

    def test_detect_multiple_cards(self, rule):
        """Probar detección de múltiples tarjetas en una línea"""
        line = "Cards: 4532015112830366 and 5555555555554444"
        candidates = rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 2

    def test_reject_all_same_digit(self, rule):
        """Probar rechazo de patrones con todos los dígitos iguales"""
        line = "Card: 4444444444444444"
        candidates = rule.scan_line(line, 1, "test.txt")

        # Debería ser DROPPED
        assert len(candidates) == 0

    def test_validate_visa_format(self, rule):
        """Probar validación de formato Visa"""
        is_valid, validators = rule.validate("4532015112830366")

        assert is_valid
        assert "brand_visa" in validators
        assert "luhn" in validators

    def test_validate_mastercard_format(self, rule):
        """Probar validación de formato Mastercard"""
        is_valid, validators = rule.validate("5555555555554444")

        assert is_valid
        assert "brand_mastercard" in validators
        assert "luhn" in validators

    def test_validate_amex_format(self, rule):
        """Probar validación de formato Amex"""
        is_valid, validators = rule.validate("378282246310005")

        assert is_valid
        assert "brand_amex" in validators
        assert "luhn" in validators

    def test_masking(self, rule):
        """Probar enmascaramiento de PII"""
        masked = rule.mask_value("4532015112830366")

        assert masked.startswith("4532")
        assert masked.endswith("0366")
        assert "*" in masked
        assert "0151" not in masked
