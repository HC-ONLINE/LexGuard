"""Tests para validador de algoritmo Luhn"""

from lexguard.core.validators.luhn import validate_luhn, validate_luhn_batch


class TestLuhnValidator:
    """Probar implementación del algoritmo Luhn"""

    def test_valid_visa_cards(self):
        """Test valid Visa card numbers"""
        valid_cards = ["4532015112830366", "4556737586899855", "4916338506082832"]
        for card in valid_cards:
            assert validate_luhn(card), f"{card} should be valid"

    def test_valid_mastercard(self):
        """Probar números Mastercard válidos"""
        valid_cards = ["5425233430109903", "5555555555554444"]
        for card in valid_cards:
            assert validate_luhn(card), f"{card} should be valid"

    def test_valid_amex(self):
        """Probar números American Express válidos"""
        valid_cards = ["374245455400126", "378282246310005"]
        for card in valid_cards:
            assert validate_luhn(card), f"{card} should be valid"

    def test_invalid_cards(self):
        """Probar números de tarjeta inválidos"""
        invalid_cards = [
            "1234567812345678",
            # Nota: "0000000000000000" pasa Luhn técnicamente (suma=0, 0%10=0)
            # pero debería ser rechazado por lógica de regla (todos los dígitos iguales)
            "1111111111111111",
        ]
        for card in invalid_cards:
            assert not validate_luhn(card), f"{card} should be invalid"

    def test_cards_with_spaces(self):
        """Probar que se manejan tarjetas con espacios"""
        assert validate_luhn("4532 0151 1283 0366")

    def test_cards_with_dashes(self):
        """Probar que se manejan tarjetas con guiones"""
        assert validate_luhn("4532-0151-1283-0366")

    def test_too_short(self):
        """Probar tarjetas que son demasiado cortas"""
        assert not validate_luhn("123456")

    def test_batch_validation(self):
        """Probar validación por lotes"""
        cards = [
            "4532015112830366",  # Valid
            "1234567812345678",  # Invalid
            "5555555555554444",  # Valid
        ]
        results = validate_luhn_batch(cards)

        assert results["4532015112830366"] is True
        assert results["1234567812345678"] is False
        assert results["5555555555554444"] is True
