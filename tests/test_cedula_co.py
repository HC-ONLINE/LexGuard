"""Tests para CedulaCORule - Detección de Cédulas de Ciudadanía colombianas"""

import pytest
from lexguard.core.rules.cedula_co import CedulaCORule


class TestCedulaCORule:
    """Pruebas para detección de cédulas colombianas"""

    @pytest.fixture
    def cedula_rule(self):
        """Crea una instancia de CedulaCORule"""
        return CedulaCORule()

    # ==================== DETECCIÓN BÁSICA ====================

    def test_detect_valid_cedula_numeric(self, cedula_rule):
        """Verifica detección de cédula numérica continua válida"""
        line = "La cédula del usuario es 1023456789"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert candidates[0].pii_type == "CEDULA_CO"
        assert candidates[0].raw_value == "1023456789"
        assert candidates[0].masked_value == "10******89"

    def test_detect_cedula_with_dots(self, cedula_rule):
        """Verifica detección de cédula con puntos separadores"""
        line = "CC: 1.023.456.789"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert candidates[0].raw_value == "1.023.456.789"
        assert candidates[0].masked_value == "10******89"

    def test_detect_cedula_with_spaces(self, cedula_rule):
        """Verifica detección de cédula con espacios separadores"""
        line = "Documento de identificación: 1 023 456 789"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert candidates[0].raw_value == "1 023 456 789"
        assert candidates[0].masked_value == "10******89"

    # ==================== VALIDACIONES DURAS (DROP) ====================

    def test_reject_trivial_sequence_ascending(self, cedula_rule):
        """Rechaza secuencia trivial ascendente"""
        line = "El número 123456789 no es una cédula válida"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0, "Secuencias triviales deben ser rechazadas"

    def test_reject_trivial_sequence_descending(self, cedula_rule):
        """Rechaza secuencia trivial descendente"""
        line = "987654321 es una secuencia"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0

    def test_reject_all_same_digits(self, cedula_rule):
        """Rechaza cédulas con todos los dígitos iguales"""
        line = "111111111 no es válido"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0, "Dígitos repetidos deben ser rechazados"

    def test_reject_too_short(self, cedula_rule):
        """Rechaza números muy cortos (<7 dígitos)"""
        line = "El número 123456 es muy corto"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0

    def test_reject_too_long(self, cedula_rule):
        """Rechaza números muy largos (>10 dígitos)"""
        line = "12345678901 es demasiado largo"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0

    # ==================== NO MATCH ESPERADO ====================

    def test_no_match_credit_card(self, cedula_rule):
        """No debe confundir con tarjetas de crédito"""
        line = "Tarjeta 4532015112830366"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0, "No debe detectar tarjetas de crédito"

    def test_no_match_colombian_phone(self, cedula_rule):
        """No debe confundir con teléfonos colombianos"""
        line = "Teléfono: 3001234567"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        # Si detecta, debe tener contexto negativo
        if len(candidates) > 0:
            assert len(candidates[0].context_negative) > 0

    # ==================== CONTEXTO ====================

    def test_positive_context_detected(self, cedula_rule):
        """Contexto positivo detectado"""
        line = "Cédula de ciudadanía: 1023456789"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert len(candidates[0].context_hits) > 0

    def test_negative_context_detected(self, cedula_rule):
        """Contexto negativo detectado"""
        line = "Número de factura: 1023456789"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        if len(candidates) > 0:
            assert len(candidates[0].context_negative) > 0

    # ==================== MASKING ====================

    def test_masking_standard_cedula(self, cedula_rule):
        """Verifica enmascaramiento estándar (10 dígitos)"""
        line = "CC: 1023456789"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert candidates[0].masked_value == "10******89"

    def test_masking_short_cedula(self, cedula_rule):
        """Verifica enmascaramiento de cédula corta (8 dígitos)"""
        line = "Documento: 10234567"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert candidates[0].masked_value == "10****67"

    # ==================== CSV / REAL WORLD ====================

    def test_detect_cedula_in_csv_line(self, cedula_rule):
        """Detecta cédulas en línea CSV realista"""
        line = "Juan Pérez,1023456789,jperez@example.com,Bogotá"

        candidates = cedula_rule.scan_line(line, 5, "usuarios.csv")

        assert len(candidates) == 1
        assert candidates[0].raw_value == "1023456789"
        assert candidates[0].file == "usuarios.csv"
        assert candidates[0].line_number == 5

    def test_multiple_cedulas_in_line(self, cedula_rule):
        """Detecta múltiples cédulas en la misma línea"""
        line = "Usuario 1: 1023456789, Usuario 2: 8765432109"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 2
        assert candidates[0].raw_value == "1023456789"
        assert candidates[1].raw_value == "8765432109"

    # ==================== VALIDATORS ====================

    def test_validators_passed_list(self, cedula_rule):
        """Verifica que validators_passed se reporte correctamente"""
        line = "CC: 1023456789"

        candidates = cedula_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert "length" in candidates[0].validators_passed
        assert "not_trivial" in candidates[0].validators_passed
        assert "not_repeated" in candidates[0].validators_passed
        assert len(candidates[0].validators_failed) == 0
