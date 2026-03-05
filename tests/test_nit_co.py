"""Tests para NITCORule - Detección de NIT/RUT colombiano

NITs válidos usados en los tests (verificados con algoritmo DIAN):
  - 800197268-4   (DIAN)
  - 901234567-7
  - 900456789-4
  - 700456789-9
"""

import pytest
from lexguard.core.rules.nit_co import NITCORule
from lexguard.core.validators.nit_co import validate_nit, compute_check_digit


# ===========================================================================
# Tests del validador (nit_co.py)
# ===========================================================================


class TestNITValidator:
    """Pruebas unitarias del validador de dígito verificador DIAN"""

    def test_compute_check_digit_dian_known(self):
        """Verifica dígito verificador del NIT de la DIAN (800197268-4)"""
        assert compute_check_digit("800197268") == 4

    def test_compute_check_digit_sample_1(self):
        """Verifica dígito verificador de 901234567-7"""
        assert compute_check_digit("901234567") == 7

    def test_compute_check_digit_sample_2(self):
        """Verifica dígito verificador de 900456789-4"""
        assert compute_check_digit("900456789") == 4

    def test_compute_check_digit_sample_3(self):
        """Verifica dígito verificador de 700456789-9"""
        assert compute_check_digit("700456789") == 9

    def test_validate_nit_valid(self):
        """validate_nit retorna True para NIT correcto"""
        assert validate_nit("800197268", 4) is True
        assert validate_nit("901234567", 7) is True
        assert validate_nit("900456789", 4) is True

    def test_validate_nit_invalid_check_digit(self):
        """validate_nit retorna False si el dígito verificador es incorrecto"""
        assert validate_nit("800197268", 5) is False
        assert validate_nit("800197268", 0) is False

    def test_validate_nit_accepts_string_check_digit(self):
        """validate_nit acepta el dígito verificador como string"""
        assert validate_nit("800197268", "4") is True
        assert validate_nit("800197268", "9") is False

    def test_compute_check_digit_raises_on_wrong_length(self):
        """compute_check_digit lanza ValueError si no son exactamente 9 dígitos"""
        with pytest.raises(ValueError):
            compute_check_digit("12345678")  # 8 dígitos

        with pytest.raises(ValueError):
            compute_check_digit("1234567890")  # 10 dígitos

    def test_compute_check_digit_raises_on_non_digits(self):
        """compute_check_digit lanza ValueError si hay caracteres no numéricos"""
        with pytest.raises(ValueError):
            compute_check_digit("80019726X")


# ===========================================================================
# Tests de la regla de detección
# ===========================================================================


class TestNITCORule:
    """Pruebas para detección de NIT/RUT colombianos"""

    @pytest.fixture
    def nit_rule(self):
        """Crea una instancia de NITCORule"""
        return NITCORule()

    # ==================== IDENTIDAD ====================

    def test_pii_type(self, nit_rule):
        """pii_type debe ser NIT_CO"""
        assert nit_rule.pii_type == "NIT_CO"

    def test_display_name(self, nit_rule):
        """display_name debe ser legible"""
        assert "NIT" in nit_rule.display_name or "RUT" in nit_rule.display_name

    # ==================== DETECCIÓN BÁSICA ====================

    def test_detect_nit_plain_digits(self, nit_rule):
        """Detecta NIT en formato numérico continuo"""
        line = "El NIT de la empresa es 800197268-4"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert candidates[0].pii_type == "NIT_CO"
        assert "800197268" in candidates[0].raw_value
        assert candidates[0].line_number == 1

    def test_detect_nit_with_dots(self, nit_rule):
        """Detecta NIT con puntos separadores de miles"""
        line = "RUT: 800.197.268-4"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert "800" in candidates[0].raw_value

    def test_detect_nit_prefix_uppercase(self, nit_rule):
        """Detecta NIT con prefijo NIT en mayúsculas"""
        line = "NIT 901.234.567-7"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1

    def test_detect_nit_prefix_lowercase(self, nit_rule):
        """Detecta NIT con prefijo nit en minúsculas"""
        line = "nit 901234567-7"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1

    def test_detect_rut_prefix(self, nit_rule):
        """Detecta NIT con prefijo RUT"""
        line = "RUT: 900.456.789-4"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1

    def test_detect_nit_without_prefix(self, nit_rule):
        """Detecta NIT sin prefijo cuando el dígito verificador es correcto"""
        line = "700456789-9"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1

    def test_detect_nit_in_sql_query(self, nit_rule):
        """Detecta NIT dentro de una consulta SQL"""
        line = "SELECT * FROM empresas WHERE nit = '800197268-4';"

        candidates = nit_rule.scan_line(line, 10, "dump.sql")

        assert len(candidates) == 1
        assert candidates[0].file == "dump.sql"
        assert candidates[0].line_number == 10

    def test_detect_nit_in_csv_line(self, nit_rule):
        """Detecta NIT en línea CSV típica"""
        line = "Empresa ABC,800197268-4,Bogotá,activo"

        candidates = nit_rule.scan_line(line, 5, "proveedores.csv")

        assert len(candidates) == 1
        assert candidates[0].file == "proveedores.csv"

    # ==================== MASKING ====================

    def test_masking_format(self, nit_rule):
        """Enmascaramiento muestra 3 iniciales, 3 finales y dígito verificador"""
        line = "NIT 800197268-4"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        masked = candidates[0].masked_value
        assert masked.startswith("800")
        assert masked.endswith("-4")
        assert "***" in masked

    def test_masking_9digit_nit(self, nit_rule):
        """Enmascaramiento correcto para NIT de 9 dígitos"""
        line = "NIT 901234567-7"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        # Esperado: 901***567-7
        assert candidates[0].masked_value == "901***567-7"

    # ==================== VALIDACIONES DURAS (DROP) ====================

    def test_reject_invalid_check_digit(self, nit_rule):
        """Rechaza NIT cuando el dígito verificador es incorrecto"""
        line = "NIT 800197268-9"  # Correcto es -4

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0, "Dígito verificador incorrecto debe ser rechazado"

    def test_reject_trivial_sequence(self, nit_rule):
        """Rechaza secuencias numéricas triviales
        aunque el verificador coincida accidentalmente"""
        line = "nit 123456789-0"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0, "Secuencias triviales deben ser rechazadas"

    def test_reject_all_same_digits(self, nit_rule):
        """Rechaza NIT con todos los dígitos iguales"""
        line = "nit 111111111-1"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0

    def test_reject_starting_with_zero(self, nit_rule):
        """Rechaza NIT que empieza en 0 (inválido en Colombia)"""
        line = "nit 012345678-5"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0, "NIT iniciando en 0 debe ser rechazado"

    def test_reject_no_check_digit(self, nit_rule):
        """No detecta número sin dígito verificador separado por guion"""
        line = "empresa 800197268"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0, "Sin dígito verificador no debe dar match"

    def test_reject_wrong_length(self, nit_rule):
        """No detecta si la base no tiene exactamente 9 dígitos"""
        line = "empresa 80019726-4"  # Solo 8 dígitos en la base

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 0

    # ==================== CONTEXTO ====================

    def test_positive_context_nit_keyword(self, nit_rule):
        """Contexto 'nit' o 'rut' es detectado como positivo"""
        line = "NIT 800197268-4 empresa proveedora"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert len(candidates[0].context_hits) > 0

    def test_positive_context_factura(self, nit_rule):
        """Contexto 'factura' es detectado como positivo"""
        line = "factura electronica emitida por NIT 800197268-4"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert "factura" in candidates[0].context_hits

    def test_positive_context_dian(self, nit_rule):
        """Contexto 'dian' es detectado como positivo"""
        line = "dian registro 901234567-7"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        assert "dian" in candidates[0].context_hits

    def test_negative_context_cedula(self, nit_rule):
        """Contexto de cédula no corresponde a NIT
        (no debe dar match — distinto formato)"""
        line = "cedula 1023456789"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        # cédula no tiene formato NIT (no tiene dígito verificador con guión)
        assert len(candidates) == 0

    # ==================== VALIDATORS ====================

    def test_validators_passed_list(self, nit_rule):
        """Verifica que validators_passed incluya los validadores correctos"""
        line = "NIT 800197268-4"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 1
        vp = candidates[0].validators_passed
        assert "length" in vp
        assert "first_digit" in vp
        assert "not_trivial" in vp
        assert "check_digit_dian" in vp

    # ==================== MÚLTIPLES EN LÍNEA ====================

    def test_multiple_nits_in_line(self, nit_rule):
        """Detecta múltiples NITs en la misma línea"""
        line = "Proveedor 1: 800197268-4, Proveedor 2: 901234567-7"

        candidates = nit_rule.scan_line(line, 1, "test.txt")

        assert len(candidates) == 2

    def test_line_number_and_file_propagated(self, nit_rule):
        """Número de línea y archivo se propagan correctamente"""
        line = "NIT 900456789-4"

        candidates = nit_rule.scan_line(line, 42, "backups/empresas.sql")

        assert len(candidates) == 1
        assert candidates[0].line_number == 42
        assert candidates[0].file == "backups/empresas.sql"

    # ==================== VALIDATE INTERFACE ====================

    def test_validate_with_full_string(self, nit_rule):
        """validate() acepta string completo XXXXXXXXX-Y"""
        is_valid, validators = nit_rule.validate("800197268-4")

        assert is_valid is True
        assert "check_digit_dian" in validators

    def test_validate_invalid_full_string(self, nit_rule):
        """validate() rechaza string completo con dígito incorrecto"""
        is_valid, validators = nit_rule.validate("800197268-9")

        assert is_valid is False
        assert validators == []
