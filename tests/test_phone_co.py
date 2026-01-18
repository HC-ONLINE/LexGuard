"""
Tests para PhoneCORule.

Cubre:
- Detección de 3 formatos válidos
- Validaciones DROP (prefijo, repetidos, triviales)
- Contexto (positivo/negativo)
- Masking
- Casos reales (CSV, múltiples números)
"""

from lexguard.core.rules.phone_co import PhoneCORule


class TestPhoneCODetection:
    """Pruebas de detección básica de teléfonos."""

    def setup_method(self):
        self.rule = PhoneCORule()

    def test_detect_continuous_format(self):
        """Detecta teléfono sin separadores: 3001234567"""
        candidates = self.rule.scan_line("3001234567", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].raw_value == "3001234567"
        assert candidates[0].masked_value == "300****567"

    def test_detect_space_format(self):
        """Detecta teléfono con espacios: 300 123 4567"""
        candidates = self.rule.scan_line("300 123 4567", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].raw_value == "300 123 4567"

    def test_detect_hyphen_format(self):
        """Detecta teléfono con guiones: 300-123-4567"""
        candidates = self.rule.scan_line("300-123-4567", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].raw_value == "300-123-4567"

    def test_detect_international_format(self):
        """Detecta teléfono con +57"""
        candidates = self.rule.scan_line("+573001234567", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].raw_value == "+573001234567"

    def test_detect_international_with_spaces(self):
        """Detecta +57 300 123 4567"""
        candidates = self.rule.scan_line("+57 300 123 4567", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].raw_value == "+57 300 123 4567"


class TestPhoneCOValidationDROP:
    """Pruebas de validadores que causan DROP inmediato."""

    def setup_method(self):
        self.rule = PhoneCORule()

    def test_invalid_prefix_below_range(self):
        """DROP: Prefijo 299 (inválido)"""
        candidates = self.rule.scan_line("2991234567", 1, "test.txt")
        assert len(candidates) == 0

    def test_invalid_prefix_above_range(self):
        """DROP: Prefijo 324 (fuera de rango)"""
        candidates = self.rule.scan_line("3241234567", 1, "test.txt")
        assert len(candidates) == 0

    def test_fixed_line_prefix(self):
        """DROP: Prefijo 201 (línea fija, no móvil)"""
        candidates = self.rule.scan_line("2011234567", 1, "test.txt")
        assert len(candidates) == 0

    def test_repeated_digits(self):
        """DROP: Dígitos repetidos"""
        candidates = self.rule.scan_line("3001111111", 1, "test.txt")
        assert len(candidates) == 0

    def test_all_same_digit(self):
        """DROP: Todo el número es igual"""
        candidates = self.rule.scan_line("3000000000", 1, "test.txt")
        assert len(candidates) == 0

    def test_short_length(self):
        """DROP: Menos de 10 dígitos"""
        candidates = self.rule.scan_line("300123456", 1, "test.txt")
        assert len(candidates) == 0

    def test_long_length(self):
        """DROP: Más de 10 dígitos"""
        candidates = self.rule.scan_line("30012345678", 1, "test.txt")
        assert len(candidates) == 0


class TestPhoneCOContext:
    """Pruebas de detección de contexto semántico."""

    def setup_method(self):
        self.rule = PhoneCORule()

    def test_positive_context_single_keyword(self):
        """Contexto positivo: 1 keyword → context_hits no vacío"""
        candidates = self.rule.scan_line("Llama al 3001234567", 1, "test.txt")
        assert len(candidates) == 1
        assert "llama" in candidates[0].context_hits

    def test_positive_context_multiple_keywords(self):
        """Contexto positivo: múltiples keywords"""
        candidates = self.rule.scan_line("Teléfono celular: 3001234567", 1, "test.txt")
        assert len(candidates) == 1
        assert len(candidates[0].context_hits) >= 2

    def test_negative_context(self):
        """Contexto negativo: se registra en context_negative"""
        candidates = self.rule.scan_line("Código referencia: 3001234567", 1, "test.txt")
        assert len(candidates) == 1
        assert (
            "codigo" in candidates[0].context_negative
            or "referencia" in candidates[0].context_negative
        )

    def test_no_context_keywords(self):
        """Sin contexto: context_hits vacío"""
        candidates = self.rule.scan_line("3001234567 es un número", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].context_hits == []


class TestPhoneCOMasking:
    """Pruebas de enmascaramiento."""

    def setup_method(self):
        self.rule = PhoneCORule()

    def test_mask_continuous_format(self):
        """Mascara 3001234567 → 300****567"""
        candidates = self.rule.scan_line("3001234567", 1, "test.txt")
        assert candidates[0].masked_value == "300****567"

    def test_mask_international_format(self):
        """Mascara +573001234567 → +57300****567"""
        candidates = self.rule.scan_line("+573001234567", 1, "test.txt")
        assert candidates[0].masked_value == "+57300****567"

    def test_mask_preserves_prefix(self):
        """El prefijo del operador siempre visible"""
        # Claro (300-304)
        c1 = self.rule.scan_line("3001234567", 1, "test.txt")[0]
        assert c1.masked_value.startswith("300")

        # Movistar (305-309)
        c2 = self.rule.scan_line("3051234567", 1, "test.txt")[0]
        assert c2.masked_value.startswith("305")

        # Tigo (310-315)
        c3 = self.rule.scan_line("3101234567", 1, "test.txt")[0]
        assert c3.masked_value.startswith("310")


class TestPhoneCOMultiple:
    """Pruebas con múltiples números y formatos reales."""

    def setup_method(self):
        self.rule = PhoneCORule()

    def test_csv_line(self):
        """Detecta en línea CSV"""
        line = "Juan Pérez,juan@example.com,3001234567,2026-01-17"
        candidates = self.rule.scan_line(line, 1, "contacts.csv")
        assert len(candidates) == 1

    def test_multiple_phones_same_line(self):
        """Múltiples teléfonos en la misma línea"""
        line = "Contactos: 3001234567 o 3051234567"
        candidates = self.rule.scan_line(line, 1, "test.txt")
        assert len(candidates) == 2

    def test_phone_in_sentence(self):
        """Teléfono dentro de una oración"""
        line = "Puedes comunicarte al teléfono 3001234567 de lunes a viernes"
        candidates = self.rule.scan_line(line, 1, "test.txt")
        assert len(candidates) == 1
        assert (
            "teléfono" in candidates[0].context_hits
            or "telefono" in candidates[0].context_hits
        )

    def test_mixed_valid_and_invalid(self):
        """Detecta válidos, ignora inválidos"""
        line = "Válido: 3001234567, Inválido: 2001234567, Otro: 3051234567"
        candidates = self.rule.scan_line(line, 1, "test.txt")
        assert len(candidates) == 2  # Los dos válidos


class TestPhoneCOValidators:
    """Pruebas de lista de validadores passed/failed."""

    def setup_method(self):
        self.rule = PhoneCORule()

    def test_validators_passed(self):
        """Número válido: todos los validadores pasaron"""
        candidates = self.rule.scan_line("3001234567", 1, "test.txt")
        assert set(candidates[0].validators_passed) == {
            "length",
            "valid_prefix",
            "not_trivial",
        }
        assert candidates[0].validators_failed == []

    def test_validators_failed_prefix(self):
        """Número con prefijo inválido"""
        is_valid, failed = self.rule.validate("2001234567")
        assert not is_valid
        assert "valid_prefix" in failed


class TestPhoneCOProperties:
    """Pruebas de propiedades de la regla."""

    def setup_method(self):
        self.rule = PhoneCORule()

    def test_pii_type(self):
        """pii_type es PHONE_CO"""
        assert self.rule.pii_type == "PHONE_CO"

    def test_display_name(self):
        """display_name es correcto"""
        assert self.rule.display_name == "Teléfono Móvil Colombiano"


class TestPhoneCOEdgeCases:
    """Pruebas de casos límite."""

    def setup_method(self):
        self.rule = PhoneCORule()

    def test_phone_at_line_boundary_start(self):
        """Teléfono al inicio de línea"""
        candidates = self.rule.scan_line("3001234567 es el contacto", 1, "test.txt")
        assert len(candidates) == 1

    def test_phone_at_line_boundary_end(self):
        """Teléfono al final de línea"""
        candidates = self.rule.scan_line("Contacto: 3001234567", 1, "test.txt")
        assert len(candidates) == 1

    def test_empty_line(self):
        """Línea vacía"""
        candidates = self.rule.scan_line("", 1, "test.txt")
        assert len(candidates) == 0

    def test_only_spaces(self):
        """Línea solo espacios"""
        candidates = self.rule.scan_line("   ", 1, "test.txt")
        assert len(candidates) == 0

    def test_case_insensitive_keywords(self):
        """Keywords en mayúsculas también se detectan"""
        candidates = self.rule.scan_line("TELÉFONO: 3001234567", 1, "test.txt")
        assert len(candidates) == 1
        assert (
            "teléfono" in candidates[0].context_hits
            or "telefono" in candidates[0].context_hits
        )
