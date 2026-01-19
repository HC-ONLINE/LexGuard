"""
Tests para EmailRule.

Cubre:
- Detección de emails estándar
- Validaciones DROP (denylist, IPs, formato)
- Contexto (positivo/negativo técnico)
- Masking
- Casos reales (logs, JSON, CSV)
"""

from lexguard.core.rules.email import EmailRule


class TestEmailDetection:
    """Pruebas de detección básica de emails."""

    def setup_method(self):
        self.rule = EmailRule()

    def test_detect_standard_email(self):
        """Detecta email estándar: usuario@dominio.com"""
        candidates = self.rule.scan_line("usuario@dominio.com", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].raw_value == "usuario@dominio.com"

    def test_detect_email_with_subdomain(self):
        """Detecta email con subdominio"""
        candidates = self.rule.scan_line("user@mail.empresa.com", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].raw_value == "user@mail.empresa.com"

    def test_detect_email_with_dots(self):
        """Detecta email con puntos en usuario"""
        candidates = self.rule.scan_line("juan.perez@dominio.com", 1, "test.txt")
        assert len(candidates) == 1

    def test_detect_email_with_plus(self):
        """Detecta email con + en usuario"""
        candidates = self.rule.scan_line("user+tag@dominio.com", 1, "test.txt")
        assert len(candidates) == 1

    def test_detect_email_with_numbers(self):
        """Detecta email con números"""
        candidates = self.rule.scan_line("user123@dominio.com", 1, "test.txt")
        assert len(candidates) == 1


class TestEmailValidationDROP:
    """Pruebas de validadores que causan DROP inmediato."""

    def setup_method(self):
        self.rule = EmailRule()

    def test_drop_localhost(self):
        """DROP: usuario@localhost"""
        candidates = self.rule.scan_line("user@localhost", 1, "test.txt")
        assert len(candidates) == 0

    def test_drop_example_com(self):
        """DROP: test@example.com"""
        candidates = self.rule.scan_line("test@example.com", 1, "test.txt")
        assert len(candidates) == 0

    def test_drop_example_org(self):
        """DROP: user@example.org"""
        candidates = self.rule.scan_line("user@example.org", 1, "test.txt")
        assert len(candidates) == 0

    def test_drop_test_com(self):
        """DROP: user@test.com"""
        candidates = self.rule.scan_line("user@test.com", 1, "test.txt")
        assert len(candidates) == 0

    def test_drop_ip_domain(self):
        """DROP: user@127.0.0.1"""
        candidates = self.rule.scan_line("user@127.0.0.1", 1, "test.txt")
        assert len(candidates) == 0

    def test_drop_no_tld(self):
        """DROP: user@domain (sin TLD)"""
        candidates = self.rule.scan_line("user@domain", 1, "test.txt")
        assert len(candidates) == 0

    def test_drop_subdomain_of_denylist(self):
        """DROP: user@mail.example.com (subdominio de denylist)"""
        candidates = self.rule.scan_line("user@mail.example.com", 1, "test.txt")
        assert len(candidates) == 0


class TestEmailContext:
    """Pruebas de detección de contexto."""

    def setup_method(self):
        self.rule = EmailRule()

    def test_positive_context_single_keyword(self):
        """Contexto positivo: 1 keyword"""
        candidates = self.rule.scan_line("Email: usuario@dominio.com", 1, "test.txt")
        assert len(candidates) == 1
        assert "email" in candidates[0].context_hits

    def test_positive_context_multiple_keywords(self):
        """Contexto positivo: múltiples keywords"""
        candidates = self.rule.scan_line(
            "Correo de contacto: usuario@dominio.com", 1, "test.txt"
        )
        assert len(candidates) == 1
        assert len(candidates[0].context_hits) >= 2

    def test_negative_context_technical(self):
        """Contexto negativo: palabras técnicas"""
        candidates = self.rule.scan_line("commit: usuario@dominio.com", 1, "git.log")
        assert len(candidates) == 1
        assert "commit" in candidates[0].context_negative

    def test_no_context(self):
        """Sin contexto (nota: 'usuario' está en POSITIVE_CONTEXT)"""
        candidates = self.rule.scan_line("juan@dominio.com es válido", 1, "test.txt")
        assert len(candidates) == 1
        assert candidates[0].context_hits == []


class TestEmailMasking:
    """Pruebas de enmascaramiento."""

    def setup_method(self):
        self.rule = EmailRule()

    def test_mask_standard_email(self):
        """Mascara email estándar: us****io@dominio.com"""
        candidates = self.rule.scan_line("usuario@dominio.com", 1, "test.txt")
        assert candidates[0].masked_value == "us****io@dominio.com"

    def test_mask_short_username(self):
        """Mascara usuario corto"""
        candidates = self.rule.scan_line("user@dominio.com", 1, "test.txt")
        # Usuario de 4 caracteres: mantiene primeros 2 + últimos 2
        assert candidates[0].masked_value == "us****er@dominio.com"

    def test_mask_very_short_username(self):
        """Mascara usuario muy corto (≤3 caracteres)"""
        candidates = self.rule.scan_line("ab@dominio.com", 1, "test.txt")
        assert candidates[0].masked_value == "a***@dominio.com"

    def test_mask_preserves_domain(self):
        """El dominio permanece visible"""
        candidates = self.rule.scan_line("user@mail.empresa.com", 1, "test.txt")
        assert "@mail.empresa.com" in candidates[0].masked_value


class TestEmailMultiple:
    """Pruebas con múltiples emails y formatos reales."""

    def setup_method(self):
        self.rule = EmailRule()

    def test_csv_line(self):
        """Detecta email en línea CSV"""
        line = "Juan,Pérez,juan.perez@empresa.com,3001234567"
        candidates = self.rule.scan_line(line, 1, "contacts.csv")
        assert len(candidates) == 1

    def test_json_value(self):
        """Detecta email en JSON"""
        line = '{"email": "user@dominio.com", "name": "Juan"}'
        candidates = self.rule.scan_line(line, 1, "data.json")
        assert len(candidates) == 1

    def test_multiple_emails_same_line(self):
        """Múltiples emails en la misma línea"""
        line = "CC: user1@dominio.com, user2@empresa.com"
        candidates = self.rule.scan_line(line, 1, "email.txt")
        assert len(candidates) == 2

    def test_email_in_log(self):
        """Email en log técnico"""
        line = "[INFO] User registered: usuario@dominio.com"
        candidates = self.rule.scan_line(line, 1, "app.log")
        assert len(candidates) == 1

    def test_email_with_separators(self):
        """Email con separadores comunes"""
        # Con dos puntos
        c1 = self.rule.scan_line("Email: user@dominio.com", 1, "test.txt")
        assert len(c1) == 1

        # Con igual
        c2 = self.rule.scan_line("email=user@dominio.com", 1, "config.txt")
        assert len(c2) == 1

        # Con ángulos
        c3 = self.rule.scan_line("<user@dominio.com>", 1, "header.txt")
        assert len(c3) == 1


class TestEmailValidators:
    """Pruebas de lista de validadores passed/failed."""

    def setup_method(self):
        self.rule = EmailRule()

    def test_validators_passed(self):
        """Email válido: todos los validadores pasaron"""
        candidates = self.rule.scan_line("user@dominio.com", 1, "test.txt")
        assert set(candidates[0].validators_passed) == {
            "format",
            "length",
            "valid_domain",
        }
        assert candidates[0].validators_failed == []

    def test_validators_failed_domain(self):
        """Email con dominio inválido"""
        is_valid, failed = self.rule.validate("user@localhost")
        assert not is_valid
        assert "valid_domain" in failed


class TestEmailProperties:
    """Pruebas de propiedades de la regla."""

    def setup_method(self):
        self.rule = EmailRule()

    def test_pii_type(self):
        """pii_type es EMAIL"""
        assert self.rule.pii_type == "EMAIL"

    def test_display_name(self):
        """display_name es correcto"""
        assert self.rule.display_name == "Dirección de Correo Electrónico"


class TestEmailEdgeCases:
    """Pruebas de casos límite."""

    def setup_method(self):
        self.rule = EmailRule()

    def test_email_at_line_start(self):
        """Email al inicio de línea"""
        candidates = self.rule.scan_line(
            "user@dominio.com es el usuario", 1, "test.txt"
        )
        assert len(candidates) == 1

    def test_email_at_line_end(self):
        """Email al final de línea"""
        candidates = self.rule.scan_line("Contacto: user@dominio.com", 1, "test.txt")
        assert len(candidates) == 1

    def test_email_with_punctuation(self):
        """Email rodeado de puntuación"""
        candidates = self.rule.scan_line("(user@dominio.com)", 1, "test.txt")
        assert len(candidates) == 1

    def test_empty_line(self):
        """Línea vacía"""
        candidates = self.rule.scan_line("", 1, "test.txt")
        assert len(candidates) == 0

    def test_only_spaces(self):
        """Línea solo espacios"""
        candidates = self.rule.scan_line("   ", 1, "test.txt")
        assert len(candidates) == 0

    def test_case_insensitive(self):
        """Email en mayúsculas"""
        candidates = self.rule.scan_line("USER@DOMINIO.COM", 1, "test.txt")
        assert len(candidates) == 1

    def test_mixed_valid_invalid(self):
        """Detecta válidos, ignora inválidos"""
        line = "user@dominio.com y test@example.com"
        candidates = self.rule.scan_line(line, 1, "test.txt")
        assert len(candidates) == 1  # Solo el válido
        assert candidates[0].raw_value == "user@dominio.com"
