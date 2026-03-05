"""
Regla de detección de NIT/RUT colombiano.

NIT (Número de Identificación Tributaria) y RUT (Registro Único Tributario)
son el mismo documento en Colombia — el RUT es el certificado del NIT.

Formato NIT:
    - 9 dígitos base + guion + 1 dígito verificador
    - Separadores opcionales de miles con punto
    - Prefijos reconocidos: NIT, NIT:, RUT, RUT:

Ejemplos válidos:
    - 800.197.268-4
    - 900456789-4
    - NIT 901.234.567-7
    - RUT: 700456789-9

Validaciones aplicadas:
    1. Formato regex (9 dígitos + dígito verificador)
    2. Dígito verificador DIAN (obligatorio — DROP si no pasa)
    3. Primer dígito ≥ 1 (no puede empezar en 0 en NIT colombiano)
    4. No es secuencia trivial (123456789, etc.)

NO incluye:
    - Cédulas de ciudadanía (CEDULA_CO)
    - Cédulas de extranjería
    - Pasaportes
"""

import regex as re
from lexguard.core.rules.base import DetectionRule, Candidate
from lexguard.core.validators.nit_co import validate_nit


class NITCORule(DetectionRule):
    """
    Detectar NIT/RUT colombianos en texto plano y estructurado.

    Pipeline de validación:
    1. Coincidencia regex (9 dígitos + dígito verificador)
    2. Normalización (eliminar separadores)
    3. Dígito verificador DIAN (DROP si inválido)
    4. Primer dígito ≥ 1 (DROP si empieza en 0)
    5. Filtrado de secuencias triviales (DROP)
    6. Análisis de contexto (boost / penalización)

    Condiciones de DROP (no reportado):
    - Dígito verificador incorrecto
    - Primer dígito = 0
    - Secuencias triviales (123456789, etc.)
    """

    # ---------------------------------------------------------------
    # Formatos soportados:
    #   900456789-4       → numérico continuo con verificador
    #   900.456.789-4     → puntos de miles con verificador
    #   NIT 900.456.789-4 → con prefijo NIT / RUT
    #   RUT: 900456789-4  → con prefijo + dos puntos
    # ---------------------------------------------------------------
    PATTERN = re.compile(
        r"""
        (?:(?i:nit|rut)\s*[:.]?\s*)?          # Prefijo opcional: NIT / RUT
        \b
        (\d{3}[.\s]?\d{3}[.\s]?\d{3}|\d{9})  # 9 dígitos base (con o sin separadores)
        \s*[-–]\s*                             # Separador guion (simple o largo)
        (\d)                                   # Dígito verificador
        \b
        """,
        re.VERBOSE,
    )

    # Palabras clave de contexto positivo
    POSITIVE_CONTEXT = {
        "nit",
        "rut",
        "tributaria",
        "contribuyente",
        "empresa",
        "sociedad",
        "razon social",
        "razón social",
        "factura",
        "invoice",
        "fiscal",
        "dian",
        "rut:",
        "nit:",
    }

    # Palabras clave de contexto negativo
    NEGATIVE_CONTEXT = {
        "telefono",
        "teléfono",
        "celular",
        "account",
        "order",
        "pedido",
        "cedula",
        "cédula",
        "cc",
    }

    # Secuencias triviales (solo la parte de 9 dígitos)
    TRIVIAL_SEQUENCES = {
        "123456789",
        "987654321",
        "000000000",
        "111111111",
        "222222222",
        "333333333",
        "444444444",
        "555555555",
        "666666666",
        "777777777",
        "888888888",
        "999999999",
    }

    @property
    def pii_type(self) -> str:
        return "NIT_CO"

    @property
    def display_name(self) -> str:
        return "NIT/RUT Colombiano"

    def scan_line(self, line: str, line_number: int, file_path: str) -> list[Candidate]:
        """
        Escanear una línea en busca de NIT/RUT colombianos.

        Args:
            line: Contenido de la línea
            line_number: Número de línea (1-based)
            file_path: Ruta del archivo

        Returns:
            Lista de candidatos detectados (vacía si ninguno válido)
        """
        candidates = []

        for match in self.PATTERN.finditer(line):
            raw_value = match.group()
            digits_raw = match.group(1)  # 9 dígitos base (puede tener puntos/espacios)
            check_raw = match.group(2)  # Dígito verificador

            # Normalizar base
            digits_norm = re.sub(r"[^\d]", "", digits_raw)
            check_digit = int(check_raw)

            # Validación estricta (DROP si falla)
            is_valid, validators = self.validate(digits_norm, check_digit)
            if not is_valid:
                continue

            candidate = Candidate(
                pii_type=self.pii_type,
                raw_value=raw_value,
                masked_value=self._mask_nit(digits_norm, check_digit),
                file=file_path,
                line_number=line_number,
                validators_passed=validators,
                validators_failed=[],
                context_hits=self._extract_context_hits(line, match),
                context_negative=self._extract_context_negative(line, match),
                line_context=line.strip(),
            )
            candidates.append(candidate)

        return candidates

    # Interfaz DetectionRule

    def validate(
        self, match: str, check_digit: int | None = None
    ) -> tuple[bool, list[str]]:
        """
        Validar semánticamente un NIT.

        Cuando se llama desde scan_line, ``match`` son los 9 dígitos base
        y ``check_digit`` es el dígito verificador ya extraído del patrón.

        Para compatibilidad con la interfaz base también acepta
        ``match`` como la cadena completa ``XXXXXXXXX-Y``.

        Returns:
            (es_válido, lista_de_validadores_pasados)
        """
        validators: list[str] = []

        # Descomponer si se recibe como "XXXXXXXXX-Y"
        if check_digit is None:
            parts = match.split("-")
            if len(parts) != 2:
                return (False, [])
            digits_norm = re.sub(r"[^\d]", "", parts[0])
            try:
                check_digit = int(parts[1])
            except ValueError:
                return (False, [])
        else:
            digits_norm = match

        # 1. Longitud exacta 9
        if len(digits_norm) != 9:
            return (False, [])
        validators.append("length")

        # 2. Primer dígito ≥ 1 (NIT colombiano no empieza en 0)
        if digits_norm[0] == "0":
            return (False, [])
        validators.append("first_digit")

        # 3. No es secuencia trivial
        if digits_norm in self.TRIVIAL_SEQUENCES:
            return (False, [])
        validators.append("not_trivial")

        # 4. Dígito verificador DIAN (validación fuerte)
        if not validate_nit(digits_norm, check_digit):
            return (False, [])
        validators.append("check_digit_dian")

        return (True, validators)

    # Helpers privados

    def _mask_nit(self, digits: str, check_digit: int) -> str:
        """
        Enmascarar NIT: mostrar primeros 3 y último dígito del grupo base.

        Ejemplo: 800197268-4  →  800***268-4
        """
        if len(digits) < 6:
            return f"{'*' * len(digits)}-{check_digit}"
        return f"{digits[:3]}{'*' * (len(digits) - 6)}{digits[-3:]}-{check_digit}"

    def _extract_context_hits(self, line: str, match: re.Match) -> list[str]:
        start = max(0, match.start() - 50)
        end = min(len(line), match.end() + 50)
        surrounding = line[start:end].lower()
        return [kw for kw in self.POSITIVE_CONTEXT if kw in surrounding]

    def _extract_context_negative(self, line: str, match: re.Match) -> list[str]:
        start = max(0, match.start() - 50)
        end = min(len(line), match.end() + 50)
        surrounding = line[start:end].lower()
        return [kw for kw in self.NEGATIVE_CONTEXT if kw in surrounding]
