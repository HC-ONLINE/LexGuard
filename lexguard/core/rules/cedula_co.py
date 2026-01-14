"""
Regla de detección de Cédulas de Ciudadanía colombianas.

Enfoque conservador:
- Solo formatos numéricos realistas (7-10 dígitos)
- Sin validación oficial (no disponible)
- Sin dígito de verificación (no existe en CC)
- Filtrado estricto de secuencias basura

NO incluye:
- Cédula de extranjería
- NIT / RUT
- Validación contra bases oficiales
"""

import regex as re
from lexguard.core.rules.base import DetectionRule, Candidate


class CedulaCORule(DetectionRule):
    """
    Detectar Cédulas de Ciudadanía colombianas en texto plano.

    Pipeline de validación:
    1. Coincidencia regex (formato numérico 7-10 dígitos)
    2. Normalización (eliminar separadores)
    3. Validación de longitud (7-10 dígitos)
    4. Filtrado de secuencias basura (DROP)
    5. Análisis de contexto

    Condiciones de DROP (no reportado):
    - Longitud fuera de rango [7, 10]
    - Todos los dígitos iguales (111111111)
    - Secuencias triviales (1234567, 987654321)
    """

    # Formatos soportados:
    # - Numérico continuo: 1023456789
    # - Con puntos: 1.023.456.789
    # - Con espacios: 1 023 456 789
    PATTERN = re.compile(
        r"\b(?:\d{1,3}(?:[.\s]?\d{3}){2,3}|\d{7,10})\b",
        re.IGNORECASE,
    )

    # Palabras clave de contexto
    POSITIVE_CONTEXT = {
        "cc",
        "cedula",
        "cédula",
        "documento",
        "identificacion",
        "identificación",
    }

    NEGATIVE_CONTEXT = {
        "telefono",
        "teléfono",
        "celular",
        "account",
        "order",
        "invoice",
        "factura",
        "pedido",
    }

    # Secuencias triviales a rechazar (DROP)
    TRIVIAL_SEQUENCES = {
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "987654321",
        "9876543210",
        "0000000",
        "00000000",
        "000000000",
        "0000000000",
    }

    @property
    def pii_type(self) -> str:
        """Identificador único del tipo de PII"""
        return "CEDULA_CO"

    @property
    def display_name(self) -> str:
        """Nombre legible para reportes"""
        return "Cédula de Ciudadanía Colombiana"

    def scan_line(self, line: str, line_number: int, file_path: str) -> list[Candidate]:
        """
        Escanea una línea en busca de cédulas colombianas.

        Args:
            line: Contenido de la línea
            line_number: Número de línea (1-based)
            file_path: Ruta del archivo

        Returns:
            Lista de candidatos detectados
        """
        candidates = []

        for match in self.PATTERN.finditer(line):
            raw_value = match.group()
            normalized = self._normalize(raw_value)

            # Validación estricta (DROP si falla)
            is_valid, validators = self.validate(normalized)
            if not is_valid:
                continue

            # Crear candidato con contexto
            candidate = Candidate(
                pii_type=self.pii_type,
                raw_value=raw_value,
                masked_value=self._mask_cedula(normalized),
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

    def validate(self, match: str) -> tuple[bool, list[str]]:
        """
        Realiza validación semántica en el valor normalizado.

        Args:
            normalized: Valor normalizado (solo dígitos)

        Returns:
            (es_válido, lista_de_validadores_pasados)
        """
        normalized = match
        validators = []

        # Validación 1: longitud válida
        if not self._is_valid_length(normalized):
            return (False, [])
        validators.append("length")

        # Validación 2: no es secuencia trivial
        if self._is_trivial_sequence(normalized):
            return (False, [])
        validators.append("not_trivial")

        # Validación 3: no todos los dígitos iguales
        if self._all_digits_same(normalized):
            return (False, [])
        validators.append("not_repeated")

        return (True, validators)

    def _normalize(self, value: str) -> str:
        """
        Normaliza el valor eliminando separadores.

        Args:
            value: Valor original

        Returns:
            Solo dígitos
        """
        return str(re.sub(r"[^\d]", "", value))

    def _is_valid_length(self, normalized: str) -> bool:
        """
        Verifica longitud válida (7-10 dígitos).

        Args:
            normalized: Valor normalizado

        Returns:
            True si longitud válida
        """
        return 7 <= len(normalized) <= 10

    def _is_trivial_sequence(self, normalized: str) -> bool:
        """
        Detecta secuencias triviales (1234567, 987654321, etc.).

        Args:
            normalized: Valor normalizado

        Returns:
            True si es secuencia trivial
        """
        return normalized in self.TRIVIAL_SEQUENCES

    def _all_digits_same(self, normalized: str) -> bool:
        """
        Detecta si todos los dígitos son iguales (111111111).

        Args:
            normalized: Valor normalizado

        Returns:
            True si todos iguales
        """
        return len(set(normalized)) == 1

    def _extract_context_hits(self, line: str, match: re.Match) -> list[str]:
        """
        Extrae palabras clave de contexto positivo cercanas al match.

        Args:
            line: Línea completa
            match: Match de regex

        Returns:
            Lista de palabras clave encontradas
        """
        # Contexto ±40 chars
        start = max(0, match.start() - 40)
        end = min(len(line), match.end() + 40)
        surrounding = line[start:end].lower()

        hits = []
        for keyword in self.POSITIVE_CONTEXT:
            if keyword in surrounding:
                hits.append(keyword)

        return hits

    def _extract_context_negative(self, line: str, match: re.Match) -> list[str]:
        """
        Extrae palabras clave de contexto negativo cercanas al match.

        Args:
            line: Línea completa
            match: Match de regex

        Returns:
            Lista de palabras clave negativas encontradas
        """
        # Contexto ±40 chars
        start = max(0, match.start() - 40)
        end = min(len(line), match.end() + 40)
        surrounding = line[start:end].lower()

        negative = []
        for keyword in self.NEGATIVE_CONTEXT:
            if keyword in surrounding:
                negative.append(keyword)

        return negative

    def _mask_cedula(self, normalized: str) -> str:
        """
        Enmascara la cédula mostrando solo 2 primeros y 2 últimos dígitos.

        Ejemplos:
            1023456789 → 10******89
            12345678 → 12****78

        Args:
            normalized: Cédula normalizada

        Returns:
            Cédula enmascarada
        """
        if len(normalized) <= 4:
            return "*" * len(normalized)

        return f"{normalized[:2]}{'*' * (len(normalized) - 4)}{normalized[-2:]}"
