"""
Detección de números de teléfono móvil colombiano.

Módulo conservador V1:
- Solo móviles colombianos (prefijos 300-323)
- Valida prefijos por operador
- Anti-secuencias (repetidos, triviales)
- Contexto semántico en español
- Confidence + Risk scoring coherente con cédula
"""

import regex as re
from lexguard.core.rules.base import DetectionRule, Candidate
from lexguard.core.validators.prefixes_co import (
    validate_colombian_prefix,
    is_technical_number,
)


class PhoneCORule(DetectionRule):
    """
    Detecta números de teléfono móvil colombiano.

    Alcance explícito:
    - Móviles nacionales: 10 dígitos (3 prefijo + 7 suscriptor)
    - Móviles internacionales: +57 + 10 dígitos
    - Separadores: espacios, guiones
    - Prefijos válidos: 300-323 (Claro, Movistar, Tigo, WOM, nuevos)

    Excluye intencional:
    - Teléfonos fijos (líneas PBX, extensiones)
    - Códigos cortos (*#123)
    - Teléfono ofuscados manualmente (3XX XXX XXXX)
    - Números internacionales no-CO
    """

    # Patrón para detectar candidatos de teléfono móvil
    # Captura: +57 o número nacional
    PATTERN = re.compile(
        r"\+57\s?3\d{2}[\s-]?\d{3}[\s-]?\d{4}|"  # +573001234567 o +57 300 123 4567
        r"\b3\d{2}[\s-]?\d{3}[\s-]?\d{4}\b",  # 3001234567 nacional
        re.IGNORECASE,
    )

    # Palabras clave positivas (incrementan confianza)
    POSITIVE_CONTEXT = {
        "teléfono",
        "telefono",
        "celular",
        "móvil",
        "movil",
        "contacto",
        "whatsapp",
        "llama",
        "llamar",
        "llámame",
        "llamame",
        "comunicarse",
        "comunicarse",
        "llamada",
    }

    # Palabras clave negativas (restan confianza)
    NEGATIVE_CONTEXT = {
        "orden",
        "ticket",
        "código",
        "codigo",
        "referencia",
        "serial",
        "código_orden",
        "código_ticket",
        "invoice",
        "factura",
    }

    @property
    def pii_type(self) -> str:
        return "PHONE_CO"

    @property
    def display_name(self) -> str:
        return "Teléfono Móvil Colombiano"

    def scan_line(self, line: str, line_number: int, file_path: str) -> list[Candidate]:
        """
        Escanea una línea buscando números de teléfono móvil colombiano.

        Args:
            line: Línea de texto
            line_number: Número de línea (1-indexed)
            file_path: Ruta del archivo

        Returns:
            Lista de Candidate (vacía si no hay hallazgos válidos)
        """
        candidates = []

        for match in self.PATTERN.finditer(line):
            phone_raw = match.group(0)

            # Normalizar: remover +57 si está presente
            phone_normalized = phone_raw.replace("+57", "").replace("+", "")
            phone_normalized = self._extract_digits(phone_normalized)

            # Validación fuerte: DROP si falla
            is_valid, validators_failed = self.validate(phone_normalized)
            if not is_valid:
                continue

            # Extracto de contexto (antes y después)
            context_hits_positive = self._extract_context_hits(
                line, match.start(), match.end(), self.POSITIVE_CONTEXT
            )
            context_hits_negative = self._extract_context_hits(
                line, match.start(), match.end(), self.NEGATIVE_CONTEXT
            )

            # Enmascarar
            masked = self._mask_phone(phone_raw)

            # Crear candidate
            candidate = Candidate(
                pii_type=self.pii_type,
                raw_value=phone_raw,
                masked_value=masked,
                file=file_path,
                line_number=line_number,
                validators_passed=self._get_validators_passed(
                    phone_normalized, validators_failed
                ),
                validators_failed=validators_failed,
                context_hits=context_hits_positive,
                context_negative=context_hits_negative,
                line_context=line,
            )

            candidates.append(candidate)

        return candidates

    def validate(self, match: str) -> tuple[bool, list[str]]:
        """
        Validación fuerte (DROP rules).

        Returns:
            (is_valid, list_of_validators_failed)
        """
        validators_failed = []

        # 1. Longitud exacta
        digits = self._extract_digits(match)
        if len(digits) != 10:
            validators_failed.append("length")

        # 2. Prefijo válido
        if not validate_colombian_prefix(match):
            validators_failed.append("valid_prefix")

        # 3. No es secuencia trivial (dígitos repetidos, secuencias)
        if is_technical_number(match):
            validators_failed.append("not_trivial")

        # 4. Detectar patrones sospechosos adicionales
        # (más de 6 dígitos iguales consecutivos)
        if len(digits) >= 10:
            for i in range(len(digits) - 5):
                if len(set(digits[i : i + 6])) == 1:
                    validators_failed.append("not_trivial")
                    break

        # Si falla cualquiera, DROP
        if validators_failed:
            return False, validators_failed

        return True, []

    def _extract_digits(self, value: str) -> str:
        """Extrae solo dígitos de una cadena."""
        return str(re.sub(r"[^\d]", "", value))

    def _extract_context_hits(
        self, line: str, start: int, end: int, keywords: set[str], window: int = 40
    ) -> list[str]:
        """
        Extrae palabras clave en ventana alrededor del match.

        Args:
            line: Línea completa
            start: Inicio del match
            end: Fin del match
            keywords: Conjunto de palabras a buscar
            window: Rango ±chars alrededor

        Returns:
            Lista de keywords encontradas (sin duplicados, ordenadas)
        """
        context_start = max(0, start - window)
        context_end = min(len(line), end + window)
        context = line[context_start:context_end].lower()

        hits = []
        for kw in keywords:
            # Busca palabra completa (con límites de palabra)
            if re.search(r"\b" + re.escape(kw) + r"\b", context):
                hits.append(kw)

        return sorted(list(set(hits)))

    def _get_validators_passed(
        self, normalized: str, validators_failed: list[str]
    ) -> list[str]:
        """
        Retorna lista de validadores que PASARON.

        El método validate() ya garantiza que si passed(), todos pasan.
        Esto es para reporte.
        """
        all_validators = ["length", "valid_prefix", "not_trivial"]
        return [v for v in all_validators if v not in validators_failed]

    def _mask_phone(self, phone_number: str) -> str:
        """
        Enmascara un número de teléfono.

        Mantiene prefijo visible, oculta núcleo:
        3001234567 → 300****567

        Args:
            phone_number: Número normalizado o con separadores

        Returns:
            Número enmascarado
        """
        digits = self._extract_digits(phone_number)

        if len(digits) < 4:
            return digits

        # Formato: primeros 3 (prefijo) + asteriscos + últimos 3
        if phone_number.startswith("+57"):
            return f"+57{digits[2:5]}****{digits[-3:]}"
        else:
            return f"{digits[:3]}****{digits[-3:]}"
