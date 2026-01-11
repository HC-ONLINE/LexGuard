"""
Regla de detección de tarjetas de crédito.
Soporta Visa, Mastercard y American Express con validación Luhn.
"""

import regex as re
from typing import Literal
from lexguard.core.rules.base import DetectionRule, Candidate
from lexguard.core.validators.luhn import validate_luhn
from lexguard.core.validators.entropy import is_high_entropy, looks_like_uuid


CardBrand = Literal["VISA", "MASTERCARD", "AMEX", "UNKNOWN"]


class CreditCardRule(DetectionRule):
    """
    Detectar números de tarjetas de crédito con validación estricta.

    Pipeline de validación:
    1. Coincidencia regex (formato básico)
    2. Verificación de longitud (específica de marca)
    3. Validación IIN/BIN (prefijo de marca)
    4. Algoritmo Luhn (obligatorio)
    5. Análisis de contexto (boost o penalización)
    6. Verificación de entropía (filtrar UUIDs/hashes)

    Condiciones de DROP (no reportado):
    - Luhn falla
    - Alta entropía (probablemente UUID/hash)
    - Contexto técnico (uuid, ref, hash, etc.)
    - Todos dígitos iguales
    """

    # Patrones de números de tarjeta (flexible con separadores)
    PATTERN = re.compile(
        r"\b"
        r"(?:"
        r"(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})"  # Prefijos IIN/BIN
        r"[\s\-]?"  # Separador opcional
        r"(?:\d{4}[\s\-]?){2,3}"  # Grupos de 4 dígitos
        r"\d{1,4}"  # Grupo final (3-4 dígitos)
        r")"
        r"\b",
        re.IGNORECASE,
    )

    # Palabras clave de contexto
    POSITIVE_CONTEXT = {
        # Contexto transaccional (fuerte, operacional)
        "payment",
        "transaction",
        "billing",
        "checkout",
        "purchase",
        "cvv",
        "exp",
        "pago",
        "transaccion",
        # Contexto descriptivo (débil, genérico)
        "card",
        "credit",
        "customer",
        "account",
        # Brands (informativo, ya cubierto por validadores)
        "visa",
        "mastercard",
        "amex",
        # Abbreviations
        "cc",
        # Español
        "tarjeta",
        "credito",
        "cliente",
        "cuenta",
    }

    NEGATIVE_CONTEXT = {
        "uuid",
        "guid",
        "ref",
        "reference",
        "id",
        "hash",
        "token",
        "key",
        "session",
        "test",
        "sample",
        "example",
        "dummy",
        "mock",
        "fake",
    }

    @property
    def pii_type(self) -> str:
        return "CREDIT_CARD"

    @property
    def display_name(self) -> str:
        return "Credit Card Number"

    def scan_line(self, line: str, line_number: int, file_path: str) -> list[Candidate]:
        """Escanear línea en busca de números de tarjetas de crédito"""
        candidates = []

        for match in self.PATTERN.finditer(line):
            raw_value = match.group(0)

            # Normalizar (eliminar separadores)
            normalized = self._normalize_card_number(raw_value)

            # Validación estricta (DROP si falla)
            is_valid, validators = self.validate(normalized)
            if not is_valid:
                # DROP — no crear Candidate
                continue

            # Verificación adicional de entropía
            if is_high_entropy(normalized, threshold=3.0) or looks_like_uuid(raw_value):
                # DROP — probablemente no es una tarjeta real
                continue

            # Extraer contexto
            context = self.extract_context(line, match.start(), match.end())
            positive_ctx, negative_ctx = self.analyze_context(context)

            # DROP si contexto negativo fuerte
            if negative_ctx and not positive_ctx:
                continue

            # Crear Candidate
            candidate = Candidate(
                pii_type=self.pii_type,
                raw_value=raw_value,
                masked_value=self.mask_value(normalized),
                file=file_path,
                line_number=line_number,
                validators_passed=validators,
                validators_failed=[],
                context_hits=positive_ctx,
                context_negative=negative_ctx,
                line_context=context,
            )

            candidates.append(candidate)

        return candidates

    def validate(self, match: str) -> tuple[bool, list[str]]:
        """
        Validar número de tarjeta de crédito.

        Todas las verificaciones deben pasar o la coincidencia es DROPPED.
        """
        # Alineamos el nombre del parámetro con la firma base
        card_number = match

        validators = []

        # 1. Verificación de longitud
        length_valid = len(card_number) in [13, 15, 16]
        if not length_valid:
            return False, []

        # 2. Detectar marca
        brand = self._detect_brand(card_number)
        if brand == "UNKNOWN":
            return False, []
        validators.append(f"brand_{brand.lower()}")

        # 3. Longitud específica de marca
        if not self._validate_brand_length(card_number, brand):
            return False, []

        # 4. Verificación Luhn (OBLIGATORIA)
        if not validate_luhn(card_number):
            return False, []
        validators.append("luhn")

        # 5. Rechazar todos-dígitos-iguales
        if len(set(card_number)) == 1:
            return False, []

        # 6. Rechazar secuencial
        if self._is_sequential(card_number):
            return False, []

        return True, validators

    def analyze_context(self, context: str) -> tuple[list[str], list[str]]:
        """Analizar contexto para pistas semánticas"""
        context_lower = context.lower()

        positive = [kw for kw in self.POSITIVE_CONTEXT if kw in context_lower]
        negative = [kw for kw in self.NEGATIVE_CONTEXT if kw in context_lower]

        return positive, negative

    def mask_value(self, value: str) -> str:
        """Enmascarar número de tarjeta: mostrar primeros 4 y últimos 4"""
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"

    # Métodos auxiliares

    def _normalize_card_number(self, raw: str) -> str:
        """Eliminar espacios, guiones y otros separadores"""
        return "".join(c for c in raw if c.isdigit())

    def _detect_brand(self, card_number: str) -> CardBrand:
        """Detectar marca de tarjeta desde prefijo IIN/BIN"""
        if card_number.startswith("4"):
            return "VISA"
        elif card_number[:2] in ["51", "52", "53", "54", "55"]:
            return "MASTERCARD"
        elif card_number[:2] in ["34", "37"]:
            return "AMEX"
        else:
            return "UNKNOWN"

    def _validate_brand_length(self, card_number: str, brand: CardBrand) -> bool:
        """Validar que la longitud coincida con especificaciones de marca"""
        length = len(card_number)

        if brand == "VISA":
            return length in [13, 16]
        elif brand == "MASTERCARD":
            return length == 16
        elif brand == "AMEX":
            return length == 15

        return False

    def _is_sequential(self, card_number: str) -> bool:
        """Verificar si los dígitos son estrictamente secuenciales"""
        if len(card_number) < 4:
            return False

        # Verificar si todos los dígitos consecutivos incrementan en 1 (mod 10)
        for i in range(len(card_number) - 1):
            if int(card_number[i + 1]) != (int(card_number[i]) + 1) % 10:
                return False

        return True
