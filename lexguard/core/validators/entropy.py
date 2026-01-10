"""
Cálculo simple de entropía para detectar cadenas de apariencia aleatoria.
Usado para filtrar UUIDs, hashes y otros datos no-PII de alta entropía.
"""

import math
from collections import Counter


def calculate_shannon_entropy(text: str) -> float:
    """
    Calcular la entropía de Shannon de una cadena.

    Mayor entropía = distribución más aleatoria/uniforme de caracteres.

    Fórmula de entropía de Shannon:
    H(X) = -Σ p(x) * log₂(p(x))

    Args:
        text: Cadena a analizar

    Returns:
        Valor de entropía (típicamente 0-8 para texto)
        Valores más altos indican mayor aleatoriedad

    Examples:
        >>> calculate_shannon_entropy("aaaaaaa")  # Baja entropía
        0.0
        >>> calculate_shannon_entropy("abc123")  # Media
        ~2.5
        >>> calculate_shannon_entropy("x7k2p9m1")  # Alta
        ~3.0
    """
    if not text:
        return 0.0

    # Contar frecuencias de caracteres
    counter = Counter(text)
    length = len(text)

    # Calcular probabilidades y entropía
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(text: str, threshold: float = 3.5) -> bool:
    """
    Verificar si una cadena tiene entropía sospechosamente alta.

    Las cadenas de alta entropía probablemente son:
    - UUIDs
    - Hashes
    - Tokens aleatorios
    - Datos codificados en Base64

    Args:
        text: Cadena a verificar
        threshold: Umbral de entropía (por defecto 3.5 es conservador)

    Returns:
        True si la entropía excede el umbral
    """
    return calculate_shannon_entropy(text) > threshold


def contains_hex_pattern(text: str, min_length: int = 8) -> bool:
    """
    Detectar si el texto parece codificación hexadecimal.

    Args:
        text: Cadena a verificar
        min_length: Longitud mínima a considerar

    Returns:
        True si parece hexadecimal
    """
    if len(text) < min_length:
        return False

    hex_chars = set("0123456789abcdefABCDEF")
    text_chars = set(text)

    # Si >80% de caracteres son dígitos hexadecimales, probablemente codificado en hex
    hex_ratio = len(text_chars & hex_chars) / len(text_chars) if text_chars else 0

    return hex_ratio > 0.8


def looks_like_uuid(text: str) -> bool:
    """
    Detectar patrones similares a UUID.

    Los UUIDs siguen el patrón: 8-4-4-4-12 dígitos hexadecimales
    Ejemplo: 550e8400-e29b-41d4-a716-446655440000

    Args:
        text: Cadena a verificar

    Returns:
        True si parece un UUID
    """
    # Eliminar separadores comunes de UUID
    cleaned = text.replace("-", "").replace("_", "")

    # Verificar longitud y contenido hexadecimal
    if len(cleaned) != 32:
        return False

    return contains_hex_pattern(cleaned, min_length=32)
