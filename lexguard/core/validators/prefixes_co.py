"""
Validación de prefijos de teléfono móvil colombiano.
Prefijos móviles válidos: 300-399
"""

# Prefijos de teléfono móvil colombiano (actualizados a 2024)
# Fuente: Regulaciones del Ministerio TIC de Colombia
VALID_PREFIXES = set(range(300, 400))  # 300-399


def validate_colombian_prefix(phone_number: str) -> bool:
    """
    Validar si un número de teléfono colombiano tiene un prefijo
    móvil válido.

    Formato de móvil colombiano:
    - Código de país: +57
    - Prefijo móvil: 300-399 (3 dígitos)
    - Número de suscriptor: 7 dígitos
    - Total: 10 dígitos después del código de país

    Args:
        phone_number: Cadena de número de teléfono
        (puede incluir +57, espacios, guiones)

    Returns:
        True si el prefijo es válido, False en caso contrario

    Examples:
        >>> validate_colombian_prefix("+573001234567")
        True
        >>> validate_colombian_prefix("+572001234567")  # Línea fija
        False
        >>> validate_colombian_prefix("+574991234567")  # Prefijo inválido
        False
    """
    # Extraer solo dígitos
    digits = "".join(c for c in phone_number if c.isdigit())

    # Eliminar código de país si está presente
    if digits.startswith("57"):
        digits = digits[2:]

    # Debe ser exactamente 10 dígitos
    if len(digits) != 10:
        return False

    # Extraer prefijo (primeros 3 dígitos)
    try:
        prefix = int(digits[:3])
    except ValueError:
        return False

    return prefix in VALID_PREFIXES


def extract_prefix(phone_number: str) -> int | None:
    """
    Extraer el prefijo móvil de un número de teléfono colombiano.

    Args:
        phone_number: Cadena de número de teléfono

    Returns:
        Prefijo como entero, o None si el formato es inválido
    """
    digits = "".join(c for c in phone_number if c.isdigit())

    if digits.startswith("57"):
        digits = digits[2:]

    if len(digits) != 10:
        return None

    try:
        return int(digits[:3])
    except ValueError:
        return None


def is_technical_number(phone_number: str) -> bool:
    """
    Detectar si un número de teléfono parece un número técnico/de prueba.

    Números técnicos a rechazar:
    - Todo el mismo dígito: 3000000000
    - Secuencial: 3001234567
    - Patrones de prueba comunes

    Args:
        phone_number: Cadena de número de teléfono

    Returns:
        True si probablemente es un número técnico
    """
    digits = "".join(c for c in phone_number if c.isdigit())

    if digits.startswith("57"):
        digits = digits[2:]

    if len(digits) != 10:
        return False

    # Todo el mismo dígito
    if len(set(digits)) == 1:
        return True

    # Estrictamente secuencial
    is_sequential = all(
        int(digits[i + 1]) == (int(digits[i]) + 1) % 10 for i in range(len(digits) - 1)
    )

    return is_sequential
