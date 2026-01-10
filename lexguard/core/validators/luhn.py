"""
Implementación del algoritmo Luhn para validación de tarjetas de crédito.
https://en.wikipedia.org/wiki/Luhn_algorithm
"""


def validate_luhn(card_number: str) -> bool:
    """
    Validar un número de tarjeta de crédito usando el algoritmo Luhn.

    El algoritmo Luhn (algoritmo mod-10):
    1. Comenzando desde el dígito más a la derecha (excluyendo dígito de verificación),
       duplicar cada segundo dígito
    2. Si duplicar resulta en un número de dos dígitos, sumar esos dígitos
    3. Sumar todos los dígitos
    4. Si el total mod 10 es igual a 0, el número es válido

    Args:
        card_number: Cadena de dígitos (espacios/guiones eliminados)

    Returns:
        True si es válido, False en caso contrario

    Examples:
        >>> validate_luhn("4532015112830366")  # Visa válida
        True
        >>> validate_luhn("1234567812345678")  # Inválida
        False
    """
    # Eliminar cualquier carácter que no sea dígito
    digits = [int(d) for d in card_number if d.isdigit()]

    if len(digits) < 13:
        return False

    # Invertir para procesamiento más fácil (trabajar de derecha a izquierda)
    digits = digits[::-1]

    checksum = 0

    for idx, digit in enumerate(digits):
        if (
            idx % 2 == 1
        ):  # Cada segundo dígito (indexado en 0, por lo tanto índices impares)
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit

    return checksum % 10 == 0


def validate_luhn_batch(card_numbers: list[str]) -> dict[str, bool]:
    """
    Validar múltiples números de tarjeta eficientemente.

    Args:
        card_numbers: Lista de cadenas de números de tarjeta

    Returns:
        Dict mapeando número_de_tarjeta -> es_válida
    """
    return {num: validate_luhn(num) for num in card_numbers}
