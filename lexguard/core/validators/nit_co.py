"""
Validador del dígito de verificación para NIT colombiano.

El NIT (Número de Identificación Tributaria) colombiano tiene
9 dígitos base + 1 dígito verificador.

Algoritmo oficial DIAN:
  - Multiplicar cada dígito por los factores: 41,37,29,23,19,17,13,7,3
  - Sumar todos los productos
  - Calcular el residuo módulo 11
  - Residuo 0 → dígito = 0
  - Residuo 1 → dígito = 1
  - Residuo ≥2 → dígito = 11 - residuo
"""

# Factores para el cálculo del dígito de verificación (posición 1..9 → izq→der)
_NIT_FACTORS = [41, 37, 29, 23, 19, 17, 13, 7, 3]


def compute_check_digit(nit_digits: str) -> int:
    """
    Calcular el dígito verificador esperado para un NIT de 9 dígitos.

    Args:
        nit_digits: Exactamente 9 dígitos numéricos
        (sin separadores, sin dígito verificador)

    Returns:
        Dígito verificador calculado (0-9)

    Raises:
        ValueError: Si nit_digits no tiene exactamente 9 dígitos numéricos
    """
    if len(nit_digits) != 9 or not nit_digits.isdigit():
        raise ValueError(
            f"nit_digits debe tener exactamente 9 dígitos; recibido: {nit_digits!r}"
        )

    total = sum(int(d) * f for d, f in zip(nit_digits, _NIT_FACTORS))
    remainder = total % 11

    if remainder <= 1:
        return remainder
    return 11 - remainder


def validate_nit(nit_digits: str, check_digit: int | str) -> bool:
    """
    Verificar si el dígito verificador es correcto para un NIT dado.

    Args:
        nit_digits: 9 dígitos del NIT (sin separadores ni dígito verificador)
        check_digit: Dígito verificador a validar (int o str de un solo carácter)

    Returns:
        True si el dígito verificador es correcto, False en caso contrario
    """
    try:
        expected = compute_check_digit(nit_digits)
        return expected == int(check_digit)
    except (ValueError, TypeError):
        return False
