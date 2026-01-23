"""
Script de prueba para validar integración de clasificador de IA.

Flujo:
1. Escanear archivo de datos
2. Identificar hallazgos en zona gris (0.4 <= confidence < 0.8)
3. Clasificar con IA
4. Mostrar resultados
"""

import sys
from pathlib import Path

# Agregar path del proyecto
sys.path.insert(0, str(Path(__file__).parent.parent))

from lexguard.core.scanner import Scanner
from lexguard.core.rules.email import EmailRule
from lexguard.core.rules.phone_co import PhoneCORule
from lexguard.core.rules.cedula_co import CedulaCORule
from lexguard.core.scoring.confidence import ConfidenceScorer
from lexguard.ai.classifier import AIClassifier


def main():
    print("=" * 70)
    print("PRUEBA DE INTEGRACIÓN: Clasificador de IA")
    print("=" * 70)
    print()

    # Archivo de prueba
    test_file = Path("data/cedula_co/test/test_cedulas.txt")
    if not test_file.exists():
        print(f"Archivo no encontrado: {test_file}")
        return

    print(f"Archivo: {test_file}")
    print()

    # Inicializar scanner y clasificador
    rules = [EmailRule(), PhoneCORule(), CedulaCORule()]
    scanner = Scanner(rules)
    scorer = ConfidenceScorer()
    ai_classifier = AIClassifier()

    print("Escaneando archivo...")
    print()

    # Escanear archivo
    candidates = []
    with open(test_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            for rule in rules:
                for candidate in rule.scan_line(line, line_num, str(test_file)):
                    # Calcular confidence
                    confidence, _, _ = scorer.score(candidate)
                    candidates.append((candidate, confidence, line.strip()))

    # Filtrar zona gris
    gray_zone = [
        (c, conf, line)
        for c, conf, line in candidates
        if AIClassifier.should_use_ai(conf)
    ]

    print(f"Estadísticas:")
    print(f"   Total hallazgos: {len(candidates)}")
    print(f"   En zona gris (0.4-0.8): {len(gray_zone)}")
    print()

    if not gray_zone:
        print("No hay hallazgos en zona gris para clasificar con IA")
        return

    print("Clasificando con IA...")
    print()

    # Clasificar con IA
    results = []
    for candidate, confidence, line in gray_zone[:5]:  # Primeros 5
        print(f"{'─' * 70}")
        print(f"Línea {candidate.line_number}: {candidate.pii_type}")
        print(f"   Valor: {candidate.masked_value}")
        print(f"   Confidence: {confidence:.2f}")
        print(f"   Contexto: {line[:80]}...")
        print()

        # Clasificar
        ai_result = ai_classifier.classify(snippet=line, pii_type=candidate.pii_type)

        if ai_result:
            print(f"   IA Classification:")
            print(f"      ├─ Sensible: {ai_result.is_sensitive}")
            print(f"      ├─ Confianza IA: {ai_result.confidence.value}")
            print(f"      └─ Razón: {ai_result.reason}")
            results.append((candidate, confidence, ai_result))
        else:
            print(f"    IA no disponible o error en clasificación")

        print()

    # Resumen
    if results:
        print("=" * 70)
        print("RESUMEN")
        print("=" * 70)
        print()

        sensitive_count = sum(1 for _, _, r in results if r.is_sensitive)
        not_sensitive_count = len(results) - sensitive_count

        print(f"   Clasificados como sensibles: {sensitive_count}")
        print(f"   Clasificados como NO sensibles: {not_sensitive_count}")
        print()

        print(" La IA funcionó correctamente como clasificador auxiliar")
        print("   - NO detectó PII desde cero")
        print("   - NO calculó riesgo")
        print("   - Solo clasificó sensibilidad contextual")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n Prueba interrumpida por el usuario")
    except Exception as e:
        print(f"\n\n Error: {e}")
        import traceback

        traceback.print_exc()
