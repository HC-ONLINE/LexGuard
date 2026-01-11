"""
Motor del scanner que orquesta detección, validación y puntuación.
"""

from pathlib import Path
from typing import Iterator, Sequence
from lexguard.core.ingestion.file_stream import FileStream
from lexguard.core.rules.base import DetectionRule, Candidate, Finding
from lexguard.core.scoring.confidence import ConfidenceScorer
from lexguard.core.scoring.risk import RiskScorer


class Scanner:
    """
    Motor de escaneo principal.

    Orquesta:
    1. Ingestión de archivos (streaming)
    2. Aplicación de reglas (detección)
    3. Puntuación de confianza
    4. Evaluación de riesgo
    5. Generación de hallazgos
    """

    def __init__(self, rules: Sequence[DetectionRule]):
        """
        Args:
            rules: List of detection rules to apply
        """
        self.rules = rules
        self.file_stream = FileStream()
        self.confidence_scorer = ConfidenceScorer()
        self.risk_scorer = RiskScorer()

        # Estadísticas
        self.total_files = 0
        self.total_lines = 0

    def scan_path(self, path: Path, recursive: bool = True) -> Iterator[Finding]:
        """
        Escanear un archivo o directorio.

        Args:
            path: Ruta a escanear
            recursive: Recurrir en subdirectorios

        Yields:
            Objetos Finding
        """
        # Recolectar archivos
        files = list(self.file_stream.collect_files(path, recursive=recursive))
        self.total_files = len(files)

        # Escanear cada archivo
        for file_path in files:
            yield from self.scan_file(file_path)

    def scan_file(self, file_path: Path) -> Iterator[Finding]:
        """
        Escanear un único archivo.

        Args:
            file_path: Ruta del archivo

        Yields:
            Objetos Finding
        """
        try:
            # Streaming de líneas
            for line_num, line in self.file_stream.stream_lines(file_path):
                self.total_lines += 1

                # Aplicar todas las reglas a esta línea
                for rule in self.rules:
                    candidates = rule.scan_line(line, line_num, str(file_path))

                    # Evaluar cada candidato
                    for candidate in candidates:
                        finding = self._evaluate_candidate(candidate)
                        yield finding

        except Exception as e:
            # Registrar error pero continuar escaneando
            print(f"Warning: Failed to scan {file_path}: {e}")

    def _evaluate_candidate(self, candidate: Candidate) -> Finding:
        """
        Evaluar un candidato: puntuar confianza y riesgo.

        Args:
            candidate: Candidato de PII

        Returns:
            Finding con puntajes
        """
        # Calcular confianza
        confidence, classification, conf_reasons = self.confidence_scorer.score(
            candidate
        )

        # Calcular riesgo
        risk, risk_reasons = self.risk_scorer.score(candidate, confidence)

        return Finding(
            candidate=candidate,
            confidence=confidence,
            classification=classification,
            risk=risk,
            confidence_reasons=conf_reasons,
            risk_reasons=risk_reasons,
        )

    def get_statistics(self) -> dict[str, int]:
        """Obtener estadísticas de escaneo"""
        return {"total_files": self.total_files, "total_lines": self.total_lines}
