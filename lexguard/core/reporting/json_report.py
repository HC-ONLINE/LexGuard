"""
Utilidades de generación de reportes y enmascaramiento.
"""

from datetime import datetime
from lexguard.core.rules.base import Finding
from lexguard.core.scoring.risk import RiskAggregator
from lexguard.core.reporting.json_schema import (
    ScanReportSchema,
    MetadataSchema,
    SummarySchema,
    FindingSchema,
)


class ReportGenerator:
    """
    Generar reportes estructurados desde hallazgos de escaneo.

    Responsabilidades:
    - Convertir objetos Finding a esquema
    - Calcular estadísticas de resumen
    - Formatear salida (JSON/Markdown)
    - Aplicar reglas de enmascaramiento
    """

    def __init__(self, scan_path: str, confidence_threshold: float = 0.8):
        self.scan_path = scan_path
        self.confidence_threshold = confidence_threshold
        self.scan_start_time = datetime.now()

    def generate_report(
        self, findings: list[Finding], total_files: int, total_lines: int
    ) -> ScanReportSchema:
        """
        Generar reporte de escaneo completo.

        Args:
            findings: Lista de hallazgos evaluados
            total_files: Número de archivos escaneados
            total_lines: Total de líneas procesadas

        Returns:
            Reporte estructurado
        """
        # Calcular duración
        duration = (datetime.now() - self.scan_start_time).total_seconds()

        # Convertir hallazgos a esquema
        finding_schemas = [self._finding_to_schema(f) for f in findings]

        # Generar resumen
        summary = self._generate_summary(
            findings=findings,
            total_files=total_files,
            total_lines=total_lines,
            duration=duration,
        )

        # Generar metadatos
        metadata = MetadataSchema(
            scan_timestamp=datetime.now().isoformat() + "Z",
            scan_path=self.scan_path,
            confidence_threshold=self.confidence_threshold,
        )

        return ScanReportSchema(
            metadata=metadata, summary=summary, findings=finding_schemas
        )

    def _finding_to_schema(self, finding: Finding) -> FindingSchema:
        """Convertir Finding a esquema"""
        # Extraer información de IA si existe
        ai_assisted = finding.ai_result is not None
        ai_sensitive = finding.ai_result.is_sensitive if finding.ai_result else None
        ai_reason = finding.ai_result.reason if finding.ai_result else None

        return FindingSchema(
            pii_type=finding.candidate.pii_type,
            classification=finding.classification,
            confidence=finding.confidence,
            risk=finding.risk,
            file=finding.candidate.file,
            line_number=finding.candidate.line_number,
            masked_value=finding.candidate.masked_value,
            confidence_reasons=finding.confidence_reasons,
            risk_reasons=finding.risk_reasons,
            validators_passed=finding.candidate.validators_passed,
            context_hits=finding.candidate.context_hits,
            ai_assisted=ai_assisted,
            ai_sensitive=ai_sensitive,
            ai_reason=ai_reason,
        )

    def _generate_summary(
        self,
        findings: list[Finding],
        total_files: int,
        total_lines: int,
        duration: float,
    ) -> SummarySchema:
        """Generar estadísticas de resumen"""
        # Count by classification
        found_count = sum(1 for f in findings if f.classification == "FOUND")
        uncertain_count = sum(1 for f in findings if f.classification == "UNCERTAIN")
        ignored_count = sum(1 for f in findings if f.classification == "IGNORED")

        # Count by risk
        high_risk = sum(1 for f in findings if f.risk == "HIGH")
        medium_risk = sum(1 for f in findings if f.risk == "MEDIUM")
        low_risk = sum(1 for f in findings if f.risk == "LOW")

        # Count by type
        by_type: dict[str, int] = {}
        for finding in findings:
            pii_type = finding.candidate.pii_type
            by_type[pii_type] = by_type.get(pii_type, 0) + 1

        # Calculate cross-PII exposure
        candidates = [f.candidate for f in findings]
        exposure = RiskAggregator.calculate_exposure(candidates)
        pii_types = sorted(set(f.candidate.pii_type for f in findings))

        # Calculate overall risk (with exposure adjustment)
        findings_with_risk = [(f.candidate, f.risk) for f in findings]
        overall_risk = RiskAggregator.calculate_overall_risk(
            findings_with_risk, exposure
        )

        return SummarySchema(
            total_files_scanned=total_files,
            total_lines_scanned=total_lines,
            total_findings=len(findings),
            found_count=found_count,
            uncertain_count=uncertain_count,
            ignored_count=ignored_count,
            high_risk_count=high_risk,
            medium_risk_count=medium_risk,
            low_risk_count=low_risk,
            overall_risk=overall_risk,
            exposure_level=exposure.value,
            pii_types_detected=pii_types,
            findings_by_type=by_type,
            scan_duration_seconds=round(duration, 2),
        )

    def generate_markdown(self, report: ScanReportSchema) -> str:
        """
        Generar reporte Markdown legible para humanos.

        Args:
            report: Reporte estructurado

        Returns:
            String Markdown
        """
        lines = [
            "# Reporte de Escaneo PII - LexGuard",
            "",
            f"**Ruta Escaneada:** `{report.metadata.scan_path}`",
            f"**Fecha:** {report.metadata.scan_timestamp}",
            f"**Duración:** {report.summary.scan_duration_seconds}s",
            "",
            "## Resumen",
            "",
            f"- **Archivos Escaneados:** {report.summary.total_files_scanned}",
            f"- **Líneas Escaneadas:** {report.summary.total_lines_scanned:,}",
            f"- **Total Hallazgos:** {report.summary.total_findings}",
            "",
            "### Evaluación de Riesgo",
            "",
            f"- **Riesgo General:** {report.summary.overall_risk}",
            f"- **Exposición Cross-PII:** {report.summary.exposure_level}",
            f"""- **Tipos de PII Detectados:**
            {', '.join(report.summary.pii_types_detected)}""",
            "",
            "### Por Clasificación",
            "",
            f"- **ENCONTRADO:** {report.summary.found_count} (alta confianza)",
            f"- **INCIERTO:** {report.summary.uncertain_count} (confianza media)",
            f"- **IGNORADO:** {report.summary.ignored_count} (baja confianza)",
            "",
            "### Por Nivel de Riesgo",
            "",
            f"- **ALTO:** {report.summary.high_risk_count}",
            f"- **MEDIO:** {report.summary.medium_risk_count}",
            f"- **BAJO:** {report.summary.low_risk_count}",
            "",
            "### Por Tipo de PII",
            "",
        ]

        for pii_type, count in sorted(report.summary.findings_by_type.items()):
            lines.append(f"- **{pii_type}:** {count}")

        lines.extend(["", "## Hallazgos Detallados", ""])

        # Group by file
        by_file = report.get_findings_by_file()

        for file_path in sorted(by_file.keys()):
            file_findings = by_file[file_path]
            lines.append(f"### `{file_path}`")
            lines.append("")

            for finding in file_findings:
                risk_label = {"HIGH": "[ALTO]", "MEDIUM": "[MEDIO]", "LOW": "[BAJO]"}[
                    finding.risk
                ]
                lines.append(
                    f"- **Línea {finding.line_number}** {risk_label} "
                    f"`{finding.pii_type}` → `{finding.masked_value}` "
                    f"(confianza: {finding.confidence:.2f})"
                )

            lines.append("")

        return "\n".join(lines)
