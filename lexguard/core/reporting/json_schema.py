"""
Esquema JSON y modelos Pydantic para generación de reportes.
Proporciona formato de salida fuertemente tipado y versionado.
"""

from datetime import datetime
from typing import Literal, Any, Optional
from pathlib import Path
from pydantic import BaseModel, Field, field_validator


class CandidateSchema(BaseModel):
    """Esquema para candidato de PII (solo evidencia)"""

    pii_type: str = Field(..., description="Type of PII detected")
    masked_value: str = Field(..., description="Masked value for display")
    file: str = Field(..., description="Relative file path")
    line_number: int = Field(..., ge=1, description="Line number (1-indexed)")
    validators_passed: list[str] = Field(
        default_factory=list, description="Validators that passed"
    )
    context_hits: list[str] = Field(
        default_factory=list, description="Positive context keywords"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "pii_type": "CREDIT_CARD",
                "masked_value": "4532************0366",
                "file": "logs/transactions.log",
                "line_number": 42,
                "validators_passed": ["luhn", "brand_visa"],
                "context_hits": ["payment", "card"],
            }
        }
    }


class FindingSchema(BaseModel):
    """Esquema para hallazgo de PII evaluado"""

    pii_type: str = Field(..., description="Type of PII")
    classification: Literal["FOUND", "UNCERTAIN", "IGNORED"] = Field(
        ..., description="Detection confidence level"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score (0.0-1.0)"
    )
    risk: Literal["LOW", "MEDIUM", "HIGH"] = Field(..., description="Risk level")

    # Location
    file: str = Field(..., description="Relative file path")
    line_number: int = Field(..., ge=1, description="Line number")
    masked_value: str = Field(..., description="Masked PII value")

    # Justification
    confidence_reasons: list[str] = Field(
        default_factory=list, description="Why this confidence score"
    )
    risk_reasons: list[str] = Field(
        default_factory=list, description="Why this risk level"
    )

    # Validation
    validators_passed: list[str] = Field(
        default_factory=list, description="Semantic validators passed"
    )
    context_hits: list[str] = Field(
        default_factory=list, description="Positive context keywords found"
    )

    # AI classification (optional)
    ai_assisted: bool = Field(
        default=False, description="Whether AI was used for classification"
    )
    ai_sensitive: Optional[bool] = Field(
        default=None, description="AI classification result (if assisted)"
    )
    ai_reason: Optional[str] = Field(
        default=None, description="AI classification reason (if assisted)"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "pii_type": "CREDIT_CARD",
                "classification": "FOUND",
                "confidence": 0.95,
                "risk": "HIGH",
                "file": "backups/db_dump.sql",
                "line_number": 1523,
                "masked_value": "4532************0366",
                "confidence_reasons": ["luhn_valid", "semantic_context_payment"],
                "risk_reasons": ["file_in_backup", "high_confidence"],
                "validators_passed": ["luhn", "brand_visa"],
                "context_hits": ["card", "payment"],
            }
        }
    }


class SummarySchema(BaseModel):
    """Estadísticas agregadas"""

    total_files_scanned: int = Field(..., ge=0)
    total_lines_scanned: int = Field(..., ge=0)
    total_findings: int = Field(..., ge=0)

    # By classification
    found_count: int = Field(..., ge=0, description="High-confidence detections")
    uncertain_count: int = Field(..., ge=0, description="Medium-confidence detections")
    ignored_count: int = Field(..., ge=0, description="Low-confidence detections")

    # By risk
    high_risk_count: int = Field(..., ge=0)
    medium_risk_count: int = Field(..., ge=0)
    low_risk_count: int = Field(..., ge=0)

    # Overall risk
    overall_risk: Literal["LOW", "MEDIUM", "HIGH"] = Field(
        default="LOW", description="Riesgo general agregado"
    )

    # Cross-PII exposure
    exposure_level: Literal["SINGLE", "COMBINED", "CRITICAL"] = Field(
        default="SINGLE",
        description="Nivel de exposición por coexistencia de tipos de PII",
    )
    pii_types_detected: list[str] = Field(
        default_factory=list, description="Tipos de PII detectados en el escaneo"
    )

    # By type
    findings_by_type: dict[str, int] = Field(
        default_factory=dict, description="Count per PII type"
    )

    # Performance
    scan_duration_seconds: float = Field(..., ge=0)


class MetadataSchema(BaseModel):
    """Metadatos de escaneo"""

    version: str = Field(default="1.0.0", description="Versión de LexGuard")
    schema_version: str = Field(
        default="v1", description="Versión del esquema de reporte"
    )
    scan_timestamp: str = Field(..., description="Timestamp ISO 8601")
    scan_path: str = Field(..., description="Ruta raíz escaneada")
    confidence_threshold: float = Field(
        ..., ge=0.0, le=1.0, description="Umbral de confianza usado"
    )

    @field_validator("scan_timestamp")
    @classmethod
    def validate_iso_format(cls, v: str) -> str:
        """Asegurar que timestamp es ISO 8601 válido"""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("scan_timestamp must be ISO 8601 format")
        return v


class ScanReportSchema(BaseModel):
    """Reporte de escaneo completo (esquema raíz)"""

    metadata: MetadataSchema = Field(..., description="Scan metadata")
    summary: SummarySchema = Field(..., description="Aggregated statistics")
    findings: list[FindingSchema] = Field(
        default_factory=list, description="Detailed findings"
    )

    model_config = {
        "json_schema_extra": {
            "title": "LexGuard PII Scan Report",
            "description": "Schema v1 for LexGuard PII detection reports",
        }
    }

    def to_json_file(self, output_path: Path) -> None:
        """Escribir reporte a archivo JSON"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))

    def has_high_risk_findings(self) -> bool:
        """Verificar si existen hallazgos de riesgo HIGH"""
        return self.summary.high_risk_count > 0

    def get_findings_by_file(self) -> dict[str, list[FindingSchema]]:
        """Agrupar hallazgos por archivo"""
        grouped: dict[str, list[FindingSchema]] = {}
        for finding in self.findings:
            if finding.file not in grouped:
                grouped[finding.file] = []
            grouped[finding.file].append(finding)
        return grouped


# Export schema as JSON Schema for external validation
def export_json_schema() -> dict[str, Any]:
    """
    exportar esquema Pydantic como JSON Schema (formato OpenAPI).
    Útil para validación externa o documentación.
    """
    return ScanReportSchema.model_json_schema()
