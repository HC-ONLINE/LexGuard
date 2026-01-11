"""
CLI de LexGuard — Punto de entrada principal.
"""

from pathlib import Path
from typing import Optional
import typer
from typing_extensions import Annotated

from lexguard import __version__
from lexguard.core.scanner import Scanner
from lexguard.core.rules.credit_card import CreditCardRule
from lexguard.core.reporting.json_report import ReportGenerator


app = typer.Typer(
    name="lexguard",
    help="Escáner de PII para datos colombianos con validación semántica",
    add_completion=False,
)


def version_callback(value: bool):
    """Mostrar versión y salir"""
    if value:
        typer.echo(f"LexGuard v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            callback=version_callback,
            is_eager=True,
            help="Mostrar versión y salir",
        ),
    ] = None
):
    """LexGuard — Escáner de PII para datos colombianos"""
    pass


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(
            help="Archivo o directorio a escanear", exists=True, resolve_path=True
        ),
    ],
    format: Annotated[
        str, typer.Option("--format", "-f", help="Formato de salida (json o md)")
    ] = "json",
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o", help="Ruta del archivo de salida (por defecto: stdout)"
        ),
    ] = None,
    confidence_threshold: Annotated[
        float,
        typer.Option(
            "--confidence-threshold",
            "-c",
            help="Confianza mínima para reportar (0.0-1.0)",
            min=0.0,
            max=1.0,
        ),
    ] = 0.8,
    mask_output: Annotated[
        bool, typer.Option("--mask-output", help="Enmascarar valores PII en la salida")
    ] = True,
    fail_on_high_risk: Annotated[
        bool,
        typer.Option(
            "--fail-on-high-risk",
            help="Salir con código de error si existen hallazgos de ALTO riesgo",
        ),
    ] = False,
    recursive: Annotated[
        bool,
        typer.Option(
            "--recursive/--no-recursive",
            "-r",
            help="Buscar recursivamente en subdirectorios",
        ),
    ] = True,
):
    """
    Escanear archivos en busca de PII colombiana.

    Ejemplos:

        # Escanear un directorio
        lexguard scan ./data

        # Salida en JSON a archivo
        lexguard scan ./logs --format json --output reporte.json

        # Fallar CI si hay ALTO riesgo
        lexguard scan ./backups --fail-on-high-risk

        # Ajustar umbral de confianza
        lexguard scan ./code --confidence-threshold 0.9
    """
    # Validar formato
    if format not in ["json", "md"]:
        typer.echo(f"Error: Formato inválido '{format}'. Use 'json' o 'md'.", err=True)
        raise typer.Exit(1)

    # Inicializar scanner con reglas
    rules = [
        CreditCardRule(),
        # Añadir más reglas según se implementen
    ]
    scanner = Scanner(rules)

    # Inicializar generador de reportes
    report_gen = ReportGenerator(
        scan_path=str(path), confidence_threshold=confidence_threshold
    )

    typer.echo(f"Escaneando: {path}")
    typer.echo(f"Umbral de confianza: {confidence_threshold}")
    typer.echo("")

    # Escanear y recolectar hallazgos
    findings = []
    try:
        for finding in scanner.scan_path(path, recursive=recursive):
            # Aplicar filtro de umbral de confianza
            if finding.confidence >= confidence_threshold:
                findings.append(finding)

    except KeyboardInterrupt:
        typer.echo("\nEscaneo interrumpido por el usuario", err=True)
        raise typer.Exit(130)

    except Exception as e:
        typer.echo(f"\nError durante el escaneo: {e}", err=True)
        raise typer.Exit(1)

    # Obtener estadísticas
    stats = scanner.get_statistics()

    # Generar reporte
    report = report_gen.generate_report(
        findings=findings,
        total_files=stats["total_files"],
        total_lines=stats["total_lines"],
    )

    # Generar salida del reporte
    if format == "json":
        if output:
            report.to_json_file(output)
            typer.echo(f"Reporte escrito en: {output}")
        else:
            typer.echo(report.model_dump_json(indent=2))

    elif format == "md":
        md_content = report_gen.generate_markdown(report)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(md_content)
            typer.echo(f"Reporte escrito en: {output}")
        else:
            typer.echo(md_content)

    # Imprimir resumen a stderr (no interfiere con redirección stdout)
    typer.echo("", err=True)
    typer.echo("=" * 50, err=True)
    typer.echo(
        f"Escaneo completo: {stats['total_files']} archivos, "
        f"{stats['total_lines']:,} líneas",
        err=True,
    )
    typer.echo(
        f"Hallazgos: {report.summary.total_findings} "
        f"({report.summary.found_count} alta confianza)",
        err=True,
    )
    typer.echo(
        f"Riesgo: ALTO {report.summary.high_risk_count} | "
        f"MEDIO {report.summary.medium_risk_count} | "
        f"BAJO {report.summary.low_risk_count}",
        err=True,
    )
    typer.echo("=" * 50, err=True)

    # Integración CI/CD: fallar si se solicitó y hay riesgo ALTO
    if fail_on_high_risk and report.has_high_risk_findings():
        typer.echo("", err=True)
        typer.echo("FALLO: PII de ALTO riesgo detectada", err=True)
        raise typer.Exit(1)

    # Éxito
    raise typer.Exit(0)


if __name__ == "__main__":
    app()
