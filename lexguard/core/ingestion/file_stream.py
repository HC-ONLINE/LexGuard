"""
Streaming de archivos para lectura segura y eficiente.
Maneja archivos grandes sin cargarlos completamente en memoria.
Detecta tipos de archivo para evitar escanear binarios.
"""

import mimetypes
from pathlib import Path
from typing import Iterator, Tuple, Any, Optional
from dataclasses import dataclass

# 'magic' puede no estar disponible (Windows). Declarar Optional para mypy.
magic: Optional[Any] = None
try:
    import magic as _magic

    magic = _magic
    HAS_MAGIC = True
except (ImportError, OSError):
    # python-magic no disponible o libmagic no encontrado (Windows)
    HAS_MAGIC = False


@dataclass
class FileInfo:
    """Metadatos sobre un archivo que está siendo escaneado"""

    path: Path
    mime_type: str
    is_text: bool
    size_bytes: int


class FileStream:
    """
    Streaming seguro de archivos con detección de tipo MIME.

    Decisiones de diseño:
    - Usa python-magic para detección real de tipo (no extensiones)
    - Usa mimetypes como respaldo en Windows si libmagic no está disponible
    - Stream línea por línea para manejar archivos grandes
    - Omite archivos binarios automáticamente
    - Preserva números de línea para reportes
    """

    # Tipos MIME de texto que consideramos seguros para escanear
    TEXT_MIME_TYPES = {
        "text/plain",
        "text/html",
        "text/xml",
        "text/csv",
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-sh",
        "application/x-python",
    }

    def __init__(self, chunk_size: int = 8192):
        """
        Args:
            chunk_size: Tamaño del buffer para lectura de archivos (bytes)
        """
        self.chunk_size = chunk_size
        # Inicializar instancia de magic solo si está disponible
        self.magic: Optional[Any]
        if HAS_MAGIC and magic is not None:
            try:
                self.magic = magic.Magic(mime=True)
            except Exception:
                # Si falla la inicialización, no usar magic
                self.magic = None
        else:
            self.magic = None

        # Inicializar mimetypes para respaldo
        if not HAS_MAGIC:
            mimetypes.init()

    def get_file_info(self, file_path: Path) -> FileInfo:
        """
        Obtener metadatos del archivo y determinar si es escaneable.

        Args:
            file_path: Ruta al archivo

        Returns:
            FileInfo con tipo MIME y bandera de texto
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        # Detectar tipo MIME
        mime_type: str
        if HAS_MAGIC and self.magic:
            mime_type = self.magic.from_file(str(file_path))
        else:
            # Respaldo: adivinar desde extensión
            guessed_mime, _ = mimetypes.guess_type(str(file_path))
            if guessed_mime:
                mime_type = guessed_mime
            else:
                # Intentar leer primeros bytes para detectar texto
                mime_type = self._guess_mime_from_content(file_path)

        is_text = self._is_text_file(mime_type)
        size_bytes = file_path.stat().st_size

        return FileInfo(
            path=file_path, mime_type=mime_type, is_text=is_text, size_bytes=size_bytes
        )

    def _is_text_file(self, mime_type: str) -> bool:
        """Verificar si el tipo MIME indica un archivo de texto"""
        if not mime_type:
            return False
        return mime_type in self.TEXT_MIME_TYPES or mime_type.startswith("text/")

    def _guess_mime_from_content(self, file_path: Path) -> str:
        """
        Adivinar tipo MIME leyendo primeros bytes (respaldo).

        Returns:
            Cadena de tipo MIME
        """
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)

            # Verificar firmas binarias comunes
            if header.startswith(b"\x89PNG"):
                return "image/png"
            elif header.startswith(b"\xff\xd8\xff"):
                return "image/jpeg"
            elif header.startswith(b"PK\x03\x04"):
                return "application/zip"
            elif header.startswith(b"%PDF"):
                return "application/pdf"

            # Intentar decodificar como texto
            try:
                header.decode("utf-8")
                return "text/plain"
            except UnicodeDecodeError:
                try:
                    header.decode("latin-1")
                    return "text/plain"
                except UnicodeDecodeError:
                    return "application/octet-stream"

        except Exception:
            return "text/plain"  # Asumir texto como respaldo

    def stream_lines(self, file_path: Path) -> Iterator[Tuple[int, str]]:
        """
        Stream de archivo línea por línea con números de línea.

        Args:
            file_path: Ruta al archivo

        Yields:
            Tuplas (número_de_línea, contenido_de_línea) (basado en 1)

        Raises:
            ValueError: Si el archivo no es texto
            UnicodeDecodeError: Si la codificación del archivo es inválida
        """
        file_info = self.get_file_info(file_path)

        if not file_info.is_text:
            raise ValueError(
                f"Cannot scan binary file: {file_path} "
                f"(MIME: {file_info.mime_type})"
            )

        # Intentar UTF-8 primero, volver a latin-1 si es necesario
        encodings = ["utf-8", "latin-1", "cp1252"]

        for encoding in encodings:
            try:
                with open(file_path, "r", encoding=encoding, errors="strict") as f:
                    for line_num, line in enumerate(f, start=1):
                        yield line_num, line.rstrip("\n\r")
                break
            except UnicodeDecodeError:
                if encoding == encodings[-1]:
                    raise
                continue

    def collect_files(self, path: Path, recursive: bool = True) -> Iterator[Path]:
        """
        Recolectar archivos escaneables desde una ruta.

        Args:
            path: Ruta de archivo o directorio
            recursive: Recurrir en subdirectorios

        Yields:
            Rutas a archivos de texto
        """
        if path.is_file():
            try:
                info = self.get_file_info(path)
                if info.is_text:
                    yield path
            except Exception:
                # Omitir archivos que no podemos leer
                pass

        elif path.is_dir():
            pattern = "**/*" if recursive else "*"
            for file_path in path.glob(pattern):
                if file_path.is_file():
                    try:
                        info = self.get_file_info(file_path)
                        if info.is_text:
                            yield file_path
                    except Exception:
                        # Omitir archivos que no podemos leer
                        continue
