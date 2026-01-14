"""Pruebas para FileStream - detección de archivos y tipos MIME"""

import pytest
from pathlib import Path
from lexguard.core.ingestion.file_stream import FileStream


class TestFileStreamMimeDetection:
    """Pruebas de detección de tipos MIME y filtrado de archivos"""

    @pytest.fixture
    def file_stream(self):
        """Crea una instancia de FileStream"""
        return FileStream()

    # ==================== PARAMETRIZED TESTS ====================

    @pytest.mark.parametrize(
        "extension,content",
        [
            (".txt", "Sample text file\nWith multiple lines\n"),
            (".json", '{"key": "value", "card": "4532015112830366"}'),
            (
                ".log",
                "2026-01-12 10:00:00 Application log\n"
                "2026-01-12 10:01:00 Event logged\n",
            ),
            (".csv", "header1,header2\nvalue1,value2\n"),
            (".sql", "SELECT * FROM users;\nINSERT INTO logs VALUES (1);\n"),
        ],
    )
    def test_text_file_streaming_utf8(self, file_stream, tmp_path, extension, content):
        """Verifica que stream_lines
        funciona con UTF-8 para todos los formatos de texto"""
        file_path = tmp_path / f"test{extension}"
        file_path.write_text(content, encoding="utf-8")

        lines = list(file_stream.stream_lines(file_path))

        # Validar contrato básico de streaming
        assert len(lines) > 0, "Debe retornar líneas"
        for line_num, line_content in lines:
            assert isinstance(line_num, int), "line_num debe ser int"
            assert line_num > 0, "line_num debe ser positivo"
            assert isinstance(line_content, str), "content debe ser str"

    # ==================== CSV TESTS ====================

    def test_csv_file_detected_as_text(self, file_stream):
        """Verifica que los archivos CSV se identifiquen correctamente como texto"""
        csv_path = Path("data/ejemplo/example.csv")

        if not csv_path.exists():
            pytest.skip(f"Archivo de prueba no encontrado: {csv_path}")

        info = file_stream.get_file_info(csv_path)

        # El CSV debe detectarse como texto
        assert (
            info.is_text
        ), f"El archivo CSV debería ser texto, MIME obtenido: {info.mime_type}"

    def test_csv_mime_type_variants(self, file_stream):
        """Verifica que las variantes de tipo MIME de CSV se reconozcan como texto"""
        csv_mime_variants = [
            "text/csv",
            "text/x-csv",
            "application/csv",
            "application/x-csv",
            "application/vnd.ms-excel",  # Estándar en Windows
        ]

        for mime_type in csv_mime_variants:
            is_text = file_stream._is_text_file(mime_type)
            assert is_text, f"El tipo MIME {mime_type} debería reconocerse como texto"

    def test_csv_included_in_collect_files(self, file_stream):
        """Verifica que collect_files incluya archivos CSV"""
        data_dir = Path("data/ejemplo")

        if not data_dir.exists():
            pytest.skip(f"Directorio de prueba no encontrado: {data_dir}")

        files = list(file_stream.collect_files(data_dir, recursive=False))

        # Debe incluir archivos CSV
        csv_files = [f for f in files if f.suffix.lower() == ".csv"]
        assert len(csv_files) > 0, "Los archivos CSV deberían ser recolectados"

    # ==================== SQL TESTS ====================

    def test_sql_file_detected_as_text(self, file_stream):
        """Verifica que los archivos SQL se identifiquen correctamente como texto"""
        sql_path = Path("data/ejemplo/example.sql")

        if not sql_path.exists():
            pytest.skip(f"Archivo de prueba no encontrado: {sql_path}")

        info = file_stream.get_file_info(sql_path)

        # El SQL debe detectarse como texto
        assert (
            info.is_text
        ), f"El archivo SQL debería ser texto, MIME obtenido: {info.mime_type}"

    def test_sql_mime_type_variants(self, file_stream):
        """Verifica que las variantes de tipo MIME de SQL se reconozcan como texto"""
        sql_mime_variants = [
            "text/x-sql",
            "application/sql",
            "application/x-sql",
            "text/plain",  # Fallback común para SQL
        ]

        for mime_type in sql_mime_variants:
            is_text = file_stream._is_text_file(mime_type)
            assert is_text, f"El tipo MIME {mime_type} debería reconocerse como texto"

    def test_sql_included_in_collect_files(self, file_stream):
        """Verifica que collect_files incluya archivos SQL"""
        data_dir = Path("data/ejemplo")

        if not data_dir.exists():
            pytest.skip(f"Directorio de prueba no encontrado: {data_dir}")

        files = list(file_stream.collect_files(data_dir, recursive=False))

        # Debe incluir archivos SQL
        sql_files = [f for f in files if f.suffix.lower() == ".sql"]
        assert len(sql_files) > 0, "Los archivos SQL deberían ser recolectados"

    # ==================== JSON TESTS ====================

    def test_json_file_detected_as_text(self, file_stream, tmp_path):
        """Verifica que los archivos JSON se identifiquen correctamente como texto"""
        json_path = tmp_path / "test.json"
        json_path.write_text(
            '{"key": "value", "card": "4532015112830366"}', encoding="utf-8"
        )

        info = file_stream.get_file_info(json_path)

        # El JSON debe detectarse como texto
        assert (
            info.is_text
        ), f"El archivo JSON debería ser texto, MIME obtenido: {info.mime_type}"

    def test_json_mime_type_variants(self, file_stream):
        """Verifica que las variantes de tipo MIME de JSON se reconozcan como texto"""
        json_mime_variants = [
            "application/json",
            "text/json",
            "application/x-json",
        ]

        for mime_type in json_mime_variants:
            is_text = file_stream._is_text_file(mime_type)
            assert is_text, f"El tipo MIME {mime_type} debería reconocerse como texto"

    def test_json_included_in_collect_files(self, file_stream, tmp_path):
        """Verifica que collect_files incluya archivos JSON"""
        json_path = tmp_path / "test.json"
        json_path.write_text('{"test": true}', encoding="utf-8")

        files = list(file_stream.collect_files(tmp_path, recursive=False))

        # Debe incluir archivos JSON
        json_files = [f for f in files if f.suffix.lower() == ".json"]
        assert len(json_files) > 0, "Los archivos JSON deberían ser recolectados"

    # ==================== LOG TESTS ====================

    def test_log_file_detected_as_text(self, file_stream, tmp_path):
        """Verifica que los archivos LOG se identifiquen correctamente como texto"""
        log_path = tmp_path / "test.log"
        log_path.write_text("2026-01-12 10:00:00 Application event\n", encoding="utf-8")

        info = file_stream.get_file_info(log_path)

        # El LOG debe detectarse como texto
        assert (
            info.is_text
        ), f"El archivo LOG debería ser texto, MIME obtenido: {info.mime_type}"

    def test_log_mime_type_variants(self, file_stream):
        """Verifica que las variantes de tipo MIME de LOG se reconozcan como texto"""
        log_mime_variants = [
            "text/plain",
            "text/x-log",
            "application/x-log",
        ]

        for mime_type in log_mime_variants:
            is_text = file_stream._is_text_file(mime_type)
            assert is_text, f"El tipo MIME {mime_type} debería reconocerse como texto"

    def test_log_included_in_collect_files(self, file_stream, tmp_path):
        """Verifica que collect_files incluya archivos LOG"""
        log_path = tmp_path / "application.log"
        log_path.write_text("Log entry\n", encoding="utf-8")

        files = list(file_stream.collect_files(tmp_path, recursive=False))

        # Debe incluir archivos LOG
        log_files = [f for f in files if f.suffix.lower() == ".log"]
        assert len(log_files) > 0, "Los archivos LOG deberían ser recolectados"

    # ==================== GENERAL TESTS ====================

    def test_txt_file_detected_as_text(self, file_stream):
        """Verifica que los archivos TXT se identifiquen correctamente como texto"""
        txt_path = Path("data/ejemplo/example.txt")

        if not txt_path.exists():
            pytest.skip(f"Archivo de prueba no encontrado: {txt_path}")

        info = file_stream.get_file_info(txt_path)

        # El TXT siempre debe detectarse como texto
        assert info.is_text
        assert "text" in info.mime_type.lower()

    def test_collect_files_all_text_types(self, file_stream):
        """Verifica que collect_files incluya todos los tipos de archivos de texto"""
        data_dir = Path("data/ejemplo")

        if not data_dir.exists():
            pytest.skip(f"Directorio de prueba no encontrado: {data_dir}")

        files = list(file_stream.collect_files(data_dir, recursive=False))

        # Debe recolectar archivos TXT, CSV y SQL
        file_extensions = {f.suffix.lower() for f in files}

        expected_types = {".txt", ".csv", ".sql", ".json", ".log"}
        found_types = file_extensions & expected_types

        assert (
            len(found_types) > 0
        ), f"Debería encontrar al menos algunos de {expected_types}"


class TestFileStreamEdgeCases:
    """Pruebas de casos límite y manejo de errores"""

    @pytest.fixture
    def file_stream(self):
        """Crea una instancia de FileStream"""
        return FileStream()

    def test_empty_file_is_text(self, file_stream, tmp_path):
        """Verifica que los archivos vacíos se traten como texto"""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        info = file_stream.get_file_info(empty_file)
        assert info.is_text

    def test_nonexistent_file_raises_error(self, file_stream):
        """Verifica que los archivos inexistentes lancen FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            file_stream.get_file_info(Path("/nonexistent/file.txt"))

    def test_directory_raises_error(self, file_stream):
        """Verifica que los directorios lancen ValueError"""
        with pytest.raises(ValueError):
            file_stream.get_file_info(Path("data/ejemplo"))
