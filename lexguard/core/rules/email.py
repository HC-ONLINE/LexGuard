"""
Detección de direcciones de correo electrónico.

Módulo V1:
- Alta precisión (precision > recall)
- Denylist de dominios técnicos
- Contexto técnico vs. usuario
- NO validación RFC completa
- NO correos ofuscados/incompletos
"""

import re
from lexguard.core.rules.base import DetectionRule, Candidate


class EmailRule(DetectionRule):
    """
    Detecta direcciones de correo electrónico.

    Alcance explícito:
    - Formato estándar: usuario@dominio.tld
    - Subdominios permitidos
    - TLD mínimo 2 caracteres

    Excluye intencional:
    - Correos ofuscados (user [at] domain)
    - Correos incompletos (user@)
    - Dominios internos sin TLD (user@localhost)
    - IPs como dominio (user@127.0.0.1)
    """

    # Regex simple y efectivo (NO RFC completo)
    PATTERN = re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        re.IGNORECASE,
    )

    # Denylist de dominios técnicos/prueba
    INVALID_DOMAINS = {
        "localhost",
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "test.org",
        "invalid",
        "local",
        "localdomain",
        "localnet",
    }

    # Keywords positivas (contexto de usuario)
    POSITIVE_CONTEXT = {
        "email",
        "correo",
        "mail",
        "contacto",
        "usuario",
        "registrado",
        "notificación",
        "notificacion",
        "suscripción",
        "suscripcion",
        "cuenta",
        "registro",
    }

    # Keywords negativas (contexto técnico)
    NEGATIVE_CONTEXT = {
        "commit",
        "build",
        "pipeline",
        "docker",
        "checksum",
        "artifact",
        "deploy",
        "ci",
        "cd",
        "jenkins",
        "gitlab",
        "github",
        "hash",
        "version",
    }

    @property
    def pii_type(self) -> str:
        return "EMAIL"

    @property
    def display_name(self) -> str:
        return "Dirección de Correo Electrónico"

    def scan_line(self, line: str, line_number: int, file_path: str) -> list[Candidate]:
        """
        Escanea una línea buscando direcciones de correo electrónico.

        Args:
            line: Línea de texto
            line_number: Número de línea (1-indexed)
            file_path: Ruta del archivo

        Returns:
            Lista de Candidate (vacía si no hay hallazgos válidos)
        """
        candidates = []

        for match in self.PATTERN.finditer(line):
            email = match.group(0)

            # Validación fuerte: DROP si falla
            is_valid, validators_failed = self.validate(email)
            if not is_valid:
                continue

            # Extraer contexto
            context_hits_positive = self._extract_context_hits(
                line, match.start(), match.end(), self.POSITIVE_CONTEXT
            )
            context_hits_negative = self._extract_context_hits(
                line, match.start(), match.end(), self.NEGATIVE_CONTEXT
            )

            # Enmascarar
            masked = self._mask_email(email)

            # Crear candidate
            candidate = Candidate(
                pii_type=self.pii_type,
                raw_value=email,
                masked_value=masked,
                file=file_path,
                line_number=line_number,
                validators_passed=self._get_validators_passed(email, validators_failed),
                validators_failed=validators_failed,
                context_hits=context_hits_positive,
                context_negative=context_hits_negative,
                line_context=line,
            )

            candidates.append(candidate)

        return candidates

    def validate(self, match: str) -> tuple[bool, list[str]]:
        """
        Validación fuerte (DROP rules).

        Returns:
            (is_valid, list_of_validators_failed)
        """
        validators_failed = []

        # Separar usuario y dominio
        if "@" not in match:
            validators_failed.append("format")
            return False, validators_failed

        parts = match.rsplit("@", 1)
        if len(parts) != 2:
            validators_failed.append("format")
            return False, validators_failed

        username, domain = parts

        # 1. Longitud razonable
        if len(username) > 64 or len(domain) > 255:
            validators_failed.append("length")

        # 2. Dominio válido (no denylist)
        if not self._is_valid_domain(domain):
            validators_failed.append("valid_domain")

        # 3. Estructura básica
        if not username or not domain:
            validators_failed.append("format")

        # Si falla cualquiera, DROP
        if validators_failed:
            return False, validators_failed

        return True, []

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Valida que el dominio no esté en denylist.

        Args:
            domain: Parte del dominio del email

        Returns:
            True si el dominio es válido
        """
        domain_lower = domain.lower()

        # Verificar denylist exacta
        if domain_lower in self.INVALID_DOMAINS:
            return False

        # Verificar si es subdominio de denylist
        for invalid in self.INVALID_DOMAINS:
            if domain_lower.endswith("." + invalid):
                return False

        # Verificar que tenga al menos un punto (TLD)
        if "." not in domain:
            return False

        # Verificar que no sea una IP
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            return False

        return True

    def _extract_context_hits(
        self, line: str, start: int, end: int, keywords: set[str], window: int = 40
    ) -> list[str]:
        """
        Extrae palabras clave en ventana alrededor del match.

        Args:
            line: Línea completa
            start: Inicio del match
            end: Fin del match
            keywords: Conjunto de palabras a buscar
            window: Rango ±chars alrededor

        Returns:
            Lista de keywords encontradas (sin duplicados, ordenadas)
        """
        context_start = max(0, start - window)
        context_end = min(len(line), end + window)
        context = line[context_start:context_end].lower()

        hits = []
        for kw in keywords:
            if re.search(r"\b" + re.escape(kw) + r"\b", context):
                hits.append(kw)

        return sorted(list(set(hits)))

    def _get_validators_passed(
        self, email: str, validators_failed: list[str]
    ) -> list[str]:
        """
        Retorna lista de validadores que PASARON.
        """
        all_validators = ["format", "length", "valid_domain"]
        return [v for v in all_validators if v not in validators_failed]

    def _mask_email(self, email: str) -> str:
        """
        Enmascara un correo electrónico.

        Formato: us****io@dominio.com
        - Mantiene 2 primeros y 2 últimos del usuario
        - Dominio completo visible

        Args:
            email: Dirección de correo

        Returns:
            Correo enmascarado
        """
        if "@" not in email:
            return email

        username, domain = email.rsplit("@", 1)

        # Si el usuario es muy corto (≤3), mascara todo menos 1
        if len(username) <= 3:
            return f"{username[0]}***@{domain}"

        # Formato estándar: primeros 2 + asteriscos + últimos 2
        return f"{username[:2]}****{username[-2:]}@{domain}"
