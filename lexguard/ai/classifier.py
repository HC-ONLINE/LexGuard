"""
Clasificador de sensibilidad contextual con IA.

REGLAS CRÍTICAS:
- La IA NO detecta PII desde cero
- La IA NO calcula riesgo (LOW/MEDIUM/HIGH)
- La IA NO decide resultado final (FOUND/UNCERTAIN/IGNORED)
- Solo clasifica sensibilidad de hallazgos ya detectados
- Solo se ejecuta en zona gris (0.4 <= confidence < 0.8)
"""

import json
import logging
import os
from typing import Optional
import requests
from dotenv import load_dotenv

from lexguard.ai.result import AIResult, AIConfidence
from lexguard.ai.prompt import build_classification_prompt, build_system_prompt


logger = logging.getLogger(__name__)

# Cargar variables de entorno
load_dotenv()


class AIClassifier:
    """
    Clasificador auxiliar de sensibilidad contextual.

    Rol: Desempatar casos ambiguos donde las reglas determinísticas
    no son concluyentes.

    NO es detector primario.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        timeout: Optional[int] = None,
        api_key: Optional[str] = None,
    ):
        """
        Args:
            api_url: URL del endpoint de chat
            (default: desde .env o http://localhost:8000/chat)
            timeout: Timeout en segundos (default: desde .env o 10)
            api_key: API key opcional para autenticación (default: desde .env)
        """
        self.api_url: str = (
            api_url
            if api_url is not None
            else (os.getenv("AI_API_URL") or "http://localhost:8000/chat")
        )
        self.timeout: int = (
            timeout if timeout is not None else int(os.getenv("AI_TIMEOUT") or "10")
        )
        self.api_key: Optional[str] = (
            api_key if api_key is not None else os.getenv("AI_API_KEY")
        )

    def classify(self, snippet: str, pii_type: str) -> Optional[AIResult]:
        """
        Clasificar sensibilidad contextual de un fragmento.

        Args:
            snippet: Fragmento de texto (1-2 líneas)
            pii_type: Tipo de PII detectado (email, phone, cedula, etc.)

        Returns:
            AIResult o None si falla la clasificación
        """
        try:
            # Construir request
            messages = [
                {"role": "system", "content": build_system_prompt()},
                {
                    "role": "user",
                    "content": build_classification_prompt(snippet, pii_type),
                },
            ]

            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            payload = {
                "messages": messages,
                "temperature": 0.0,  # Determinístico
                "max_tokens": 200,  # Respuesta corta
                "stream": False,
            }

            # Llamar API
            response = requests.post(
                self.api_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()

            # Parsear respuesta
            response_data = response.json()
            ai_text = response_data.get("text", "").strip()

            # Extraer JSON de la respuesta
            result = self._parse_ai_response(ai_text)
            return result

        except requests.exceptions.Timeout:
            logger.warning(f"AI classification timeout after {self.timeout}s")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"AI classification request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in AI classification: {e}")
            return None

    def _parse_ai_response(self, ai_text: str) -> Optional[AIResult]:
        """
        Parsear respuesta JSON de la IA.

        Args:
            ai_text: Texto generado por la IA

        Returns:
            AIResult o None si el formato es inválido
        """
        try:
            # Intentar extraer JSON si hay texto adicional
            start = ai_text.find("{")
            end = ai_text.rfind("}") + 1
            if start == -1 or end == 0:
                logger.warning("No JSON found in AI response")
                return None

            json_str = ai_text[start:end]
            data = json.loads(json_str)

            # Validar campos requeridos
            if not all(k in data for k in ["is_sensitive", "confidence", "reason"]):
                logger.warning("Missing required fields in AI response")
                return None

            # Mapear confidence string a enum
            confidence_map = {
                "low": AIConfidence.LOW,
                "medium": AIConfidence.MEDIUM,
                "high": AIConfidence.HIGH,
            }
            confidence_str = data["confidence"].lower()
            if confidence_str not in confidence_map:
                logger.warning(f"Invalid confidence value: {confidence_str}")
                return None

            return AIResult(
                is_sensitive=bool(data["is_sensitive"]),
                confidence=confidence_map[confidence_str],
                reason=str(data["reason"]),
            )

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse AI response as JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            return None

    @staticmethod
    def should_use_ai(confidence: float) -> bool:
        """
        Determinar si se debe consultar la IA.

        Regla: Solo en zona gris (0.4 <= confidence < 0.8)

        Args:
            confidence: Confidence score del detector

        Returns:
            True si se debe usar IA
        """
        return 0.4 <= confidence < 0.8
