"""
Tests del clasificador de IA.

Valida:
- Parsing de respuestas
- Lógica de activación
- Manejo de errores
- Carga de configuración desde .env
"""

import os
from unittest.mock import Mock, patch
from lexguard.ai.classifier import AIClassifier
from lexguard.ai.result import AIResult, AIConfidence


class TestAIClassifierActivation:
    """Tests de cuándo se debe activar la IA"""

    def test_should_use_ai_in_gray_zone(self):
        """AI se activa en zona gris (0.4 <= confidence < 0.8)"""
        assert AIClassifier.should_use_ai(0.4) is True
        assert AIClassifier.should_use_ai(0.5) is True
        assert AIClassifier.should_use_ai(0.6) is True
        assert AIClassifier.should_use_ai(0.7) is True
        assert AIClassifier.should_use_ai(0.79) is True

    def test_should_not_use_ai_below_threshold(self):
        """AI NO se activa con confianza baja (< 0.4)"""
        assert AIClassifier.should_use_ai(0.0) is False
        assert AIClassifier.should_use_ai(0.3) is False
        assert AIClassifier.should_use_ai(0.39) is False

    def test_should_not_use_ai_above_threshold(self):
        """AI NO se activa con confianza alta (>= 0.8)"""
        assert AIClassifier.should_use_ai(0.8) is False
        assert AIClassifier.should_use_ai(0.9) is False
        assert AIClassifier.should_use_ai(1.0) is False


class TestAIResponseParsing:
    """Tests de parsing de respuestas de IA"""

    def setup_method(self):
        self.classifier = AIClassifier()

    def test_parse_valid_response(self):
        """Parsear respuesta JSON válida"""
        ai_text = """
        {
          "is_sensitive": true,
          "confidence": "high",
          "reason": "Email personal en contexto de usuario"
        }
        """
        result = self.classifier._parse_ai_response(ai_text)

        assert result is not None
        assert result.is_sensitive is True
        assert result.confidence == AIConfidence.HIGH
        assert "Email personal" in result.reason

    def test_parse_response_with_extra_text(self):
        """Parsear JSON embebido en texto adicional"""
        ai_text = """
        Aquí está el análisis:
        {
          "is_sensitive": false,
          "confidence": "medium",
          "reason": "Email genérico de contacto"
        }
        Espero que sea útil.
        """
        result = self.classifier._parse_ai_response(ai_text)

        assert result is not None
        assert result.is_sensitive is False
        assert result.confidence == AIConfidence.MEDIUM

    def test_parse_invalid_json(self):
        """JSON inválido retorna None"""
        ai_text = "This is not JSON at all"
        result = self.classifier._parse_ai_response(ai_text)
        assert result is None

    def test_parse_missing_fields(self):
        """JSON sin campos requeridos retorna None"""
        ai_text = '{"is_sensitive": true}'
        result = self.classifier._parse_ai_response(ai_text)
        assert result is None

    def test_parse_invalid_confidence_value(self):
        """Valor de confidence inválido retorna None"""
        ai_text = """
        {
          "is_sensitive": true,
          "confidence": "super-high",
          "reason": "Test"
        }
        """
        result = self.classifier._parse_ai_response(ai_text)
        assert result is None

    def test_parse_all_confidence_levels(self):
        """Validar todos los niveles de confidence"""
        for level in ["low", "medium", "high"]:
            ai_text = f"""
            {{
              "is_sensitive": true,
              "confidence": "{level}",
              "reason": "Test"
            }}
            """
            result = self.classifier._parse_ai_response(ai_text)
            assert result is not None
            assert result.confidence.value == level


class TestAIClassifierIntegration:
    """Tests de integración con API mock"""

    @patch("lexguard.ai.classifier.requests.post")
    def test_classify_success(self, mock_post):
        """Clasificación exitosa"""
        # Mock de respuesta exitosa
        mock_response = Mock()
        mock_response.json.return_value = {
            "text": '{"is_sensitive": true, "confidence": "high", "reason": "Test"}',
            "provider": "test",
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        classifier = AIClassifier()
        result = classifier.classify("test@example.com", "email")

        assert result is not None
        assert result.is_sensitive is True
        assert result.confidence == AIConfidence.HIGH

    @patch("lexguard.ai.classifier.requests.post")
    def test_classify_timeout(self, mock_post):
        """Timeout retorna None"""
        mock_post.side_effect = Exception("Timeout")

        classifier = AIClassifier(timeout=1)
        result = classifier.classify("test@example.com", "email")

        assert result is None

    @patch("lexguard.ai.classifier.requests.post")
    def test_classify_api_error(self, mock_post):
        """Error de API retorna None"""
        mock_post.side_effect = Exception("API Error")

        classifier = AIClassifier()
        result = classifier.classify("test@example.com", "email")

        assert result is None


class TestAIResult:
    """Tests de AIResult"""

    def test_to_dict(self):
        """Serialización a dict"""
        result = AIResult(
            is_sensitive=True,
            confidence=AIConfidence.HIGH,
            reason="Test reason",
        )

        data = result.to_dict()
        assert data["is_sensitive"] is True
        assert data["confidence"] == "high"
        assert data["reason"] == "Test reason"

    def test_repr(self):
        """String representation"""
        result = AIResult(
            is_sensitive=False,
            confidence=AIConfidence.MEDIUM,
            reason="Generic contact",
        )

        repr_str = repr(result)
        assert "is_sensitive=False" in repr_str
        assert "confidence=medium" in repr_str
        assert "Generic contact" in repr_str


class TestAIClassifierConfiguration:
    """Tests de configuración desde .env"""

    def test_default_configuration(self):
        """Valores por defecto cuando no hay .env"""
        classifier = AIClassifier()
        assert classifier.api_url == "http://localhost:8000/chat"
        assert classifier.timeout == 10
        assert classifier.api_key is None

    def test_override_with_parameters(self):
        """Parámetros explícitos tienen prioridad sobre .env"""
        classifier = AIClassifier(
            api_url="http://custom.api/chat",
            timeout=30,
            api_key="test-key",
        )
        assert classifier.api_url == "http://custom.api/chat"
        assert classifier.timeout == 30
        assert classifier.api_key == "test-key"

    @patch.dict(os.environ, {"AI_API_URL": "http://env.api/chat"})
    def test_load_from_env_api_url(self):
        """Cargar AI_API_URL desde variable de entorno"""
        classifier = AIClassifier()
        assert classifier.api_url == "http://env.api/chat"

    @patch.dict(os.environ, {"AI_TIMEOUT": "60"})
    def test_load_from_env_timeout(self):
        """Cargar AI_TIMEOUT desde variable de entorno"""
        classifier = AIClassifier()
        assert classifier.timeout == 60

    @patch.dict(os.environ, {"AI_API_KEY": "env-api-key"})
    def test_load_from_env_api_key(self):
        """Cargar AI_API_KEY desde variable de entorno"""
        classifier = AIClassifier()
        assert classifier.api_key == "env-api-key"

    @patch.dict(
        os.environ,
        {
            "AI_API_URL": "http://full.env/chat",
            "AI_TIMEOUT": "45",
            "AI_API_KEY": "full-key",
        },
    )
    def test_load_all_from_env(self):
        """Cargar toda la configuración desde variables de entorno"""
        classifier = AIClassifier()
        assert classifier.api_url == "http://full.env/chat"
        assert classifier.timeout == 45
        assert classifier.api_key == "full-key"
