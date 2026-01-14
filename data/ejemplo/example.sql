-- Plantilla SQL para datos de producción (ejemplo)
INSERT INTO datos (tipo, comentario, valor) VALUES ('credit_card', 'credit card number: 4532015112830366', '4532015112830366');
INSERT INTO datos (tipo, comentario, valor) VALUES ('cedula', 'Cédula: 1023456789', '1023456789');
INSERT INTO datos (tipo, comentario, valor) VALUES ('email', 'email: cliente@dominio.com', 'cliente@dominio.com');
INSERT INTO datos (tipo, comentario, valor) VALUES ('phone', 'phone: +57 300 1234567', '+573001234567');

# NOTA:
# - Para crear archivos por regla (ej: `credit_card`, `cedula_co`, `phone_co`, `email`) copie este archivo y reemplace/ajuste ejemplos.
# - Mantén secciones de riesgo para facilitar pruebas y validación de reglas.
