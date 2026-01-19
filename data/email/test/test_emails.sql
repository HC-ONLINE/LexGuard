-- =====================================================
-- SCRIPT SQL DE PRUEBA: TABLA DE USUARIOS
-- Contiene emails válidos y contexto de datos personales
-- =====================================================

-- Crear tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    telefono VARCHAR(20),
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activo BOOLEAN DEFAULT TRUE
);

-- Insertar datos de prueba
INSERT INTO usuarios (nombre, email, telefono, activo) VALUES
    ('Juan Pérez', 'juan.perez@empresa.com', '3001234567', TRUE),
    ('María Rodríguez', 'maria.rodriguez@company.co', '3109876543', TRUE),
    ('Carlos Gómez', 'carlos.gomez@portal.net', '3201122334', FALSE),
    ('Laura Torres', 'laura.torres@gmail.com', '3156677889', TRUE),
    ('Diego Sánchez', 'diego.sanchez@hotmail.com', '3187788990', TRUE),
    ('Patricia López', 'patricia.lopez@outlook.com', '3145566778', TRUE),
    ('Roberto Díaz', 'roberto.diaz@yahoo.com', '3124455667', FALSE),
    ('Carolina Martínez', 'carolina.martinez@icloud.com', '3163344556', TRUE),
    ('Andrés Gómez', 'andres.gomez@protonmail.com', '3192233445', TRUE),
    ('Sofía Ramírez', 'sofia.ramirez@empresa.com', '3181122334', TRUE);

-- Consultas de ejemplo
SELECT * FROM usuarios WHERE email LIKE '%@gmail.com';
SELECT nombre, email FROM usuarios WHERE activo = TRUE;

-- Actualización de email de usuario
UPDATE usuarios
SET email = 'nuevo.email@company.com'
WHERE id = 5;

-- Registro de notificaciones
INSERT INTO notificaciones (usuario_email, asunto, enviado) VALUES
    ('juan.perez@empresa.com', 'Bienvenida', TRUE),
    ('maria.rodriguez@company.co', 'Confirmación', TRUE),
    ('laura.torres@gmail.com', 'Recordatorio', FALSE);

-- Emails inválidos que deben ser rechazados (comentados)
-- INSERT INTO usuarios (nombre, email) VALUES ('Test', 'test@example.com');
-- INSERT INTO usuarios (nombre, email) VALUES ('Local', 'admin@localhost');
-- INSERT INTO usuarios (nombre, email) VALUES ('Invalid', 'user@127.0.0.1');
