INSERT INTO contacts (name, phone, email, created_at) VALUES
('Juan Pérez', '3001234567', 'juan@example.com', '2026-01-17'),
('María González', '+573051234567', 'maria@example.com', '2026-01-16'),
('Carlos López', '310 123 4567', 'carlos@example.com', '2026-01-15'),
('Ana Rodríguez', '315-123-4567', 'ana@example.com', '2026-01-14');

SELECT phone FROM contacts WHERE contact_type = 'mobile';

UPDATE contacts SET phone = '3201234567' WHERE id = 5;
