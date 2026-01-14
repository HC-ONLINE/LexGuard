# Datos de prueba

Esta carpeta contiene **datos de prueba** usados para desarrollo y tests locales.

## Estructura

```plaintext
data/
├── ejemplo/
│   ├── example.csv
│   ├── example.json
│   ├── example.log
│   ├── example.sql
│   ├── example.txt
│   └── prod_data.txt      # Plantilla para datos de producción
├── cedula_co/
│   ├── test/
│   └── prod/
├── credit_card/
│   ├── test/
│   └── prod/
├── email/
│   ├── test/
│   └── prod/
├── phone_co/
│   ├── test/
│   └── prod/
└── README.md
```

## Cómo agregar nuevos datos

Para agregar nuevos datos de prueba para una regla específica (ej: `credit_card`, `cedula_co`, `phone_co`, `email`), siga estos pasos:

1. **Copiar la plantilla**: Use `ejemplo/example.txt` como base o `ejemplo/prod_data.txt` para datos de producción.
2. **Crear estructura por regla**: Cree carpeta `nombre_regla/` con subcarpetas `test/` y `prod/`.
3. **Nominar archivos**: Use nomenclatura `test_nombre_regla.{csv,json,sql,txt,log}` para tests.
4. **Reemplazar datos**: Adapte con datos ficticios y deterministas específicos para la regla.
5. **Mantener esquema**: Divida en secciones de riesgo (BAJO / MEDIO / ALTO) para facilitar validación.
6. **Probar localmente**: Verifique que la regla detecta correctamente:

   ```bash
   python -m lexguard.interfaces.cli.main scan data/nombre_regla/ -c 0.5 -f json
   ```

## Notas

- Los datos deben ser **ficticios** y no deben contener información real o sensible.
- **Plantillas**: Use `ejemplo/example.txt` para casos generales o `ejemplo/prod_data.txt` para escenarios de producción.
- La herramienta usa el contexto de los datos para mejorar la detección, por lo que es útil incluir metadatos que simulen escenarios reales.
- La ruta al archivo se usa como contexto adicional para la detección, por eso es importante probar en carpetas `test/` y `prod/` para validar comportamientos diferenciados.
- Cada regla debe tener **mínimo**: `test/test_nombre_regla.txt` y ejemplos en `test/` de todos los formatos soportados (CSV, JSON, SQL, etc. si aplica).
