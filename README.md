# eVestigia

**Plataforma de portafolios de aprendizaje/ portafolio educativo** con editor visual por bloques, capa social, ciclos de Lesson Study (parcial), analíticas formativas para el profesorado (no incorporan IA ni modelos de ML) y asistentes de IA opcionales (locales con
Ollama,etc.). Toda la aplicación vive en un único archivo `app.py` (Python + Flask + SQLite), pensada para ser fácil de desplegar y de adaptar a las necesidades.

Software libre y de código abierto bajo **Licencia MIT** (ver `LICENSE`).

## El nombre

*eVestigia* toma su nombre del latín *vestigia* —vestigios, huellas—: las marcas que el aprendizaje va dejando como proceso. Un portafolio es precisamente eso, el rastro visible del camino recorrido: lo que se ha explorado, reflexionado y comprendido. La *e* le añade su carácter digital. 

## Características

- **Editor por bloques**: títulos, textos, imágenes, vídeo (YouTube/Vimeo), audio y documentos en columnas personalizables.
- **Portafolios y colecciones**, con visibilidad privada / docentes / pública y exportación a PDF.
- **Feedback docente** con respuestas y avisos en la app y por correo.
- **Comunidad**: perfiles, conocidos y mensajería; grupos de trabajo.
- **Lesson Study**: ciclo completo (objetivos, contenidos, ítems de observación, lección, evidencias,
  reflexión y discusiones) con exportación del ciclo a PDF.
- **Analíticas de aprendizaje** individuales y formativas (no comparativas): completitud, participación,
  constancia, tendencia, riesgo de abandono, etc., con saturación suave para evitar el efecto techo.
- **Asistentes de IA opcionales** para el profesorado (feedback y análisis de entradas): funcionan con
  **Ollama en local** (los datos no salen del servidor) u otras APIs; con ejemplos *few-shot* subibles.
- **Administración**: usuarios, asignaturas, apariencia (tema), correo, cuotas, copias de seguridad
  (descarga y **restauración**) y cifrado en reposo del chat.

## Ejecutar en local

```bash
pip install flask cryptography openpyxl      # dependencias mínimas
python app.py
```

Abre **http://127.0.0.1:5000**. La página inicial es una landing pública; pulsa *Iniciar sesión*.

Opcionales: `xhtml2pdf` no es necesario (la exportación a PDF usa la impresión emergente del navegador);
para la IA local, instala [Ollama](https://ollama.com) y arranca con
`OLLAMA_MODEL=llama3.2:3b python app.py`.

## Cuentas de demostración

Solo en una base de datos nueva. IMPORTANTE **Cámbialas antes de usar la app con personas reales.**

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `admin123` | Administración |
| `profesor` | `profe123` | Docente |
| `ana` / `luis` / `maria` | `ana123` / `luis123` / `maria123` | Estudiante |

## Configuración (variables de entorno)

- `EVESTIGIA_SECRET_KEY`: clave de sesión estable (recomendado en producción).
- `EVESTIGIA_SMTP_HOST/PORT/USER/PASS/FROM`: envío de correo real.
- `OLLAMA_MODEL`, `OLLAMA_HOST`, `EVESTIGIA_AI_TIMEOUT`: IA local con Ollama.
- `EVESTIGIA_HTTPS=1` tras un proxy con TLS.

## Privacidad y datos (importante)

La base de datos (`evestigia.db`), la carpeta `uploads/`, las claves y los registros **contienen datos personales y secretos y NO deben subirse al repositorio** en caso de hacer modificaciones del proyecto (ya están excluidos en `.gitignore`). Las contraseñas se guardan cifradas (hash PBKDF2-SHA256). Con Ollama, la IA se procesa en local.

## Licencia

Distribuido bajo la Licencia MIT: puedes usar, modificar, redistribuir y reutilizar el código,
conservando el aviso de autoría. Ver `LICENSE`.
