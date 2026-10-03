# Desplegar eVestigia en PythonAnywhere (para pruebas o trabajo con grupos pequeños, durante un mes, sin IA y sin avisos por email. Se puede renovar mensualmente)

Guía paso a paso para poner eVestigia en internet sin administrar un servidor. La IA (Ollama) queda **desactivada**: si no configuras ningún modelo, los botones de IA no aparecen y el resto funciona igual (incluido el resumen y las sugerencias automáticas por reglas).

> Nota: el envío de correos (avisos, restablecer contraseña, fallos críticos al admin.) necesita el **plan de pago** (Developer sobre 10 €/mes en 2026), porque el gratuito bloquea la salida a internet. El resto de la app funciona también en el gratuito.

## 1. Crear la cuenta

1. Entra en **pythonanywhere.com** y crea una cuenta.
2. Para las pruebas con correo, elige el plan **Developer** (de pago). Si no necesitas correo aún, puedes empezar en el gratuito y subir después.
3. Tu URL será `https://TUUSUARIO.pythonanywhere.com`.

## 2. Subir la app

1. Pestaña **Files**.
2. Crea una carpeta `evestigia` (botón "New directory").
3. Entra en ella y usa **Upload a file** para subir tu `app.py`.

Ruta final: `/home/TUUSUARIO/evestigia/app.py`

## 3. Crear el entorno virtual e instalar dependencias

1. Pestaña **Consoles** → abre una consola **Bash**.
2. Ejecuta (sin `waitress`: PythonAnywhere ya pone su propio servidor):

```bash
mkvirtualenv --python=/usr/bin/python3.11 evestigia
pip install flask cryptography openpyxl
```

Anota la ruta del entorno que te muestra: `/home/TUUSUARIO/.virtualenvs/evestigia`

## 4. Crear la aplicación web

1. Pestaña **Web** → **Add a new web app** → **Next**.
2. Elige **Manual configuration** (¡no "Flask"!, porque ya tienes tu propio `app.py`).
3. Elige **Python 3.11**.

## 5. Configurar la web

En la pestaña **Web**, ajusta:

- **Virtualenv**: escribe `/home/TUUSUARIO/.virtualenvs/evestigia`.
- **Working directory** (directorio de trabajo): `/home/TUUSUARIO/evestigia`.
- **WSGI configuration file**: pincha en el enlace para editarlo, **borra todo** y pega esto (cambiando `TUUSUARIO` y la clave):

```python
import os, sys

# Clave de sesión estable (genera una larga y secreta, ver abajo):
os.environ["EVESTIGIA_SECRET_KEY"] = "PEGA_AQUI_LA_CADENA_ALEATORIA"

path = "/home/TUUSUARIO/evestigia"
if path not in sys.path:
    sys.path.insert(0, path)

from app import app as application
```

Guarda el archivo.

Para generar la clave, en la consola Bash:

```bash
python3 -c "import secrets;print(secrets.token_hex(32))"
```

Copia el resultado y pégalo en el WSGI, entre las comillas de `EVESTIGIA_SECRET_KEY`.

## 6. Arrancar

Pestaña **Web** → botón verde **Reload**. Abre `https://TUUSUARIO.pythonanywhere.com`: debe salir el login de eVestigia.

## 7. Actualizar la app cuando refinemos algo

1. Sube el `app.py` nuevo en **Files** (sustituye al anterior).
2. Pestaña **Web** → **Reload**.

Los datos **no se pierden**: `evestigia.db` y la carpeta `uploads/` están en el disco persistente y no se tocan al actualizar el código. Si una mejora añade tablas o columnas nuevas, se crean solas al hacer Reload (las migraciones corren al arrancar). Si algo falla, vuelve a subir la versión anterior y Reload.

## Notas

- **IA desactivada**: al no definir `OLLAMA_MODEL` ni ninguna clave de IA, los asistentes no aparecen. El resto (portafolios, grupos, chat, analíticas, Lesson Study, resumen automático) funciona con normalidad.
- **Correo**: configúralo en **Administración → Correo (SMTP)** dentro de la app; requiere plan de pago para que salga a internet.
- **Copia de seguridad**: descarga de vez en cuando `evestigia.db` desde **Files** para tener respaldo.
- **CPU**: el plan de pruebas tiene un límite de segundos de CPU al día; para un piloto con pocos usuarios sobra.
