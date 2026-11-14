# centinela (copia para CI)

- **Origen:** `lab/bot/centinela.py` del repositorio del curso (Grupo 6, Ciberseguridad 2026-2).
- **Versión:** 2.2.0
- **SHA-256 de `centinela.py`:** `b1d4b3ea13dbaa4b26ad45a9810959a58e6bb5d5f8ecba81da93d3ef65520c90`
- **Licencia:** el repositorio de origen no declara una licencia; es código académico del Grupo 6.
- **Dependencias:** ninguna; solo la biblioteca estándar de Python 3.

Lo usa `.github/workflows/centinela.yml`: niveles 1 (secretos en el historial) y 3 (workflows),
compuerta con `--falla-en alta` (exit 0 sin hallazgos altos, 1 con hallazgos, 2 por error) y subida
del SARIF a code scanning.

## Qué publica el SARIF

Por cada secreto, el SARIF lleva el tipo, la ruta, la línea, el commit, el valor **enmascarado**
(solo el prefijo público, como `AKIA...(20 car.)`, o `****(len=N)`) y la **huella SHA-256** del
valor. Nunca el valor completo: el bot lo comprueba antes de escribir los reportes y el workflow lo
vuelve a comprobar antes de subirlo.

**Riesgo de la huella:** el SHA-256 de un secreto real es una pista. Quien sospeche un valor
candidato puede confirmarlo comparando hashes, y un secreto débil (una contraseña corta) se puede
recuperar por fuerza bruta. En este repositorio endurecido no hay secretos, pero en otro repo
convendría reemplazar la huella por un HMAC con una clave local o truncarla.

## Falsos positivos

Se aceptan en `.centinela-ignorar` (raíz del repo), con la huella, la ruta y el motivo. Siguen
apareciendo en el reporte y en el SARIF como suprimidos; no se esconden.

Los commits huérfanos (`--huerfanos`) solo se ven en un clon que los conserve; el clon nuevo del CI
no los tiene.
