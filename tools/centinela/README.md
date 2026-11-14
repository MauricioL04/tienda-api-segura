# centinela (copia para CI)

- **Origen:** `lab/bot/centinela.py` del repositorio del curso (Grupo 6, Ciberseguridad 2026-2).
- **Versión:** 2.2.2
- **SHA-256 de `centinela.py`:** `e824efb98656d85fefd508658d6cc027c7a2dd4fa795b71ea4c02a834ebba4b0` (con finales de línea LF, como queda en el repo)
- **Licencia:** el repositorio de origen no declara una licencia; es código académico del Grupo 6.
- **Dependencias:** ninguna; solo la biblioteca estándar de Python 3.

Lo usa `.github/workflows/centinela.yml`: niveles 1 (secretos en el historial) y 3 (workflows),
compuerta con `--falla-en alta` (exit 0 sin hallazgos altos, 1 con hallazgos, 2 por error de git, clon superficial o fallo interno; solo `.centinela-ignorar` exime, N2 nunca) y subida
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

## Pull requests (R22)

En un `pull_request`, el workflow toma `tools/centinela/centinela.py` y `.centinela-ignorar` de la
rama **base** (`git show origin/<rama base>:ruta`); el nombre de la rama llega por `env:`, sin
interpolarse dentro de `run:`. Así, un PR no puede agregar la huella de su propio secreto a
`.centinela-ignorar` ni traer un bot modificado.

**Riesgo residual:** en `pull_request`, GitHub ejecuta el workflow tal como viene en el PR. Un PR que
edite `.github/workflows/centinela.yml` puede quitar ese paso. Solo lo frena una revisión humana de
`.github/`, `tools/` y `.centinela-ignorar` (CODEOWNERS más aprobaciones obligatorias). El ruleset
de `main` pide 0 aprobaciones porque el repositorio tiene un solo dueño, así que, en la práctica,
el dueño puede cambiar la compuerta con un PR propio.
