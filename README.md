# tienda-api-segura

API de inventario para la tienda (proyecto de curso), en su versión endurecida.

```
pip install -r requirements.txt
cp .env.example .env   # completar con valores propios; .env nunca se sube
python app.py
```

## Controles

- `.gitignore` excluye `.env` y otros archivos con credenciales.
- `.pre-commit-config.yaml` corre gitleaks antes de cada commit (`pre-commit install`).
- El CI escanea secretos en cada push y pull request, con `permissions: contents: read` y acciones fijadas por SHA.
- Secret scanning y push protection activos en el repositorio.
