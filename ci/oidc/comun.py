"""Utilidades compartidas del laboratorio de nube simulada (Grupo 6).

Todo corre contra un servidor local de moto (127.0.0.1), sin Docker ni red
externa. moto imita la API de AWS pero NO genera CloudTrail: por eso cada
llamada la registra el propio cliente con `registrar()` en salida/cloudtrail.jsonl.
"""
import contextlib
import datetime
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

AQUI = Path(__file__).resolve().parent
SALIDA = AQUI / "salida"
CLOUDTRAIL = SALIDA / "cloudtrail.jsonl"
REGION = "us-east-1"
# IP de documentación (RFC 5737, bloque TEST-NET-3). Nunca es una IP real.
IP_ATACANTE = "203.0.113.7"
AGENTE_ATACANTE = "aws-cli/2.17.0 Python/3.12 Linux/6.8 botocore/1.34"


def ahora():
    """Hora local con offset (America/Lima en esta máquina), formato ISO-8601."""
    return datetime.datetime.now().astimezone()


def _puerto_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@contextlib.contextmanager
def servidor_moto(puerto=None):
    """Levanta `python -m moto.server` en 127.0.0.1 y lo cierra al salir.

    Devuelve el endpoint `http://127.0.0.1:<puerto>`. Todos los clientes que
    apunten a él comparten el mismo estado mientras el servidor viva.
    """
    puerto = puerto or _puerto_libre()
    # Que moto cargue las políticas administradas de AWS (AdministratorAccess, etc.).
    entorno = {**os.environ, "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "moto.server", "-p", str(puerto)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=entorno)
    endpoint = f"http://127.0.0.1:{puerto}"
    try:
        for _ in range(100):  # espera activa hasta que el puerto acepte conexiones
            try:
                socket.create_connection(("127.0.0.1", puerto), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("moto.server no abrió el puerto a tiempo")
        yield endpoint
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)


def cliente(servicio, endpoint, akid="admin-root", secret="admin-root"):
    """Cliente boto3 apuntado al moto local. Importa boto3 aquí para que el
    resto del módulo se pueda usar sin tenerlo instalado."""
    import boto3
    return boto3.client(servicio, endpoint_url=endpoint, region_name=REGION,
                        aws_access_key_id=akid, aws_secret_access_key=secret)


def reiniciar_cloudtrail():
    SALIDA.mkdir(exist_ok=True)
    CLOUDTRAIL.write_text("", encoding="utf-8")


def registrar(evento, akid, fuente, *, ip=IP_ATACANTE, agente=AGENTE_ATACANTE, extra=None):
    """Escribe un evento estilo CloudTrail (una línea JSON) y lo devuelve.

    Lo registra el cliente, no AWS: moto no produce CloudTrail. Por eso esta
    función existe. `fuente` es el eventSource (iam.amazonaws.com, s3..., sts...).
    """
    e = {
        "eventTime": ahora().isoformat(timespec="seconds"),
        "eventName": evento,
        "eventSource": fuente,
        "userIdentity": {"accessKeyId": akid},
        "sourceIPAddress": ip,
        "userAgent": agente,
    }
    if extra:
        e.update(extra)
    SALIDA.mkdir(exist_ok=True)
    with CLOUDTRAIL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return e


def leer_cloudtrail():
    if not CLOUDTRAIL.exists():
        return []
    return [json.loads(x) for x in CLOUDTRAIL.read_text(encoding="utf-8").splitlines() if x.strip()]
