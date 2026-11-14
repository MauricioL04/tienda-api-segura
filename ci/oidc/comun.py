"""Utilidades compartidas del laboratorio de nube simulada (Grupo 6).

Todo corre contra un servidor local de moto (127.0.0.1), sin Docker ni red
externa. moto imita la API de AWS pero NO genera CloudTrail: por eso cada
llamada la registra el propio cliente con `registrar()` en salida/cloudtrail.jsonl.

La autenticación de moto está ACTIVADA: tras las primeras SIN_AUTH llamadas
(el arranque del escenario: crear el admin y su clave), toda petición tiene que
venir firmada con una clave existente y autorizada por sus políticas IAM.
"""
import contextlib
import datetime
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

AQUI = Path(__file__).resolve().parent
SALIDA = AQUI / "salida"
CLOUDTRAIL = SALIDA / "cloudtrail.jsonl"
REGION = "us-east-1"
# Llamadas sin autenticar que moto acepta al arrancar: crear el admin, adjuntarle
# AdministratorAccess y crear su clave. Desde la 4.ª, todo va firmado.
SIN_AUTH = 3
# IP de documentación (RFC 5737, TEST-NET-3): el atacante. Nunca es una IP real.
IP_ATACANTE = "203.0.113.7"
AGENTE_ATACANTE = "aws-cli/2.17.0 Python/3.12 Linux/6.8 botocore/1.34"
# Red interna de la tienda (CI y administradores). Lo de fuera es «externo».
RED_INTERNA = ipaddress.ip_network("10.0.0.0/8")
IP_CI = "10.0.1.20"
IP_ADMIN = "10.0.2.15"


def ahora():
    """Hora local con offset (America/Lima en esta máquina), formato ISO-8601."""
    return datetime.datetime.now().astimezone()


def es_externa(ip):
    """True si la IP no pertenece a la red interna de la tienda."""
    try:
        return ipaddress.ip_address(ip) not in RED_INTERNA
    except ValueError:  # un nombre (p. ej. github.com) no es una IP interna
        return True


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
    entorno = {
        **os.environ,
        # Que moto cargue las políticas administradas de AWS (AdministratorAccess, etc.).
        "MOTO_IAM_LOAD_MANAGED_POLICIES": "true",
        # Autenticación y autorización activas tras las llamadas de arranque.
        "INITIAL_NO_AUTH_ACTION_COUNT": str(SIN_AUTH),
    }
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


def cliente(servicio, endpoint, akid="arranque", secret="arranque"):
    """Cliente boto3 apuntado al moto local. Las credenciales por defecto solo
    sirven para las SIN_AUTH llamadas de arranque; luego moto las rechaza."""
    import boto3
    return boto3.client(servicio, endpoint_url=endpoint, region_name=REGION,
                        aws_access_key_id=akid, aws_secret_access_key=secret)


def reiniciar_cloudtrail():
    SALIDA.mkdir(exist_ok=True)
    CLOUDTRAIL.write_text("", encoding="utf-8")


def registrar(evento, akid, fuente, *, ip=IP_ATACANTE, agente=AGENTE_ATACANTE, extra=None):
    """Escribe un evento estilo CloudTrail (una línea JSON) y lo devuelve.

    Lo registra el cliente, no AWS: moto no produce CloudTrail. `fuente` es el
    eventSource. `extra` lleva requestParameters / responseElements, como en
    CloudTrail real. La hora va con microsegundos para ordenar sin empates.
    """
    e = {
        "eventID": str(uuid.uuid4()),
        "eventTime": ahora().isoformat(timespec="microseconds"),
        "eventName": evento,
        "eventSource": fuente,
        "userIdentity": {"accessKeyId": akid},
        "sourceIPAddress": ip,
        "userAgent": agente,
    }
    if extra:
        e.update(extra)
    SALIDA.mkdir(exist_ok=True)
    # Una sola escritura por línea completa: el detector en línea nunca lee media línea.
    with CLOUDTRAIL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return e


def leer_cloudtrail():
    if not CLOUDTRAIL.exists():
        return []
    return [json.loads(x) for x in CLOUDTRAIL.read_text(encoding="utf-8").splitlines() if x.strip()]


def segundos(hora_iso):
    """Hora ISO-8601 -> segundos desde la época (para restar tiempos)."""
    return datetime.datetime.fromisoformat(hora_iso).timestamp()
