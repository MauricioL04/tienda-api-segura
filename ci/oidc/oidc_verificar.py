"""OIDC con verificación real: valida un token de GitHub Actions y, si pasa,
hace AssumeRoleWithWebIdentity contra moto para obtener credenciales temporales.

Qué valida (con PyJWT + cryptography, sin inventar nada):
  - firma RS256 contra el JWKS público de GitHub;
  - iss = https://token.actions.githubusercontent.com;
  - aud = sts.amazonaws.com;
  - exp (no vencido) e iat presentes;
  - sub EXACTO e inmutable del repo (E15): con StringEquals, no comodines.

Nunca imprime el token. Pensado para correr DENTRO del CI de `tienda-api-segura`,
donde GitHub entrega un token real; `demo()` lo prueba en local con un par de
claves generado al vuelo (no hay token real fuera del CI).
"""
import argparse
import os
import sys
import time

import jwt

ISS = "https://token.actions.githubusercontent.com"
AUD = "sts.amazonaws.com"
JWKS_URL = "https://token.actions.githubusercontent.com/.well-known/jwks"
# sub inmutable del repo (E15): este repo se creó tras el 15/07/2026, así que
# GitHub emite el sub con los IDs del dueño y del repo. AWS debe exigir este valor.
SUB = "repo:MauricioL04@168030514/tienda-api-segura@1457346793:ref:refs/heads/main"
ROL = "arn:aws:iam::123456789012:role/gh-oidc-deploy"


def verificar_token(token, *, jwks_url=JWKS_URL, clave_publica=None, aud=AUD, iss=ISS, sub=SUB):
    """Verifica firma y claims. Devuelve los claims o lanza una excepción de jwt."""
    if clave_publica is None:  # producción: se baja la clave de firma del JWKS de GitHub
        clave_publica = jwt.PyJWKClient(jwks_url).get_signing_key_from_jwt(token).key
    claims = jwt.decode(
        token, clave_publica, algorithms=["RS256"], audience=aud, issuer=iss,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    if claims["sub"] != sub:  # StringEquals: ni comodines ni ramas de más
        raise jwt.InvalidTokenError(f"sub no coincide: {claims['sub']!r}")
    return claims


def asumir_rol(endpoint, token, rol=ROL):
    """Cambia el token por credenciales temporales en moto (STS)."""
    import comun
    sts = comun.cliente("sts", endpoint)
    r = sts.assume_role_with_web_identity(
        RoleArn=rol, RoleSessionName="gh-oidc-ci", WebIdentityToken=token)
    return r["Credentials"]


def _segundos_para(expiracion):
    """Segundos hasta una fecha (datetime con tz que devuelve moto)."""
    import datetime
    return int((expiracion - datetime.datetime.now(datetime.UTC)).total_seconds())


def main(argv=None):
    p = argparse.ArgumentParser(description="Verifica un token OIDC de GitHub y asume un rol en moto")
    p.add_argument("--token", help="token OIDC; por defecto se lee de la variable OIDC_TOKEN")
    p.add_argument("--endpoint", default=os.environ.get("MOTO_ENDPOINT"),
                   help="endpoint de moto; por defecto la variable MOTO_ENDPOINT")
    a = p.parse_args(argv)
    token = a.token or os.environ.get("OIDC_TOKEN")
    if not token:
        print("falta el token (--token o OIDC_TOKEN)", file=sys.stderr)
        return 2
    claims = verificar_token(token)          # firma + claims contra el JWKS real
    creds = asumir_rol(a.endpoint, token)    # AssumeRoleWithWebIdentity contra moto
    n = _segundos_para(creds["Expiration"])
    # Nunca se imprime el token; solo el resultado.
    print(f"firma válida, claims OK (sub={claims['sub']}), AssumeRole OK, expira en {n} s")
    return 0


def demo():
    """Autochequeo local: genera un par RSA, firma tokens y prueba cada regla."""
    import datetime

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    import comun

    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = clave.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    pub = clave.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    ahora = int(time.time())
    base = {"iss": ISS, "aud": AUD, "sub": SUB, "iat": ahora, "exp": ahora + 300}

    def firmar(**cambios):
        return jwt.encode({**base, **cambios}, priv, algorithm="RS256")

    # 1) Token válido -> pasa y devuelve el sub correcto.
    assert verificar_token(firmar(), clave_publica=pub)["sub"] == SUB

    # 2) Firma inválida (otra clave) -> falla.
    otra = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    otra_pub = otra.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    _falla(lambda: verificar_token(firmar(), clave_publica=otra_pub), "firma inválida")

    # 3) Token vencido -> falla.
    _falla(lambda: verificar_token(firmar(exp=ahora - 1, iat=ahora - 400), clave_publica=pub), "vencido")

    # 4) aud equivocado -> falla.
    _falla(lambda: verificar_token(firmar(aud="otra"), clave_publica=pub), "aud")

    # 5) sub de otra rama -> falla (StringEquals, no comodín).
    _falla(lambda: verificar_token(
        firmar(sub="repo:MauricioL04@168030514/tienda-api-segura@1457346793:ref:refs/heads/dev"),
        clave_publica=pub), "sub")

    # 6) AssumeRoleWithWebIdentity contra moto con el token válido.
    with comun.servidor_moto() as ep:
        creds = asumir_rol(ep, firmar())
        assert creds["AccessKeyId"].startswith("ASIA"), creds["AccessKeyId"]
        assert isinstance(creds["Expiration"], datetime.datetime)
    print("autochequeo OIDC OK: 1 válido pasa; firma/exp/aud/sub inválidos fallan; AssumeRole da ASIA…")


def _falla(fn, que):
    try:
        fn()
    except jwt.PyJWTError:  # cada caso negativo debe fallar con un error de jwt
        return
    raise AssertionError(f"debía fallar por {que} y no falló")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    if "--demo" in sys.argv:
        demo()
    else:
        sys.exit(main())
