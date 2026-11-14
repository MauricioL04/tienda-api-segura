"""Centinela: bot de rastreo de secretos de solo lectura (laboratorio del Grupo 6).

Uso:
    python centinela.py <ruta_repo_git_o_carpeta> [--niveles 1,2,3] [--salida dir]
                        [--falla-en alta] [--no-huerfanos]

Códigos de salida (sirve de compuerta en CI):
    0  sin hallazgos de severidad >= --falla-en (por defecto «alta»)
    1  hay al menos uno. Cuenta todo hallazgo de N1 y N3; solo se excluyen los de
       .centinela-ignorar (decisión humana con huella y motivo). N2 anota y prioriza el
       reporte, pero nunca exime: un LLM no determinista no abre una compuerta de seguridad.
    2  error (ruta inexistente, fallo interno o un valor sin enmascarar en los reportes)

N1  regex de proveedores + detector genérico clave=valor con entropía de Shannon,
    sobre el historial de git: todas las ramas (también archivos borrados) y, con
    --huerfanos (por defecto), los commits inalcanzables que el clon todavía guarda
    (reescritos por un force-push, solo en el reflog). Se marcan alcance «huerfano».
    Falsos positivos aceptados: archivo .centinela-ignorar en la raíz, una línea
    «<sha256 del valor> <ruta>  # motivo». Quedan en el reporte como «ignorados».
N2  clasificador local con Ollama (real / ejemplo / prueba). Solo recibe el
    secreto enmascarado (prefijo y longitud), nunca el valor completo.
N3  auditor de .github/workflows/*.yml (OWASP Top 10 CI/CD).

El bot nunca usa ni valida un secreto contra un servicio: solo lee.
Nunca imprime ni guarda un secreto completo: guarda la versión enmascarada y su SHA-256.
"""
import argparse
import datetime
import glob
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = "2.2.1"
UMBRAL_ENTROPIA = 3.5  # bits por carácter; por debajo, el valor genérico se descarta
UMBRAL_LIMITROFE = 4.2  # v2: un genérico por debajo de esto es ambiguo y lo revisa N2
USAR_LISTA_CONOCIDOS = True  # v2; en False reproduce el N1 de la v1

# v2: lista de valores de ejemplo conocidos. Los valores públicos de la documentación
# (token de ejemplo de jwt.io) se guardan como SHA-256
# para no versionar literales con formato de secreto.
# (Las claves de ejemplo de AWS ya caen por contener «example».)
CONOCIDOS_SHA256 = {
    "7f75367e7881255134e1375e723d1dea8ad5f6a4fdb79d938df1f1754a830606",  # jwt.io: token de ejemplo
}
MARCADORES_EXACTOS = {"password", "secret", "123456", "12345678", "admin"}
MARCADORES_PARCIALES = ("example", "changeme", "your_", "your-", "yourkey", "xxxx", "<", ">", "${",
                        "{{", "placeholder", "dummy", "fake", "sample", "test", "redacted", "...")
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODELO = os.environ.get("CENTINELA_MODELO", "qwen2.5:1.5b")

# ---------------------------------------------------------------- N1: patrones
# (tipo, regex, severidad). Si el regex tiene el grupo «s», ese es el secreto;
# si no, el secreto es la coincidencia completa.
PATRONES = [
    ("aws_access_key_id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "alta"),
    ("aws_secret_access_key",
     r"(?i)aws_?secret_?(?:access_?)?key\W{0,4}[:=]\s*[\"']?(?P<s>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", "alta"),
    ("github_token", r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b", "alta"),
    ("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "alta"),
    ("stripe_live", r"\bsk_live_[A-Za-z0-9]{24,}", "alta"),
    ("openai_key", r"\bsk-proj-[A-Za-z0-9_-]{20,}", "alta"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", "alta"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}", "alta"),
    ("clave_privada", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----", "critica"),
    ("url_bd_con_clave",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:(?P<s>[^\s/@]+)@", "alta"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "media"),
]
# Cuantificadores acotados ({0,40}): evitan el ReDoS (con «*», una línea como "key"*2000
# tardaba minutos por el retroceso). MAX_LINEA solo pone un techo al trabajo por línea.
GENERICO = re.compile(
    r"(?i)[\w.-]{0,40}(?:key|secret|token|passw(?:or)?d|pwd)[\w.-]{0,40}[\"']?\s*[:=]\s*[\"']?"
    r"(?P<s>[^\s\"'`,;]{8,})")
MAX_LINEA = 100_000  # ponytail: lo que pase de 100 KB en una línea no se escanea; la guardia lo bloquea
# Una línea que es solo un token base64 o hex largo (cuerpo de clave, blob): se enmascara entera.
TOKEN_SOLO = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
PATRONES = [(t, re.compile(r), sev) for t, r, sev in PATRONES]

# Archivos de configuración: la credencial está guardada sin protección (CWE-522).
# En código fuente es una credencial embebida (CWE-798).
CONFIG = re.compile(r"(?i)(\.env(\..*)?|\.ini|\.cfg|\.conf|\.ya?ml|\.json|\.properties|\.toml)$")


def entropia(valor):
    """Entropía de Shannon en bits por carácter."""
    n = len(valor)
    return -sum(c / n * math.log2(c / n) for c in (valor.count(x) for x in set(valor)))


# Prefijos que son formato público del proveedor: mostrarlos no revela nada del secreto.
PREFIJOS_PUBLICOS = ("AKIA", "ASIA", "ghp_", "github_pat_", "xoxa", "xoxb", "xoxp", "xoxr", "xoxs",
                     "sk_live_", "sk-proj-", "sk-ant-", "AIza", "-----BEGIN", "eyJ")


def enmascarar(valor):
    """Solo deja visible un prefijo público y la longitud: AKIA...(20 car.).
    Cualquier otro valor (clave secreta de AWS, contraseña, genérico) no muestra ni un
    carácter: ****(len=40). La huella SHA-256 va aparte."""
    for prefijo in PREFIJOS_PUBLICOS:
        if valor.startswith(prefijo):
            return f"{prefijo}...({len(valor)} car.)"
    return f"****(len={len(valor)})"


def sha256(valor):
    return hashlib.sha256(valor.encode()).hexdigest()


def es_conocido(valor):
    """v2: valores de ejemplo o marcadores conocidos, como la lista de exclusiones de gitleaks."""
    v = valor.lower()
    return (sha256(valor) in CONOCIDOS_SHA256 or v in MARCADORES_EXACTOS
            or any(p in v for p in MARCADORES_PARCIALES))


def necesita_n2(h):
    """v2, N2 en cascada: solo se consulta al LLM por los hallazgos ambiguos.

    Los patrones de proveedor con formato fuerte no pasan por N2 (con el valor
    enmascarado, el modelo pequeño no los distingue). Son ambiguos el detector
    genérico con entropía limítrofe y la contraseña dentro de una URL de BD,
    que no tiene formato propio.
    """
    if h["tipo"] == "url_bd_con_clave":
        return True
    return h["tipo"] == "generico_entropia" and h["entropia"] < UMBRAL_LIMITROFE


def _coincidencias(linea):
    """Devuelve (tipo, severidad, inicio, fin, valor) de cada secreto en la línea."""
    encontrados = []
    linea = linea[:MAX_LINEA]
    for tipo, rx, sev in PATRONES:
        for m in rx.finditer(linea):
            g = "s" if "s" in rx.groupindex else 0
            encontrados.append((tipo, sev, m.start(g), m.end(g), m.group(g)))
    for m in GENERICO.finditer(linea):
        ini, fin, valor = m.start("s"), m.end("s"), m.group("s")
        solapa = any(a < fin and ini < b for _, _, a, b, _ in encontrados)
        if not solapa and entropia(valor) >= UMBRAL_ENTROPIA:
            encontrados.append(("generico_entropia", "media", ini, fin, valor))
    if USAR_LISTA_CONOCIDOS:  # se filtra al final para que el genérico no recoja lo descartado
        encontrados = [c for c in encontrados if not es_conocido(c[4])]
    return encontrados


def enmascarar_linea(linea):
    """La línea con todos sus secretos enmascarados (para contexto y reportes)."""
    linea = linea[:MAX_LINEA]  # lo recortado no se escanea, así que tampoco se muestra
    for _, _, ini, fin, valor in sorted(_coincidencias(linea), key=lambda c: -c[2]):
        linea = linea[:ini] + enmascarar(valor) + linea[fin:]
    return linea


def enmascarar_lineas(lineas):
    """Enmascara un archivo completo: secretos de N1, todo lo que está dentro de un bloque
    -----BEGIN … -----END (cuerpos PEM) y las líneas que son un solo token base64/hex largo."""
    salida, en_bloque = [], False
    for x in lineas:
        if en_bloque or TOKEN_SOLO.fullmatch(x.strip()):
            salida.append(f"[{len(x.strip())} car. enmascarados]")
        else:
            salida.append(enmascarar_linea(x))
        if "-----BEGIN " in x:
            en_bloque = True
        if "-----END " in x:
            en_bloque = False
    return salida


def escanear_texto(texto, ruta=""):
    """N1 sobre un texto. Cada hallazgo guarda el valor solo en «_valor» (uso interno)."""
    lineas = texto.splitlines()
    seguras = None  # se enmascara el archivo solo si hay algún hallazgo
    hallazgos = []
    for i, linea in enumerate(lineas, 1):
        for tipo, sev, _, _, valor in _coincidencias(linea):
            seguras = seguras or enmascarar_lineas(lineas)
            contexto = seguras[max(0, i - 4):i + 3]
            hallazgos.append({
                "tipo": tipo, "severidad": sev, "ruta": ruta, "linea": i,
                "cwe": "CWE-522" if CONFIG.search(ruta) else "CWE-798",
                "enmascarado": enmascarar(valor), "sha256": sha256(valor),
                "entropia": round(entropia(valor), 2),
                "contexto": contexto, "_valor": valor,
            })
    return hallazgos


def escanear_directorio(carpeta):
    """N1 sobre una carpeta que no es repo git (por ejemplo, el corpus del benchmark)."""
    hallazgos = []
    for raiz, dirs, archivos in os.walk(carpeta):
        dirs[:] = [d for d in dirs if d != ".git"]
        for nombre in archivos:
            ruta = os.path.join(raiz, nombre)
            try:
                with open(ruta, encoding="utf-8") as f:
                    texto = f.read()
            except (UnicodeDecodeError, OSError):
                continue  # binario o ilegible
            rel = os.path.relpath(ruta, carpeta).replace("\\", "/")
            for h in escanear_texto(texto, rel):
                h.update(commit=None, estado="en_HEAD")
                hallazgos.append(h)
    return hallazgos


def _git(repo, *args, entrada=None):
    r = subprocess.run(["git", "-C", repo, "-c", "core.quotePath=false", *args],
                       input=entrada.encode() if entrada else None, capture_output=True, check=False)
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None


def commits_huerfanos(repo):
    """Commits que el clon guarda pero ninguna rama ni etiqueta alcanza (git fsck sin reflogs:
    incluye los que solo viven en el reflog, como el commit reescrito por un force-push)."""
    salida = _git(repo, "fsck", "--unreachable", "--no-reflogs", "--no-progress") or ""
    return [linea.split()[2] for linea in salida.splitlines() if linea.startswith("unreachable commit ")]


def escanear_repo(repo, huerfanos=True):
    """N1 sobre el historial: cada línea agregada en cualquier commit de cualquier rama
    y, si huerfanos=True, también en los commits inalcanzables que el clon conserva.

    Un secreto que sigue en HEAD también se agregó en algún commit, así que el
    historial cubre el árbol actual; luego se marca si sigue en HEAD o no.
    """
    extra = commits_huerfanos(repo) if huerfanos else []
    diff = _git(repo, "log", "-p", "--all", *(["--stdin"] if extra else []), "--reverse", "--no-color",
                "--no-ext-diff", "--no-textconv", "--unified=0", "--format=COMMIT %H",
                entrada="\n".join(extra) + "\n" if extra else None)
    alcanzables = set((_git(repo, "rev-list", "--all") or "").split())
    hallazgos, vistos = [], set()
    commit = ruta = None
    num = 0
    cabecera = False  # entre «diff --git» y el primer «@@»; una línea agregada «++ x» no es cabecera
    for linea in (diff or "").splitlines():
        if linea.startswith("COMMIT "):
            commit = linea[7:]
        elif linea.startswith("diff --git "):
            cabecera, ruta = True, None
        elif cabecera and linea.startswith("+++ "):
            ruta = linea[6:] if linea.startswith("+++ b/") else None
        elif linea.startswith("@@"):
            cabecera = False
            num = int(re.search(r"\+(\d+)", linea).group(1))
        elif not cabecera and linea.startswith("+") and ruta:
            for h in escanear_texto(linea[1:], ruta):
                clave = (ruta, h["tipo"], h["sha256"])
                if clave not in vistos:  # --reverse: queda el commit que lo introdujo
                    vistos.add(clave)
                    h.update(commit=commit, linea=num)
                    hallazgos.append(h)
            num += 1
    # Estado y contexto real (±3 líneas, enmascarado) desde el archivo en ese commit.
    for h in hallazgos:
        h["alcance"] = "rama" if h["commit"] in alcanzables else "huerfano"
        actual = _git(repo, "show", f"HEAD:{h['ruta']}")
        h["estado"] = "en_HEAD" if actual and h["_valor"] in actual else "solo_historial"
        texto = _git(repo, "show", f"{h['commit']}:{h['ruta']}") or ""
        i = h["linea"]
        h["contexto"] = enmascarar_lineas(texto.splitlines())[max(0, i - 4):i + 3]
    return hallazgos


# ---------------------------------------------------------------- N2: Ollama
PROMPT_N2 = """Eres un analista de seguridad. Un escáner encontró un posible secreto en un archivo.
El valor está enmascarado: solo ves su prefijo, su longitud y su entropía.
Archivo: {ruta}
Tipo detectado: {tipo}
Valor enmascarado: {enmascarado}
Entropía de Shannon del valor: {entropia} bits por carácter (un valor aleatorio largo suele superar 4,5;
un marcador repetitivo como XXXX o xxxx tiene entropía muy baja)
Contexto (±3 líneas, secretos enmascarados):
{contexto}

Clasifícalo:
- "real": parece una credencial verdadera de un sistema.
- "ejemplo": marcador, valor de documentación, plantilla, .env.example o README.
- "prueba": dato falso de pruebas, fixture o archivo dentro de tests/.
Responde solo JSON con la clase y un motivo breve escrito por ti sobre este caso:
{{"clase": "...", "motivo": "..."}}"""


def clasificar_n2(h, timeout=180):
    """Pide la clase a Ollama. Si no responde, devuelve «no_disponible» y el bot sigue."""
    prompt = PROMPT_N2.format(ruta=h["ruta"], tipo=h["tipo"], enmascarado=h["enmascarado"],
                              entropia=h["entropia"], contexto="\n".join(h["contexto"]))
    prompt = prompt.replace(h["_valor"], h["enmascarado"])  # garantía: nunca se envía el valor
    cuerpo = json.dumps({"model": OLLAMA_MODELO, "prompt": prompt, "stream": False,
                         "format": "json", "options": {"temperature": 0}}).encode()
    req = urllib.request.Request(OLLAMA_URL, cuerpo, {"Content-Type": "application/json"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            respuesta = json.loads(json.loads(r.read())["response"])
        if not isinstance(respuesta, dict):  # p. ej. una lista o un número: se conserva el hallazgo
            return "real", "respuesta de N2 no interpretable", round((time.perf_counter() - t0) * 1000)
        clase = str(respuesta.get("clase", "")).lower()
        if clase not in ("real", "ejemplo", "prueba"):
            clase = "real"  # respuesta ambigua: se conserva el hallazgo (conservador)
        return clase, str(respuesta.get("motivo", ""))[:300], round((time.perf_counter() - t0) * 1000)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as e:
        return "no_disponible", type(e).__name__, None


# ---------------------------------------------------------------- N3: workflows
# (id, severidad, referencia OWASP Top 10 CI/CD, CWE, descripción)
REGLAS_N3 = {
    "CICD-01": ("critica", "CICD-SEC-4", "CWE-829",
                "pull_request_target hace checkout del código de la cabeza del PR (PPE)"),
    "CICD-02": ("alta", "CICD-SEC-4", "CWE-94",
                "${{ github.event.* }} dentro de run: permite inyección de comandos"),
    "CICD-03": ("alta", "CICD-SEC-5", "CWE-732", "permissions: write-all da todos los permisos al GITHUB_TOKEN"),
    "CICD-04": ("media", "CICD-SEC-5", "CWE-732",
                "sin bloque permissions: el GITHUB_TOKEN usa los permisos por defecto"),
    "CICD-05": ("media", "CICD-SEC-3", "CWE-829", "acción de terceros no fijada por SHA de commit"),
    "CICD-06": ("alta", "CICD-SEC-6", "CWE-522", "secrets.* expuestos en un workflow pull_request_target"),
}


def auditar_workflow(texto, ruta):
    """N3 por líneas y regex, sin parser YAML."""
    lineas = texto.splitlines()
    hallazgos = []

    def marcar(regla, num):
        sev, owasp, cwe, desc = REGLAS_N3[regla]
        hallazgos.append({"regla": regla, "severidad": sev, "owasp": owasp, "cwe": cwe,
                          "descripcion": desc, "ruta": ruta, "linea": num})

    prt = any(re.search(r"\bpull_request_target\b", x) for x in lineas)
    indent_run = None  # sangría de la clave run: mientras se está dentro del bloque
    for num, linea in enumerate(lineas, 1):
        sangria = len(linea) - len(linea.lstrip())
        if indent_run is not None and linea.strip() and sangria <= indent_run:
            indent_run = None
        m = re.match(r"(\s*)(?:-\s+)?run:\s*(.*)", linea)
        if m:
            indent_run = len(m.group(1))
            if "${{ github.event." in m.group(2).replace("${{github", "${{ github"):
                marcar("CICD-02", num)
        elif indent_run is not None and re.search(r"\$\{\{\s*github\.event\.", linea):
            marcar("CICD-02", num)
        if prt and re.search(r"ref:\s*\$\{\{\s*github\.(event\.pull_request\.head\.|head_ref)", linea):
            marcar("CICD-01", num)
        if re.search(r"^\s*permissions:\s*write-all", linea):
            marcar("CICD-03", num)
        u = re.search(r"uses:\s*([^\s#]+)@([^\s#]+)", linea)
        if u and not u.group(1).startswith(("./", "docker://")) and not re.fullmatch(r"[0-9a-f]{40}", u.group(2)):
            marcar("CICD-05", num)
        if prt and re.search(r"\$\{\{\s*secrets\.", linea):
            marcar("CICD-06", num)
    if not any(re.match(r"\s*permissions:", x) for x in lineas):
        marcar("CICD-04", 1)
    return hallazgos


def auditar_workflows(repo):
    hallazgos = []
    for ruta in sorted(glob.glob(os.path.join(repo, ".github", "workflows", "*.y*ml"))):
        with open(ruta, encoding="utf-8") as f:
            rel = os.path.relpath(ruta, repo).replace("\\", "/")
            hallazgos += auditar_workflow(f.read(), rel)
    return hallazgos


# ---------------------------------------------------------------- reportes
NIVEL_SARIF = {"critica": "error", "alta": "error", "media": "warning", "baja": "note"}


def escribir_reportes(salida, repo, secretos, workflows, niveles, ignorados=()):
    """Escribe hallazgos.json, reporte.md y reporte.sarif. Antes de escribir, comprueba que
    ningún valor completo aparezca en los textos; si aparece, no escribe nada y falla."""
    os.makedirs(salida, exist_ok=True)
    fecha = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    publicos = [{k: v for k, v in h.items() if k != "_valor"} for h in secretos]
    ign = [{k: v for k, v in h.items() if k != "_valor"} for h in ignorados]
    datos = {"herramienta": "centinela", "version": VERSION, "fecha": fecha, "repo": repo,
             "niveles": niveles, "modelo_n2": OLLAMA_MODELO if 2 in niveles else None,
             "secretos": publicos, "ignorados": ign, "workflows": workflows}

    md = [f"# Reporte de Centinela {VERSION}", "", f"- Repositorio: `{repo}`", f"- Fecha: {fecha}",
          f"- Niveles: {', '.join(map(str, niveles))}", "",
          f"## Secretos ({len(publicos)})", "",
          "| Tipo | Severidad | CWE | Ruta:línea | Commit | Alcance | Estado | Valor enmascarado | N2 |",
          "|---|---|---|---|---|---|---|---|---|"]
    for h in publicos:
        n2 = h.get("n2", "—") + (f" ({h['n2_motivo']})" if h.get("n2_motivo") else "")
        md.append(f"| {h['tipo']} | {h['severidad']} | {h['cwe']} | `{h['ruta']}:{h['linea']}` | "
                  f"{(h['commit'] or '—')[:10]} | {h.get('alcance', '—')} | {h['estado']} | "
                  f"`{h['enmascarado']}` | {n2.replace('|', '/')} |")
    md += ["", f"## Ignorados por .centinela-ignorar ({len(ign)})", "",
           "| Tipo | Ruta:línea | Valor enmascarado | Huella SHA-256 | Motivo |", "|---|---|---|---|---|"]
    for h in ign:
        md.append(f"| {h['tipo']} | `{h['ruta']}:{h['linea']}` | `{h['enmascarado']}` | "
                  f"`{h['sha256'][:16]}…` | {h['ignorado']} |")
    md += ["", f"## Workflows ({len(workflows)})", "",
           "| Regla | Severidad | OWASP CI/CD | CWE | Ruta:línea | Descripción |", "|---|---|---|---|---|---|"]
    for w in workflows:
        md.append(f"| {w['regla']} | {w['severidad']} | {w['owasp']} | {w['cwe']} | "
                  f"`{w['ruta']}:{w['linea']}` | {w['descripcion']} |")

    resultados, reglas = [], {}
    for h in publicos + ign:
        reglas[h["tipo"]] = {"id": h["tipo"], "properties": {"cwe": h["cwe"]}}
        texto = (f"Posible secreto {h['tipo']} ({h['enmascarado']}), {h['estado']}, "
                 f"alcance {h.get('alcance', '—')}, commit {h['commit'] or '—'}")
        if h.get("n2"):
            texto += f", N2: {h['n2']}"
        r = _resultado_sarif(h["tipo"], h["severidad"], texto, h["ruta"], h["linea"],
                             {"sha256": h["sha256"], "cwe": h["cwe"]})
        if h.get("ignorado"):  # supresión explícita: visible, no escondida
            r["suppressions"] = [{"kind": "external", "justification": h["ignorado"]}]
        resultados.append(r)
    for w in workflows:
        reglas[w["regla"]] = {"id": w["regla"], "shortDescription": {"text": w["descripcion"]},
                              "properties": {"owasp": w["owasp"], "cwe": w["cwe"]}}
        resultados.append(_resultado_sarif(w["regla"], w["severidad"], w["descripcion"], w["ruta"], w["linea"],
                                           {"owasp": w["owasp"], "cwe": w["cwe"]}))
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "centinela", "version": VERSION,
                                           "rules": list(reglas.values())}},
                       "results": resultados}]}

    textos = {"hallazgos.json": json.dumps(datos, ensure_ascii=False, indent=2),
              "reporte.md": "\n".join(md) + "\n",
              "reporte.sarif": json.dumps(sarif, ensure_ascii=False, indent=2)}
    valores = [h["_valor"] for h in [*secretos, *ignorados] if len(h["_valor"]) >= 8]
    for nombre, texto in textos.items():
        if any(v in texto for v in valores):
            raise RuntimeError(f"autocomprobación: {nombre} contiene un valor sin enmascarar; no se escribe")
    for nombre, texto in textos.items():
        with open(os.path.join(salida, nombre), "w", encoding="utf-8") as f:
            f.write(texto)


def _resultado_sarif(regla, sev, texto, ruta, linea, props):
    return {"ruleId": regla, "level": NIVEL_SARIF[sev], "message": {"text": texto},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": ruta},
                                                "region": {"startLine": linea}}}],
            "properties": props}


# ---------------------------------------------------------------- CLI
ORDEN_SEVERIDAD = {"baja": 0, "media": 1, "alta": 2, "critica": 3}


def cargar_ignorados(repo):
    """Lee .centinela-ignorar: «<sha256> <ruta>  # motivo» por línea. Devuelve {(sha, ruta): motivo}."""
    ruta = os.path.join(repo, ".centinela-ignorar")
    if not os.path.isfile(ruta):
        return {}
    reglas = {}
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            datos, _, motivo = linea.partition("#")
            partes = datos.split()
            if len(partes) == 2:
                reglas[(partes[0], partes[1])] = motivo.strip() or "sin motivo"
    return reglas


def main(argv=None):
    p = argparse.ArgumentParser(description="Bot de rastreo de secretos (solo lectura)")
    p.add_argument("repo")
    p.add_argument("--niveles", default="1,2,3")
    p.add_argument("--salida", default="salidas")
    p.add_argument("--falla-en", choices=list(ORDEN_SEVERIDAD), default="alta",
                   help="severidad mínima que hace salir con 1")
    p.add_argument("--huerfanos", action=argparse.BooleanOptionalAction, default=True,
                   help="en un repo git, escanear también los commits inalcanzables (por defecto, sí)")
    a = p.parse_args(argv)
    try:
        return _correr(a)
    except Exception as e:  # noqa: BLE001 — compuerta: un error nunca debe parecer «sin hallazgos»
        print(f"Centinela {VERSION}: error: {e}", file=sys.stderr)
        return 2


def _correr(a):
    if not os.path.isdir(a.repo):
        raise FileNotFoundError(f"no existe la carpeta {a.repo}")
    niveles = sorted(int(n) for n in a.niveles.split(","))
    es_git = _git(a.repo, "rev-parse", "--is-inside-work-tree") is not None

    secretos = []
    if 1 in niveles:
        secretos = escanear_repo(a.repo, a.huerfanos) if es_git else escanear_directorio(a.repo)
    reglas_ign = cargar_ignorados(a.repo)
    ignorados = []
    for h in secretos:
        motivo = reglas_ign.get((h["sha256"], h["ruta"]))
        if motivo:
            h["ignorado"] = motivo
            ignorados.append(h)
    secretos = [h for h in secretos if not h.get("ignorado")]
    if 2 in niveles:
        for h in secretos:  # en serie: una sola petición a la vez por la poca RAM
            if necesita_n2(h):
                h["n2"], h["n2_motivo"], h["n2_ms"] = clasificar_n2(h)
            else:  # cascada v2: formato fuerte, no se consulta al LLM
                h["n2"] = "no_requerido"
    workflows = auditar_workflows(a.repo) if 3 in niveles else []
    escribir_reportes(a.salida, a.repo, secretos, workflows, niveles, ignorados)

    umbral = ORDEN_SEVERIDAD[a.falla_en]
    cuentan = secretos + workflows  # los ignorados ya salieron; N2 no exime (falla cerrada)
    falla = any(ORDEN_SEVERIDAD[h["severidad"]] >= umbral for h in cuentan)
    print(f"Centinela {VERSION}: {len(secretos)} secretos, {len(ignorados)} ignorados, "
          f"{len(workflows)} hallazgos de workflows -> {a.salida}")
    for h in secretos:
        print(f"  [{h['severidad']}] {h['tipo']} {h['ruta']}:{h['linea']} {h['enmascarado']} "
              f"{h['estado']} {h.get('alcance', '')} {h.get('n2', '')}")
    for h in ignorados:
        print(f"  [ignorado] {h['tipo']} {h['ruta']}:{h['linea']} {h['enmascarado']} ({h['ignorado']})")
    for w in workflows:
        print(f"  [{w['severidad']}] {w['regla']} {w['ruta']}:{w['linea']} {w['descripcion']}")
    print(f"Compuerta (--falla-en {a.falla_en}): {'FALLA (exit 1)' if falla else 'OK (exit 0)'}")
    return 1 if falla else 0


if __name__ == "__main__":
    sys.exit(main())
