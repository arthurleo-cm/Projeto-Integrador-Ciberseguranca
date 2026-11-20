"""DAST do Marquezi Gestão: sobe o sistema de verdade (HTTPS + MFA) numa pasta temporária e o ataca
pela rede, sem olhar o código. Cada caso descreve o ataque e o comportamento esperado.

Uso: python tests/dast/hostile_cases.py      (ou: make dast)
"""
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[2]
PORT = int(os.environ.get("DAST_PORT", "5099"))
DATA = Path(tempfile.mkdtemp(prefix="marquezi-dast-"))
LOG = DATA / "servidor.log"
ADMIN = {"nome": "Admin DAST", "email": "admin@dast.example", "senha": "Dast#" + secrets.token_urlsafe(16)}
OPERADOR = {"nome": "Operador DAST", "email": "operador@dast.example", "senha": "Oper#" + secrets.token_urlsafe(16)}
ENV = {**os.environ, "DATA_DIR": str(DATA), "PORT": str(PORT), "MFA_MODE": "console", "TLS_MODE": "on",
       "APP_ENV": "", "PYTHONUNBUFFERED": "1"}
for var in ("APP_ORIGIN", "TRUST_PROXY", "SMTP_HOST"):
    ENV.pop(var, None)
ORIGIN = f"https://localhost:{PORT}"


class Browser:
    """Cliente HTTPS mínimo que guarda o cookie de sessão e envia Origin como um navegador."""

    def __init__(self):
        self.cookies = {}
        self.context = ssl.create_default_context(cafile=str(DATA / "tls" / "localhost-cert.pem"))

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPSConnection("localhost", PORT, context=self.context, timeout=30)
        h = {"Host": f"localhost:{PORT}"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if method == "POST":
            h.update({"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"})
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", "replace")
        for raw in resp.headers.get_all("Set-Cookie") or []:
            name, _, rest = raw.partition("=")
            value = rest.split(";", 1)[0]
            if value and "Max-Age=0" not in raw and "expires=Thu, 01 Jan 1970" not in raw:
                self.cookies[name] = value
            else:
                self.cookies.pop(name, None)
        conn.close()
        return resp.status, resp.headers, text

    def get(self, path, headers=None):
        return self.request("GET", path, headers=headers)

    def post(self, path, data, headers=None):
        return self.request("POST", path, urlencode(data),
                            {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})

    def upload(self, path, fields, filename, content):
        boundary = uuid.uuid4().hex
        parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
                 for k, v in fields.items()]
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="arquivo"; filename="{filename}"\r\n'
                     f"Content-Type: application/pdf\r\n\r\n".encode() + content + b"\r\n")
        body = b"".join(parts) + f"--{boundary}--\r\n".encode()
        return self.request("POST", path, body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    def csrf(self, path):
        status, _, text = self.get(path)
        m = re.search(r'name="_csrf" value="([^"]+)"', text)
        return m.group(1) if m else ""

    def follow(self, status, headers, text):
        if status in (301, 302, 303, 307, 308):
            return self.get(urlsplit(headers["Location"]).path or "/")
        return status, headers, text


def mfa_code(email, since):
    for _ in range(50):
        found = re.findall(rf"MFA desenvolvimento\] {re.escape(email)}: (\d{{6}})", LOG.read_text()[since:])
        if found:
            return found[-1]
        time.sleep(0.1)
    return None


def password_step(email, senha):
    b = Browser()
    token = b.csrf("/login")
    since = len(LOG.read_text())
    status, headers, _ = b.post("/login", {"_csrf": token, "email": email, "senha": senha})
    return b, status, headers, since


def login(user):
    b, status, headers, since = password_step(user["email"], user["senha"])
    assert status == 302 and headers["Location"].endswith("/login/codigo"), f"senha recusada ({status})"
    token = b.csrf("/login/codigo")
    status, headers, _ = b.post("/login/codigo", {"_csrf": token, "codigo": mfa_code(user["email"], since)})
    assert status == 302 and headers["Location"].endswith("/dashboard"), f"código recusado ({status})"
    return b


def goes_to_login(status, headers):
    return status in (302, 303) and urlsplit(headers.get("Location", "")).path == "/login"


# ------------------------------------------------------------------ casos hostis

def caso_cabecalhos_de_seguranca():
    """Toda página precisa dos cabeçalhos de proteção, e o cookie de sessão não pode vazar."""
    _, h, _ = Browser().get("/login")
    csp = h.get("Content-Security-Policy", "")
    cookie = h.get("Set-Cookie", "")
    checks = {
        "CSP fechada": "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp,
        "HSTS": "max-age=" in h.get("Strict-Transport-Security", ""),
        "X-Frame-Options": h.get("X-Frame-Options") == "DENY",
        "nosniff": h.get("X-Content-Type-Options") == "nosniff",
        "Referrer-Policy": h.get("Referrer-Policy") == "same-origin",
        "COOP": h.get("Cross-Origin-Opener-Policy") == "same-origin",
        "sem cache": h.get("Cache-Control") == "no-store",
        "Server sem versões": not re.search(r"Werkzeug|Python|\d+\.\d+", h.get("Server", "")),
        "cookie __Host- Secure HttpOnly SameSite=Strict": cookie.startswith("__Host-sessao=")
        and all(f in cookie for f in ("Secure", "HttpOnly", "SameSite=Strict")),
    }
    falhas = [k for k, ok in checks.items() if not ok]
    assert not falhas, "faltando: " + ", ".join(falhas)


def caso_http_sem_tls_recusado():
    """Conexão sem criptografia na porta do sistema não pode receber páginas."""
    try:
        conn = http.client.HTTPConnection("localhost", PORT, timeout=5)
        conn.request("GET", "/login")
        status = conn.getresponse().status
    except (OSError, http.client.HTTPException):
        return
    assert status != 200, "respondeu 200 em HTTP puro"


def caso_host_falso():
    """Host diferente do domínio do sistema (ataque de cabeçalho Host) recebe 421."""
    status, _, _ = Browser().get("/login", {"Host": "evil.example"})
    assert status == 421, f"status {status}"


def caso_metodos_nao_permitidos():
    """Métodos fora de GET/HEAD/POST são recusados com 405."""
    for method in ("PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"):
        status, _, _ = Browser().request(method, "/login")
        assert status == 405, f"{method} -> {status}"


def caso_paginas_protegidas_sem_login():
    """Sem login, nenhuma página interna, download ou ação pode ser acessada."""
    b = Browser()
    for path in ("/dashboard", "/clients", "/clients/1", "/processes", "/processes/1", "/users", "/audit",
                 "/account", "/documents/1/download", "/process-files/1/download", "/process-files/1/preview"):
        status, headers, _ = b.get(path)
        assert goes_to_login(status, headers), f"{path} -> {status}"


def caso_senha_errada():
    """Senha errada é recusada e nenhum código de acesso é emitido."""
    b, status, _, since = password_step(ADMIN["email"], "senha-totalmente-errada")
    assert status == 401, f"status {status}"
    assert mfa_code(ADMIN["email"], since) is None, "emitiu código com senha errada"


def caso_injecao_sql_no_login():
    """Injeção de SQL clássica no e-mail e na senha não pode autenticar."""
    for email, senha in (("' OR '1'='1' --", "qualquer"), (ADMIN["email"], "x' OR '1'='1")):
        _, status, headers, _ = password_step(email, senha)
        assert status in (400, 401), f"{email!r} -> {status} {headers.get('Location')}"


def caso_login_sem_token_csrf():
    """Envio de login sem o token CSRF é recusado."""
    b = Browser()
    b.get("/login")
    status, headers, _ = b.post("/login", {"email": ADMIN["email"], "senha": ADMIN["senha"]})
    assert goes_to_login(status, headers), f"status {status} {headers.get('Location')}"


def caso_senha_sozinha_nao_basta():
    """Depois da senha, sem o código MFA, o sistema continua fechado."""
    b, status, _, _ = password_step(ADMIN["email"], ADMIN["senha"])
    assert status == 302
    status, headers, _ = b.get("/dashboard")
    assert goes_to_login(status, headers), f"dashboard -> {status}"


def caso_codigo_mfa_errado_5_vezes():
    """Cinco códigos errados invalidam o desafio; o código certo deixa de valer."""
    b, _, _, since = password_step(ADMIN["email"], ADMIN["senha"])
    right = mfa_code(ADMIN["email"], since)
    wrong = f"{(int(right) + 1) % 1_000_000:06d}"
    token = b.csrf("/login/codigo")
    for _ in range(5):
        b.post("/login/codigo", {"_csrf": token, "codigo": wrong})
    b.post("/login/codigo", {"_csrf": token, "codigo": right})
    status, headers, _ = b.get("/dashboard")
    assert goes_to_login(status, headers), "entrou com código depois do bloqueio"


def caso_formulario_de_outro_site():
    """Com sessão válida, envios vindos de outro site (CSRF) são recusados."""
    b = login(ADMIN)
    token = b.csrf("/clients/new")
    for extra in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}):
        status, headers, _ = b.post("/clients/new", {"_csrf": token, "nome": "Vitima CSRF", "tipo_pessoa": "PF",
                                                    "ativo": "on"}, extra)
        assert goes_to_login(status, headers), f"{extra} -> {status}"
    _, _, text = b.get("/clients?q=Vitima")
    assert "Vitima CSRF" not in text, "cliente criado por requisição de outro site"


def caso_xss_armazenado():
    """Script gravado no nome de um cliente aparece escapado, nunca executável."""
    b = login(ADMIN)
    payload = '<script>alert("xss")</script>'
    status, headers, _ = b.post("/clients/new", {"_csrf": b.csrf("/clients/new"), "nome": payload,
                                                 "tipo_pessoa": "PF", "ativo": "on"})
    assert status == 302, f"cadastro -> {status}"
    for path in (urlsplit(headers["Location"]).path, "/clients"):
        _, _, text = b.get(path)
        assert payload not in text and "&lt;script&gt;" in text, f"{path} não escapou o script"


def caso_injecao_sql_na_busca():
    """Injeção de SQL nos filtros de busca não quebra nem expõe o banco."""
    b = login(ADMIN)
    for path in ("/clients?q=%27%20OR%201%3D1%20--", "/processes?q=%27%3B%20DROP%20TABLE%20processos%3B--",
                 "/processes?id_cliente=1%20OR%201%3D1", "/processes?status=%27%20OR%20%271%27%3D%271",
                 "/processes?valor_min=1%20OR%201=1", "/audit?page=1%27"):
        status, _, text = b.get(path)
        assert status == 200 and "Traceback" not in text and "sqlite3" not in text, f"{path} -> {status}"


def caso_path_traversal():
    """Tentativas de sair da pasta static para ler o código ou a chave falham."""
    b = Browser()
    for path in ("/static/../app.py", "/static/..%2fapp.py", "/static/%2e%2e/app.py",
                 "/static/..%2f..%2fdata/encryption.key", "/static/....//app.py"):
        status, _, text = b.get(path)
        assert not (status == 200 and ("import " in text or "def " in text)), f"{path} vazou arquivo"


def caso_upload_executavel_disfarcado():
    """Executável renomeado para .pdf é recusado pela assinatura do conteúdo."""
    b = login(ADMIN)
    _, headers, _ = b.post("/clients/new", {"_csrf": b.csrf("/clients/new"), "nome": "Cliente Upload",
                                            "tipo_pessoa": "PF", "ativo": "on"})
    client = urlsplit(headers["Location"]).path
    token = b.csrf(client)
    status, headers, text = b.follow(*b.upload(f"{client}/documents", {"_csrf": token, "titulo": "Malicioso"},
                                               "contrato.pdf", b"MZ\x90\x00\x03" + os.urandom(64)))
    assert "Envie um PDF" in text and "Malicioso" not in text, "executável aceito"


def caso_upload_gigante():
    """Arquivo acima de 10 MB é recusado antes de ser processado."""
    b = login(ADMIN)
    _, headers, _ = b.post("/clients/new", {"_csrf": b.csrf("/clients/new"), "nome": "Cliente Grande",
                                            "tipo_pessoa": "PF", "ativo": "on"})
    client = urlsplit(headers["Location"]).path
    token = b.csrf(client)
    try:
        resp = b.upload(f"{client}/documents", {"_csrf": token, "titulo": "Enorme"}, "g.pdf",
                        b"%PDF-1.4\n" + b"0" * (11 * 1024 * 1024))
    except (ConnectionError, OSError):
        return
    status, _, text = b.follow(*resp)
    assert "10 MB" in text and "Enorme" not in text, f"aceitou arquivo de 11 MB ({status})"


def caso_redirecionamento_aberto():
    """O parâmetro next não pode mandar o usuário para outro site."""
    b = login(ADMIN)
    for target in ("//evil.example", "https://evil.example/", "/\\evil.example"):
        token = b.csrf("/account")
        status, headers, _ = b.post("/account/toggle", {"_csrf": token, "kind": "font", "next": target})
        location = headers.get("Location", "")
        assert urlsplit(location).netloc in ("", f"localhost:{PORT}") and "evil" not in location, location


def caso_erros_sem_detalhes_internos():
    """Páginas inexistentes e IDs inválidos não mostram rastros de erro do Python."""
    b = login(ADMIN)
    for path in ("/processes/99999999", "/clients/99999999", "/nao-existe", "/documents/0/download",
                 "/process-files/99999999/preview"):
        status, _, text = b.get(path)
        assert status < 500 and "Traceback" not in text and "File \"" not in text, f"{path} -> {status}"


def caso_operador_sem_privilegios():
    """Operador não acessa usuários, auditoria, valores nem exclusões."""
    admin = login(ADMIN)
    status, _, _ = admin.post("/users/new", {"_csrf": admin.csrf("/users/new"), "nome": OPERADOR["nome"],
                                             "email": OPERADOR["email"], "senha": OPERADOR["senha"],
                                             "perfil": "OPERADOR", "ativo": "on"})
    assert status == 302, f"criação do operador -> {status}"
    _, headers, _ = admin.post("/clients/new", {"_csrf": admin.csrf("/clients/new"), "nome": "Cliente Protegido",
                                                "tipo_pessoa": "PF", "ativo": "on"})
    client = urlsplit(headers["Location"]).path
    op = login(OPERADOR)
    for path in ("/users", "/users/new", "/audit"):
        status, headers, _ = op.get(path)
        assert status == 302 and "/dashboard" in headers.get("Location", ""), f"operador abriu {path}"
    token = op.csrf(client)
    op.post(f"{client}/delete", {"_csrf": token, "confirmado": "1"})
    status, _, text = admin.get(client)
    assert status == 200 and "Cliente Protegido" in text, "operador conseguiu excluir cliente"


def caso_logout_encerra_sessao():
    """Depois de sair, o cookie antigo não abre mais o sistema."""
    b = login(ADMIN)
    old = dict(b.cookies)
    b.post("/logout", {"_csrf": b.csrf("/dashboard")})
    replay = Browser()
    replay.cookies = old
    status, headers, _ = replay.get("/dashboard")
    assert goes_to_login(status, headers), f"cookie antigo ainda vale ({status})"


def caso_forca_bruta_bloqueada():
    """Após 10 senhas erradas, a conta e o IP ficam bloqueados (429)."""
    statuses = [password_step(OPERADOR["email"], f"errada-{i}-xxxxxx")[1] for i in range(11)]
    assert statuses[-1] == 429, f"sem bloqueio: {statuses}"
    _, status, _, _ = password_step(OPERADOR["email"], OPERADOR["senha"])
    assert status == 429, "senha certa aceita durante o bloqueio"


def caso_servidor_continua_no_ar():
    """Depois de todos os ataques o servidor segue respondendo."""
    status, _, text = Browser().get("/health")
    assert status == 200 and json.loads(text)["status"] == "ok"


CASOS = [
    caso_cabecalhos_de_seguranca, caso_http_sem_tls_recusado, caso_host_falso, caso_metodos_nao_permitidos,
    caso_paginas_protegidas_sem_login, caso_senha_errada, caso_injecao_sql_no_login, caso_login_sem_token_csrf,
    caso_senha_sozinha_nao_basta, caso_codigo_mfa_errado_5_vezes, caso_formulario_de_outro_site,
    caso_xss_armazenado, caso_injecao_sql_na_busca, caso_path_traversal, caso_upload_executavel_disfarcado,
    caso_upload_gigante, caso_redirecionamento_aberto, caso_erros_sem_detalhes_internos,
    caso_operador_sem_privilegios, caso_logout_encerra_sessao,
    caso_forca_bruta_bloqueada,  # por último: bloqueia o IP por 15 minutos
    caso_servidor_continua_no_ar,
]


def preparar():
    admin_env = {**ENV, "ADMIN_NOME": ADMIN["nome"], "ADMIN_EMAIL": ADMIN["email"], "ADMIN_SENHA": ADMIN["senha"]}
    for cmd in (["setup"],):
        subprocess.run([sys.executable, "manage.py", *cmd], cwd=ROOT, env=admin_env, check=True,
                       stdout=subprocess.DEVNULL)
    log = LOG.open("w")
    server = subprocess.Popen([sys.executable, "app.py"], cwd=ROOT, env=ENV, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            if Browser().get("/health")[0] == 200:
                return server
        except (OSError, ssl.SSLError, http.client.HTTPException):
            pass
        if server.poll() is not None:
            break
        time.sleep(0.2)
    server.kill()
    sys.exit("O servidor não iniciou:\n" + LOG.read_text())


def main():
    server = preparar()
    falhas = 0
    try:
        for caso in CASOS:
            nome = caso.__name__.removeprefix("caso_").replace("_", " ")
            try:
                caso()
                print(f"PASS  {nome}")
            except (AssertionError, OSError, http.client.HTTPException, KeyError, TypeError) as erro:
                falhas += 1
                print(f"FAIL  {nome}: {caso.__doc__}\n      -> {erro}")
    finally:
        server.terminate()
        server.wait(timeout=10)
    print(f"\n{len(CASOS) - falhas} de {len(CASOS)} casos hostis passaram.")
    if falhas:
        print("\nLog do servidor:\n" + LOG.read_text()[-4000:])
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main()
