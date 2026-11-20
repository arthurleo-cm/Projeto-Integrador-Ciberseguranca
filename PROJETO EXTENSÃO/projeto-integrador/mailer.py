import ipaddress
import re
import smtplib
import socket
import ssl
from email.message import EmailMessage

# Modos: "smtp" envia de verdade; "console" mostra o código no terminal (só desenvolvimento);
# "test" guarda o código em memória para os testes automatizados.
mode = "console"
smtp = None
test_codes = {}

HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RETRYABLE = (ConnectionError, TimeoutError, socket.timeout, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected)


def configure(mfa_mode, env):
    global mode, smtp
    mode = mfa_mode
    smtp = None
    if mode != "smtp":
        return
    try:
        port = int(env.get("SMTP_PORT", "587"))
    except ValueError:
        port = 0
    smtp = {
        "host": env.get("SMTP_HOST", "").strip().lower(),
        "port": port,
        "user": env.get("SMTP_USER", ""),
        "password": env.get("SMTP_PASS", ""),
        "from": (env.get("SMTP_FROM") or env.get("SMTP_USER", "")).strip().lower(),
    }
    if (not re.fullmatch(r"[a-z0-9.-]+", smtp["host"]) or not 1 <= port <= 65535
            or not smtp["user"] or not smtp["password"]
            or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", smtp["from"])
            or any(c in v for v in (smtp["user"], smtp["password"]) for c in "\r\n\0")):
        raise SystemExit("Configure SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS e SMTP_FROM corretamente.")


def is_public_ip(address):
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public_host(host):
    # Proteção contra SSRF: o único destino externo do servidor (o SMTP) precisa resolver
    # somente para IPs públicos; respostas DNS mistas (público + privado) são recusadas.
    hostname = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(hostname)
        literal = True
    except ValueError:
        literal = False
    if not literal and not HOSTNAME.match(hostname):
        raise ValueError("Destino de rede inválido.")
    infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses or not all(is_public_ip(a) for a in addresses):
        raise ValueError("Destino de rede privado ou reservado recusado.")
    return sorted(addresses, key=lambda a: ":" in a)


def _tls_context():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class _PinnedSMTP(smtplib.SMTP):
    # Conecta no IP já validado, mas mantém o nome original para conferir o certificado TLS.
    def __init__(self, address):
        self.pinned_address = address
        super().__init__(timeout=15)

    def _get_socket(self, host, port, timeout):
        return socket.create_connection((self.pinned_address, port), timeout, self.source_address)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, address):
        self.pinned_address = address
        super().__init__(timeout=15, context=_tls_context())

    def _get_socket(self, host, port, timeout):
        sock = socket.create_connection((self.pinned_address, port), timeout, self.source_address)
        return self.context.wrap_socket(sock, server_hostname=self._host)


def _with_smtp(action):
    last_error = None
    for address in resolve_public_host(smtp["host"]):
        client = _PinnedSMTPSSL(address) if smtp["port"] == 465 else _PinnedSMTP(address)
        try:
            client.connect(smtp["host"], smtp["port"])
            if smtp["port"] != 465:
                client.ehlo()
                client.starttls(context=_tls_context())
                client.ehlo()
            client.login(smtp["user"], smtp["password"])
            result = action(client)
            client.quit()
            return result
        except RETRYABLE as error:
            last_error = error
        finally:
            try:
                client.close()
            except OSError:
                pass
    raise last_error or OSError("Nenhum endereço SMTP público disponível.")


def verify():
    if mode == "smtp":
        _with_smtp(lambda client: None)


def send_mfa_code(to, code):
    if mode == "test":
        test_codes[to] = code
        return
    if mode == "console":
        print(f"[MFA desenvolvimento] {to}: {code}", flush=True)
        return
    message = EmailMessage()
    message["From"] = f"Marquezi Gestão <{smtp['from']}>"
    message["To"] = to
    message["Subject"] = "Código de acesso — Marquezi Gestão"
    message.set_content(
        f"Seu código de acesso é {code}.\n\n"
        "Ele expira em 10 minutos e só pode ser usado uma vez. "
        "Se você não tentou entrar, ignore esta mensagem e avise o administrador."
    )
    _with_smtp(lambda client: client.send_message(message, from_addr=smtp["from"], to_addrs=[to]))
