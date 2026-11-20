#!/usr/bin/env python3
"""Comandos de administração do Marquezi Gestão. Uso: python manage.py <comando>

  setup                         cria a pasta data/, a chave de cifragem, o banco, o certificado HTTPS e o primeiro administrador
  tls [--renew]                 gera um certificado HTTPS local (localhost) válido por 1 ano
  smtp [--replace]              configura a conta Gmail que envia os códigos de acesso (MFA)
  backup DESTINO                copia o banco e a chave de cifragem para uma pasta nova
  demo --confirm-demo-data      cria usuários, clientes e processos fictícios para treinamento
  dns                           cria o registro DNS na Name.com apontando para o IP público atual
"""
import base64
import getpass
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "advocacia.sqlite"
KEY_PATH = DATA_DIR / "encryption.key"
SCHEMA_PATH = BASE_DIR / "database" / "schema.sqlite.sql"

os.umask(0o077)


def fail(message):
    raise SystemExit(message)


def open_db():
    if not KEY_PATH.exists() or not DB_PATH.exists():
        fail("Execute primeiro: python manage.py setup")
    import crypto_utils
    crypto_utils.load_key(str(KEY_PATH))
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


# --- setup ---

def cmd_setup(args):
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DATA_DIR, 0o700)
    if KEY_PATH.exists():
        print(f"Chave de cifragem já existe em {KEY_PATH}")
    elif DB_PATH.exists():
        fail("Existe um banco sem chave. Por segurança, nenhuma chave nova será gerada sobre ele.")
    else:
        KEY_PATH.write_bytes(secrets.token_bytes(32))
        os.chmod(KEY_PATH, 0o600)
        print(f"Chave de cifragem gerada em {KEY_PATH}. Guarde um backup: sem ela os dados são irrecuperáveis.")

    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA_PATH.read_text())
    os.chmod(DB_PATH, 0o600)
    print(f"Banco de dados pronto em {DB_PATH}")
    if not (DATA_DIR / "tls" / "localhost-cert.pem").exists():
        cmd_tls([])  # HTTPS por padrão: certificado autoassinado para localhost
    if db.execute("SELECT count(*) FROM usuarios WHERE perfil='ADMINISTRADOR' AND ativo=1").fetchone()[0]:
        print("Já existe um administrador ativo. Nada mais a fazer.")
        return

    import crypto_utils
    from validators import validate_password, ValidationError
    crypto_utils.load_key(str(KEY_PATH))
    # Uso automatizado (ex.: pipeline do GitHub Actions): ADMIN_NOME, ADMIN_EMAIL e ADMIN_SENHA.
    automatico = all(os.environ.get(v) for v in ("ADMIN_NOME", "ADMIN_EMAIL", "ADMIN_SENHA"))
    if not automatico:
        print("\nCrie a conta do primeiro administrador. O e-mail precisa receber mensagens: é para ele que vai o código de acesso.\n")
    nome = (os.environ["ADMIN_NOME"] if automatico else input("Nome completo: ")).strip()
    if len(nome) < 2:
        fail("Nome deve ter ao menos 2 caracteres.")
    email = (os.environ["ADMIN_EMAIL"] if automatico else input("E-mail: ")).strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        fail("E-mail inválido.")
    while True:
        senha = os.environ["ADMIN_SENHA"] if automatico else getpass.getpass("Senha (mínimo 12 caracteres, entrada oculta): ")
        try:
            validate_password(senha)
        except ValidationError as e:
            if automatico:
                fail(str(e))
            print(f"  {e}")
            continue
        if not automatico and getpass.getpass("Confirme a senha: ") != senha:
            print("  As senhas não correspondem.")
            continue
        break
    try:
        db.execute(
            "INSERT INTO usuarios(dados, email_indice, senha_hash, perfil, ativo) VALUES(?,?,?,?,1)",
            (crypto_utils.pack({"nome": nome, "email": email}, "usuario"), crypto_utils.hmac_index(email),
             crypto_utils.hash_password(senha), "ADMINISTRADOR"),
        )
        db.commit()
    except sqlite3.IntegrityError:
        fail("E-mail já cadastrado.")
    print(f"\nAdministrador '{nome}' criado. Para iniciar: python app.py")


# --- tls ---

def cmd_tls(args):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    tls_dir = DATA_DIR / "tls"
    cert_file, key_file = tls_dir / "localhost-cert.pem", tls_dir / "localhost-key.pem"
    if (cert_file.exists() or key_file.exists()) and "--renew" not in args:
        fail("O certificado local já existe. Use: python manage.py tls --renew")
    tls_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(tls_dir, 0o700)

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(key_file, 0o600)
    os.chmod(cert_file, 0o600)
    print(f"HTTPS local configurado. Certificado: {cert_file}")
    print("Inicie com python app.py e acesse https://localhost:5000 (aceite o aviso do certificado local).")


# --- smtp ---

def cmd_smtp(args):
    if not sys.stdin.isatty():
        fail("Execute em um terminal interativo para manter a senha de app oculta.")
    env_file = DATA_DIR / "smtp.env"
    if env_file.exists() and "--replace" not in args:
        fail("A configuração SMTP já existe. Use: python manage.py smtp --replace")
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    email = input("Conta Gmail remetente: ").strip().lower()
    if not re.fullmatch(r"[^\s@]+@gmail\.com", email):
        fail("Informe um endereço @gmail.com válido.")
    app_password = re.sub(r"\s", "", getpass.getpass("Senha de app do Google (entrada oculta): "))
    if not re.fullmatch(r"[A-Za-z0-9]{16}", app_password):
        fail("A senha de app do Google tem 16 caracteres.")
    tmp = env_file.with_name(f"smtp.env.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"MFA_MODE=smtp\nSMTP_HOST=smtp.gmail.com\nSMTP_PORT=465\n"
                f"SMTP_USER={email}\nSMTP_PASS={app_password}\nSMTP_FROM={email}\n")
    os.replace(tmp, env_file)
    print(f"SMTP configurado em {env_file}. Ao iniciar, o servidor valida a conexão.")


# --- backup ---

def cmd_backup(args):
    if not args:
        fail("Uso: python manage.py backup /caminho/da/pasta/nova")
    target = Path(args[0]).resolve()
    target.mkdir(mode=0o700)
    db = open_db()
    dest = sqlite3.connect(str(target / "advocacia.sqlite"))
    db.backup(dest)
    dest.close()
    db.close()
    (target / "encryption.key").write_bytes(KEY_PATH.read_bytes())
    for f in ("advocacia.sqlite", "encryption.key"):
        os.chmod(target / f, 0o600)
    print(f"Backup concluído em {target}. Proteja a pasta: ela contém a chave de recuperação.")


# --- demo ---

def _cnj(sequence, year, segment, court, origin):
    base = f"{sequence:07d}{year}{segment}{court:02d}{origin:04d}"
    check = f"{98 - int(base + '00') % 97:02d}"
    return base[:7] + check + base[7:]


def cmd_demo(args):
    if "--confirm-demo-data" not in args:
        fail("Esta operação inclui dados fictícios. Execute: python manage.py demo --confirm-demo-data")
    import crypto_utils
    from crypto_utils import pack, unpack, hmac_index, hash_password
    from validators import validate_client, validate_contact, validate_address, validate_process
    db = open_db()
    admin = db.execute("SELECT id_usuario FROM usuarios WHERE ativo=1 AND perfil='ADMINISTRADOR' ORDER BY id_usuario LIMIT 1").fetchone()
    if not admin:
        fail("Crie um administrador primeiro: python manage.py setup")
    admin_id = admin["id_usuario"]

    def audit(action, table, record):
        db.execute("INSERT INTO logs_auditoria(id_usuario,acao,tabela_afetada,id_registro) VALUES(?,?,?,?)",
                   (admin_id, action, table, record))

    credentials = []
    for nome, email in [("Ana Rodrigues", "ana.rodrigues@marquezi.example"),
                        ("Carlos Mendes", "carlos.mendes@marquezi.example"),
                        ("Júlia Nascimento", "julia.nascimento@marquezi.example")]:
        if db.execute("SELECT 1 FROM usuarios WHERE email_indice=?", (hmac_index(email),)).fetchone():
            continue
        senha = "Demo-2026-" + secrets.token_urlsafe(12)
        cur = db.execute("INSERT INTO usuarios(dados,email_indice,senha_hash,perfil,ativo) VALUES(?,?,?,'OPERADOR',1)",
                         (pack({"nome": nome, "email": email}, "usuario"), hmac_index(email), hash_password(senha)))
        audit("CADASTRO", "usuarios", cur.lastrowid)
        credentials.append((nome, email, senha))

    obs = "Cadastro de demonstração com informações inteiramente fictícias."
    clients = [
        {"nome": "Marina Alves", "tipo_pessoa": "PF", "data_nascimento": "1988-04-12",
         "contatos": [("EMAIL", "marina.alves@example.com"), ("WHATSAPP", "+5511999990001"), ("INSTAGRAM", "@marina.exemplo")],
         "enderecos": [{"tipo": "RESIDENCIAL", "cep": "01310100", "logradouro": "Rua Exemplo", "numero": "120",
                        "complemento": "Apto. 31", "bairro": "Bela Vista", "cidade": "São Paulo", "uf": "SP"}]},
        {"nome": "João Carvalho", "tipo_pessoa": "PF", "data_nascimento": "1979-11-23",
         "contatos": [("EMAIL", "joao.carvalho@example.com")], "enderecos": []},
        {"nome": "Beatriz Lima", "tipo_pessoa": "PF", "data_nascimento": "1995-07-08", "ativo": False,
         "contatos": [("EMAIL", "beatriz.lima@example.com")], "enderecos": []},
        {"nome": "Horizonte Tecnologia Ltda.", "tipo_pessoa": "PJ",
         "contatos": [("EMAIL", "juridico@horizonte.example"), ("LINKEDIN", "https://www.linkedin.com/company/horizonte-example")],
         "enderecos": [{"tipo": "COMERCIAL", "cep": "13010000", "logradouro": "Avenida Modelo", "numero": "850",
                        "complemento": "Conjunto 42", "bairro": "Centro", "cidade": "Campinas", "uf": "SP"}]},
        {"nome": "Café Aurora Comércio Ltda.", "tipo_pessoa": "PJ",
         "contatos": [("EMAIL", "contato@cafeaurora.example"), ("SITE", "https://cafeaurora.example")], "enderecos": []},
    ]
    existing = {unpack(bytes(r["dados"]), "cliente")["nome"]: r["id_cliente"]
                for r in db.execute("SELECT id_cliente, dados FROM clientes")}
    clients_created = 0
    for c in clients:
        if c["nome"] in existing:
            continue
        v = validate_client({"tipo_pessoa": c["tipo_pessoa"], "nome": c["nome"], "cpf_cnpj": "",
                             "data_nascimento": c.get("data_nascimento", ""), "observacoes": obs,
                             "ativo": "on" if c.get("ativo", True) else ""})
        data = {k: v[k] for k in ("tipo_pessoa", "nome", "cpf_cnpj", "data_nascimento", "observacoes")}
        cid = db.execute("INSERT INTO clientes(dados,documento_indice,ativo) VALUES(?,NULL,?)",
                         (pack(data, "cliente"), int(v["ativo"]))).lastrowid
        for tipo, valor in c["contatos"]:
            ct = validate_contact({"tipo": tipo, "valor": valor, "principal": "on"})
            db.execute("INSERT INTO contatos(id_cliente,tipo,dados,valor_indice,principal) VALUES(?,?,?,?,1)",
                       (cid, ct["tipo"], pack({"valor": ct["valor"]}, "contato"), hmac_index(ct["valor"])))
        for e in c["enderecos"]:
            ad = validate_address({**e, "principal": "on"})
            ad.pop("principal")
            db.execute("INSERT INTO enderecos(id_cliente,dados,principal) VALUES(?,?,1)", (cid, pack(ad, "endereco")))
        audit("CADASTRO", "clientes", cid)
        existing[c["nome"]] = cid
        clients_created += 1

    processes = [
        ("Marina Alves", _cnj(1234, 2026, 8, 26, 100), "Cobrança de obrigação contratual", "EM_ANDAMENTO",
         "CIVEL", "COBRANCA", "2026-02-03", "18500.00", "Processo e valores inteiramente fictícios para demonstração.", 350000),
        ("Horizonte Tecnologia Ltda.", _cnj(2781, 2026, 8, 26, 101), "Revisão de contrato empresarial", "EM_ANALISE",
         "EMPRESARIAL", "CONTRATOS", "2026-03-18", "78000.00", "Processo fictício para treinamento da equipe.", 0),
        ("João Carvalho", _cnj(3150, 2025, 4, 3, 6100), "Revisão de benefício previdenciário", "AGUARDANDO_DECISAO",
         "PREVIDENCIARIO", "REVISAO_BENEFICIO", "2025-11-10", "24000.00", "Dados fictícios; não correspondem a processo judicial real.", 0),
    ]
    processes_created = 0
    for cliente, cnj, titulo, status, ramo, tip, abertura, valor, observ, recebido in processes:
        if db.execute("SELECT 1 FROM processos WHERE numero_indice=?", (hmac_index(cnj),)).fetchone():
            continue
        v = validate_process({"id_cliente": str(existing[cliente]), "numero_cnj": cnj, "titulo": titulo,
                              "status": status, "ramo": ramo, "tipificacao": tip, "situacao": "ATIVO",
                              "data_abertura": abertura, "valor_estimado": valor, "observacoes": observ}, is_admin=True)
        data = {k: v[k] for k in ("numero_cnj", "titulo", "observacoes", "previsao_recebimento", "orgao", "numero_oab",
                                  "data_publicacao", "data_disponibilizacao", "ultima_movimentacao", "intimacao")}
        data.update(associados=[], jurisprudencia=[])
        pid = db.execute(
            "INSERT INTO processos(id_cliente,numero_indice,dados,status,ramo,tipificacao,situacao,data_abertura,valor_estimado_centavos) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (v["id_cliente"], hmac_index(cnj), pack(data, "processo"), v["status"], v["ramo"], v["tipificacao"],
             v["situacao"], v["data_abertura"], v["valor_estimado_centavos"]),
        ).lastrowid
        db.execute("INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
                   (pid, admin_id, pack({"evento": "PROCESSO_CADASTRADO", "status_atual": status}, f"historico:{pid}")))
        if recebido:
            db.execute("INSERT INTO recebimentos(id_processo,id_usuario,dados,valor_centavos,data_recebimento) VALUES(?,?,?,?,?)",
                       (pid, admin_id, pack({"observacao": "Recebimento fictício de demonstração"}, f"recebimento:{pid}"),
                        recebido, "2026-03-05"))
        audit("CADASTRO", "processos", pid)
        processes_created += 1
    db.commit()
    db.close()

    print(f"Demonstração pronta: {len(credentials)} usuários, {clients_created} clientes e {processes_created} processos criados.")
    if credentials:
        print("Credenciais geradas (guarde agora; as senhas não são recuperáveis):")
        for nome, email, senha in credentials:
            print(f"- {nome}: {email} / {senha}")
    else:
        print("Os usuários de demonstração já existiam; nenhuma senha foi alterada.")
    print("Todos os usuários de demonstração têm somente o perfil OPERADOR. Os e-mails .example não recebem o código MFA;")
    print("para testá-los, rode com MFA_MODE=console.")


# --- dns ---

def cmd_dns(args):
    domain = os.environ.get("DNS_DOMAIN", "marquezi.com")
    host = os.environ.get("DNS_HOST", "gestao")
    cred_file = Path(os.environ.get("CREDENTIALS_FILE", BASE_DIR / "credenciais.txt"))
    raw = cred_file.read_text(encoding="utf-8") if cred_file.exists() else ""

    def field(label):
        m = re.search(rf"^{label}\s*:\s*(.+)$", raw, re.I | re.M)
        return m.group(1).strip() if m else None

    username = os.environ.get("NAMECOM_USERNAME") or field(r"Usuário Name\.com") or field("E-mail")
    token = os.environ.get("NAMECOM_API_TOKEN") or field("Token API")
    if not username or not token:
        fail("Informe 'Usuário Name.com' e 'Token API' no arquivo de credenciais, "
             "ou use NAMECOM_USERNAME e NAMECOM_API_TOKEN.")

    def request(url, method="GET", body=None, headers=None):
        req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()

    public_ip = os.environ.get("PUBLIC_IPV4") or request("https://api.ipify.org")[1].decode().strip()
    try:
        if ipaddress.ip_address(public_ip).version != 4:
            raise ValueError
    except ValueError:
        fail("Não foi possível detectar um IPv4 público válido.")

    auth = base64.b64encode(f"{username}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    endpoint = f"https://api.name.com/v4/domains/{urllib.parse.quote(domain)}/records"
    try:
        records = json.loads(request(endpoint, headers=headers)[1]).get("records", [])
    except urllib.error.HTTPError as e:
        fail(f"A API da Name.com recusou a consulta (HTTP {e.code}). Confira o token e a liberação de API com 2FA.")
    fqdn = f"{host}.{domain}".lower()
    same = [r for r in records if str(r.get("host", "")).lower() == host.lower()
            or str(r.get("fqdn", "")).rstrip(".").lower() == fqdn]
    if any(r.get("type") == "A" and r.get("answer") == public_ip for r in same):
        print(f"{fqdn} já aponta para o IPv4 público atual; nenhuma alteração foi feita.")
        return
    if same:
        fail(f"{fqdn} já possui um registro diferente. Por segurança, nenhuma alteração foi feita.")
    try:
        request(endpoint, "POST", json.dumps({"host": host, "type": "A", "answer": public_ip, "ttl": 300}).encode(),
                {**headers, "Content-Type": "application/json"})
    except urllib.error.HTTPError as e:
        fail(f"A criação do registro DNS falhou (HTTP {e.code}).")
    print(f"{fqdn} foi configurado para o IPv4 público atual (TTL 300).")


COMMANDS = {"setup": cmd_setup, "tls": cmd_tls, "smtp": cmd_smtp, "backup": cmd_backup, "demo": cmd_demo, "dns": cmd_dns}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(1)
    COMMANDS[sys.argv[1]](sys.argv[2:])
