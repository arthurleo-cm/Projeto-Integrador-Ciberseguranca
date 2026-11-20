# Evidências de segurança — onde está e como conferir

Este documento mostra, controle por controle, **onde** a proteção foi implementada, **como** funciona e **como qualquer pessoa pode conferir** que ela está ativa. O resumo dos controles está em [SEGURANCA.md](SEGURANCA.md).

Os resultados mostrados foram obtidos rodando o sistema de verdade. As referências `arquivo:linha` apontam para a versão atual do código; se o código mudar, procure pelo nome da função indicado.

---

## Como preparar a conferência

Na pasta do projeto, com o ambiente virtual ativo:

```sh
python manage.py setup     # cria banco, chave, administrador e o certificado HTTPS
python app.py              # sobe em https://localhost:5000
```

> Se a instalação é anterior ao HTTPS automático e não existe `data/tls/`, rode `python manage.py tls` uma vez e reinicie.

Em outro terminal, na mesma pasta, defina o certificado para o `curl` confiar nele (assim a verificação TLS fica **ligada**, sem `-k`):

```sh
C=data/tls/localhost-cert.pem
B=https://localhost:5000
```

Ferramentas usadas: `curl`, `openssl` e o próprio Python. No navegador, use as Ferramentas do Desenvolvedor (**F12**).

---

## 1. HTTPS com certificado autoassinado

**Onde**
- Geração do certificado: `manage.py:115` (`cmd_tls`) — chamada automaticamente pelo `setup` (`manage.py:69`).
- Servidor HTTPS: `app.py:1781-1787` (dentro de `main`).
- Decisão de usar TLS: `app.py:67-81` (`TLS_MODE`, `DIRECT_TLS`, `SECURE`).

**Como funciona**

```python
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)        # manage.py:128
...
.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
    x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1"))]), ...)
.sign(key, hashes.SHA256())                                                 # manage.py:146
```

```python
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)                           # app.py:1784
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(TLS_CERT, TLS_KEY)
```

**Como conferir — certificado**

```sh
openssl x509 -in $C -noout -subject -dates -ext subjectAltName,keyUsage,extendedKeyUsage,basicConstraints
openssl x509 -in $C -noout -text | grep -E "Public-Key|Signature Algorithm" | head -2
```

Resultado obtido:

```text
subject=CN=localhost
notBefore=Nov 20 21:21:57 2026 GMT
notAfter=Nov 20 21:26:57 2027 GMT
X509v3 Basic Constraints: critical
    CA:FALSE
X509v3 Key Usage: critical
    Digital Signature, Key Encipherment
X509v3 Extended Key Usage:
    TLS Web Server Authentication
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
        Signature Algorithm: sha256WithRSAEncryption
                Public-Key: (3072 bit)
```

**Como conferir — protocolo e cifra**

```sh
echo | openssl s_client -connect localhost:5000 -servername localhost -CAfile $C 2>/dev/null | grep -E "^New,|Verify return code"
echo | openssl s_client -connect localhost:5000 -tls1_2 -CAfile $C 2>/dev/null | grep "^New,"
echo | openssl s_client -connect localhost:5000 -tls1_1 2>&1 | grep -E "alert|Cipher is"
```

Resultado obtido:

```text
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Verify return code: 0 (ok)
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
... tlsv1 alert protocol version ... SSL alert number 70
New, (NONE), Cipher is (NONE)
```

TLS 1.3 com AES-256-GCM, TLS 1.2 só com troca de chaves ECDHE (sigilo futuro) e cifra autenticada, e TLS 1.1 **recusado**.

**No navegador:** clique no cadeado da barra de endereço → *Conexão segura* → *Mais informações* (Firefox) ou F12 → aba **Segurança/Security** (Chrome): aparece `TLS 1.3` e `AES_256_GCM`. O aviso de "certificado não confiável" na primeira visita é esperado, porque é autoassinado.

**Proteção da chave privada** (`app.py:1782`): o sistema se recusa a iniciar se a chave puder ser lida por outros usuários. Confira com `ls -l data/tls/` → `-rw-------`.

---

## 2. HTTP puro, Host falso, redirecionamento e métodos

**Onde:** `app.py:179` (`network_guard`).

```python
if request.method not in ("GET", "HEAD", "POST"):
    return "Método não permitido.", 405, {"Allow": "GET, HEAD, POST"}
if SECURE:
    if request.host.lower() != EXPECTED_HOST:
        return "Destino HTTP inválido.", 421, ...
    if not request.is_secure:
        if request.method in ("GET", "HEAD"):
            return redirect(f"https://{EXPECTED_HOST}{request.full_path.rstrip('?')}", 308)
        return "Use uma conexão HTTPS.", 400
```

**Como conferir**

```sh
curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 http://localhost:5000/login        # HTTP puro
curl -s --cacert $C -o /dev/null -w "%{http_code}\n" -H "Host: evil.example" $B/login    # Host falso
curl -s --cacert $C -o /dev/null -w "%{http_code}\n" -X PUT $B/login                     # método proibido
```

Resultado obtido:

```text
000      ← a porta só fala TLS: HTTP puro não recebe página
421      ← Host diferente do domínio do sistema
405      ← PUT, DELETE, PATCH, TRACE e OPTIONS são recusados
```

---

## 3. Cabeçalhos de segurança

**Onde:** `app.py:225` (`security_headers`, executado depois de **toda** resposta via `@app.after_request`).

```python
h["X-Content-Type-Options"] = "nosniff"
h["X-Frame-Options"] = "DENY"
h["Referrer-Policy"] = "same-origin"
h["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"
h["Cross-Origin-Opener-Policy"] = "same-origin"
h["Cross-Origin-Embedder-Policy"] = "require-corp"
h["Cross-Origin-Resource-Policy"] = "same-origin"
h["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; ...")
h["Permissions-Policy"] = ("accelerometer=(), autoplay=(), camera=(), ...")
if SECURE:
    h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
if request.endpoint != "static":
    h["Cache-Control"] = "no-store"
```

**Como conferir**

```sh
curl -s --cacert $C -D - -o /dev/null $B/login
```

Resultado obtido:

```text
HTTP/1.1 200 OK
Server: Marquezi
Content-Type: text/html; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: same-origin
X-Robots-Tag: noindex, nofollow, noarchive, nosnippet
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy: default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; upgrade-insecure-requests
Permissions-Policy: accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Cache-Control: no-store
Set-Cookie: __Host-sessao=...; Secure; HttpOnly; Path=/; SameSite=Strict
```

**No navegador:** F12 → aba **Rede/Network** → recarregue a página → clique na requisição `login` → **Cabeçalhos de resposta**.

**Prova de que a CSP funciona:** abra o console (F12 → **Console**) e tente injetar um script inline, por exemplo colando:

```js
document.body.insertAdjacentHTML("beforeend", '<img src=x onerror="alert(1)">')
```

O alerta **não** aparece e o console mostra um erro de *Content Security Policy* bloqueando o evento inline.

**Cabeçalho `Server` sem versões** (`app.py:1794`, `_QuietHandler`): o servidor HTTP do Python anunciaria `Server: Werkzeug/3.1.9 Python/3.14.8`. O manipulador próprio troca isso por `Server: Marquezi`, como aparece na saída acima.

---

## 4. Cookie de sessão

**Onde:** `app.py:106-114` (configuração) e `app.py:120` (chave do cookie).

```python
SESSION_COOKIE_NAME="__Host-sessao" if SECURE else "sessao",
SESSION_COOKIE_HTTPONLY=True,
SESSION_COOKIE_SECURE=SECURE,
SESSION_COOKIE_SAMESITE="Strict",
PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
...
app.secret_key = hmac.new(KEY_PATH.read_bytes(), b"flask-session-cookie", hashlib.sha256).digest()
```

**Como conferir:** na saída do item 3 aparece `Set-Cookie: __Host-sessao=...; Secure; HttpOnly; Path=/; SameSite=Strict`. No navegador: F12 → **Armazenamento/Application** → **Cookies** → `https://localhost:5000`: as colunas *HttpOnly*, *Secure* e *SameSite = Strict* aparecem marcadas. No console, `document.cookie` retorna vazio, porque o JavaScript não consegue ler o cookie.

O cookie só carrega IDs. A sessão de verdade fica na tabela `sessoes` e é conferida a cada requisição (`app.py:255`, `current_user`); por isso, apagar a sessão no servidor derruba o login na hora.

---

## 5. Criptografia dos dados (AES-256-GCM)

**Onde:** `crypto_utils.py:18-42` (`encrypt`, `decrypt`, `pack`, `unpack`); chave gerada em `manage.py:52-61`.

```python
def encrypt(plaintext, context):
    iv = os.urandom(12)                                   # nonce aleatório de 96 bits por registro
    aesgcm = AESGCM(_key)                                 # chave de 256 bits
    ct_with_tag = aesgcm.encrypt(iv, plaintext, context.encode())   # context = dado associado (AAD)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]                               # tag de autenticação de 128 bits
    return iv + tag + ciphertext
```

**Como conferir — o banco não tem texto claro**

```sh
python3 - <<'EOF'
import sqlite3
db = sqlite3.connect("data/advocacia.sqlite")
r = db.execute("SELECT hex(substr(dados,1,40)), email_indice, senha_hash FROM usuarios").fetchone()
print("dados  :", r[0])
print("índice :", r[1])
print("senha  :", r[2][:60] + "...")
print("o e-mail aparece no arquivo?", b"SEU_EMAIL_AQUI" in open("data/advocacia.sqlite", "rb").read())
EOF
```

Resultado obtido (troque `SEU_EMAIL_AQUI` pelo e-mail do administrador):

```text
dados  : 0B4209B3D2C2273F60E79F9C8644061B56405560E5D91B6F4F673CB9F69290771D83E2BB815B918E
índice : 79cc22f76c7498bb809c7dcbf5ad55c5966a0d2c9c1b0ee8231fca9017e66b7e
senha  : scrypt:32768:8:3:36ca7bb49564736b575562ef102a1aea:ab19316c6cc5233ce4a3e716...
o e-mail aparece no arquivo? False
```

**Como conferir — integridade (GCM detecta adulteração)**

```sh
python3 - <<'EOF'
import sqlite3, crypto_utils
crypto_utils.load_key("data/encryption.key")
blob = bytearray(sqlite3.connect("data/advocacia.sqlite").execute("SELECT dados FROM usuarios").fetchone()[0])
print("com a chave certa:", crypto_utils.unpack(bytes(blob), "usuario")["email"])
try: crypto_utils.unpack(bytes(blob), "cliente")
except Exception as e: print("contexto errado:", type(e).__name__)
blob[40] ^= 1
try: crypto_utils.unpack(bytes(blob), "usuario")
except Exception as e: print("1 byte alterado:", type(e).__name__)
EOF
```

Resultado obtido:

```text
com a chave certa: admin@evidencia.example
contexto errado: InvalidTag
1 byte alterado: InvalidTag
```

Um bloco cifrado de usuário não pode ser reaproveitado como dado de cliente, e alterar um único bit faz a leitura falhar em vez de devolver dado corrompido.

---

## 6. Índices de busca com HMAC

**Onde:** `crypto_utils.py:45` (`hmac_index`); colunas `email_indice`, `documento_indice`, `numero_indice` e `valor_indice` com `UNIQUE` em `database/schema.sqlite.sql`.

```python
def hmac_index(value):
    return hmac.new(_key, ("lookup:" + value).encode(), hashlib.sha256).hexdigest()
```

**Como conferir:** a coluna `índice` do item 5 é um HMAC-SHA256 (64 caracteres hexadecimais). Tente cadastrar dois clientes com o mesmo CPF: o segundo é recusado com "CPF/CNPJ ou contato já cadastrado", mesmo o CPF estando cifrado, porque o índice é `UNIQUE`.

---

## 7. Senhas com scrypt

**Onde:** `crypto_utils.py:49-72` (`hash_password`, `verify_password`); política em `validators.py:124` (`validate_password`).

```python
h = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=3, dklen=64, ...)
return f"scrypt:32768:8:3:{salt}:{h.hex()}"
...
return hmac.compare_digest(actual.hex(), expected)        # comparação em tempo constante
```

**Como conferir:** a linha `senha` do item 5 mostra o formato `scrypt:N:r:p:salt:hash`. Dois usuários com a mesma senha têm hashes diferentes, porque o salt é aleatório.

**Enumeração de contas** (`app.py:428` e `login`): quando o e-mail não existe, um hash falso (`_DUMMY_HASH`) é verificado mesmo assim, e a mensagem é sempre "E-mail ou senha inválidos.".

---

## 8. Verificação em duas etapas (MFA)

**Onde:** `app.py:425-650` — `login` (gera o desafio), `login_mfa` (confere o código), `login_mfa_resend` (reenvio), `_usable_challenge` (validade); envio em `mailer.py:122`.

```python
MFA_LIFETIME_MS = 10 * 60 * 1000      # expira em 10 minutos
MFA_RESEND_MS = 60 * 1000             # reenvio só depois de 60 s
...
code = f"{secrets.randbelow(1_000_000):06d}"                      # gerador criptográfico
... _mfa_code_hash(challenge, code) ...                           # só o HMAC é gravado
if not re.fullmatch(r"\d{6}", code) or not hmac.compare_digest(row["codigo_hash"], ...):
    attempts = row["tentativas"] + 1                              # 5 erros apagam o desafio
```

**Como conferir na tela:** depois da senha o sistema abre "Código de acesso" e **não** entra no painel. Abrir `https://localhost:5000/dashboard` nessa hora volta para o login.

**Como conferir no banco:** com um login pendente, a tabela `desafios_mfa` guarda só hashes:

```text
{'token_hash': 'e1282d3b30a2dbf05dea07d2e5a4807f0725871ce429773e4a7cc077c1b1575a',
 'codigo_hash': '575f912c1565f6205540d25de3e598148d4a7c7497d2bbdebaf73bad05e01f1d',
 'ip_indice': '1f92c0dd55cd24a70404127924b288b89c9bd9fd9ae86555c604de2e946ec168',
 'senha_indice': 'bd351f15b24685efa0e52d757b45ddd7ea47ee3f34f08194f71b699b52ed77d3',
 'tentativas': 0, 'validade_ms': 600000}
código no terminal: 359877
código 359877 aparece em algum arquivo do banco? False
```

`ip_indice` liga o desafio ao IP, e `senha_indice` à senha atual: se a senha mudar, o código deixa de valer.

**Testes que comprovam:** `test_mfa_obrigatorio`, `test_mfa_limite_de_tentativas` e `test_codigo_nao_reutilizavel` (em `tests/test_app.py`), e os casos do DAST *senha sozinha não basta* e *código MFA errado 5 vezes*.

---

## 9. Força bruta e limite de requisições

**Onde:** `app.py:440-452` (`_bump`, `_blocked`) e `login` — 10 tentativas por conta e por IP; `app.py:206` (`rate_limit`) — 600 requisições a cada 5 minutos por IP.

**Como conferir**

```sh
for i in $(seq 1 11); do
  J=$(mktemp)
  T=$(curl -s --cacert $C -c $J -b $J $B/login | grep -oP 'name="_csrf" value="\K[^"]+')
  printf "%s " $(curl -s --cacert $C -c $J -b $J -o /dev/null -w "%{http_code}" -H "Origin: $B" \
    --data-urlencode "_csrf=$T" --data-urlencode "email=SEU_EMAIL_AQUI" --data-urlencode "senha=errada$i-xxxxxx" $B/login)
  rm -f $J
done; echo
```

Resultado obtido:

```text
401 401 401 401 401 401 401 401 401 401 429
```

A 11ª tentativa recebe **429** e a tela mostra "Muitas tentativas. Aguarde 15 minutos." O bloqueio fica gravado na tabela `tentativas`, então reiniciar o servidor não o remove. (Atenção: esse teste bloqueia sua conta e seu IP por 15 minutos.)

---

## 10. CSRF

**Onde:** `app.py:296-309` (`csrf_protect`, `enforce_csrf`) e `app.py:189-195` (checagem de `Origin` e `Sec-Fetch-Site` em `network_guard`). Todo formulário POST tem `<input type="hidden" name="_csrf" value="{{ csrf_token }}">`.

```python
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf", "")
        if not token or not expected or not secrets.compare_digest(token, expected):
            abort(403)
```

**Como conferir**

```sh
J=$(mktemp); curl -s --cacert $C -c $J -b $J -o /dev/null $B/login
# 1) sem token
curl -s --cacert $C -c $J -b $J -o /dev/null -w "%{http_code} -> %{redirect_url}\n" -H "Origin: $B" --data "email=a@b.com&senha=x" $B/login
# 2) com token válido, mas vindo de outro site
T=$(curl -s --cacert $C -c $J -b $J $B/login | grep -oP 'name="_csrf" value="\K[^"]+')
curl -s --cacert $C -c $J -b $J -o /dev/null -w "%{http_code} -> %{redirect_url}\n" -H "Origin: https://evil.example" --data "_csrf=$T&email=a@b.com&senha=x" $B/login
```

Resultado obtido:

```text
302 -> https://localhost:5000/login     ← recusado (sem token)
302 -> https://localhost:5000/login     ← recusado (Origin de outro site)
```

No navegador, a tela mostra "O formulário expirou ou veio de outra página. Tente de novo." Ver o código-fonte da página (Ctrl+U) mostra o campo oculto `_csrf` em cada formulário.

**Verificação automática:** a regra de SAST `formulario-sem-csrf` falha o pipeline se algum template tiver um formulário POST sem esse campo.

---

## 11. Injeção de SQL

**Onde:** todas as consultas de `app.py` e `manage.py` usam `?` com os valores separados. Exemplo da lista de clientes (`app.py:764`):

```python
rows = db.execute(
    "SELECT * FROM clientes WHERE (? = -1 OR ativo = ?) ORDER BY id_cliente DESC", (ativo, ativo)
).fetchall()
```

Nos filtros de processos, os nomes de colunas vêm de listas fixas no código e os valores digitados vão sempre como parâmetros.

**Como conferir — no código:** `make sast` roda a regra `sql-montado-com-texto`, que bloqueia qualquer `execute` montado com f-string, `%`, `.format` ou `+`. O resultado atual é `Findings: 0`.

**Como conferir — atacando:**

```sh
J=$(mktemp); T=$(curl -s --cacert $C -c $J -b $J $B/login | grep -oP 'name="_csrf" value="\K[^"]+')
curl -s --cacert $C -c $J -b $J -w "\nstatus %{http_code}\n" -H "Origin: $B" --data-urlencode "_csrf=$T" \
  --data-urlencode "email=' OR '1'='1' --" --data-urlencode "senha=x' OR '1'='1" $B/login | grep -oP 'role="alert"><p>\K[^<]+|^status.*'
```

Resultado obtido:

```text
E-mail inválido.
status 400
```

A entrada é barrada já na validação; com um e-mail válido e a injeção na senha, a resposta é `401 E-mail ou senha inválidos.` Na tela, buscar `' OR 1=1 --` em **Clientes** ou **Processos** só não encontra nada, sem erro e sem listar registros indevidos.

---

## 12. XSS

**Onde:** escape automático do Jinja (padrão do Flask para `.html`), CSP do item 3 e regras de SAST `template-sem-escape`, `html-sem-escape-no-python` e `template-quebra-a-csp`.

**Como conferir:** cadastre um cliente com o nome `<script>alert("xss")</script>`. Nenhum alerta aparece, o nome é mostrado como texto, e o código-fonte da página (Ctrl+U) mostra:

```html
&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;
```

O caso do DAST *xss armazenado* faz exatamente isso, automaticamente.

---

## 13. Autorização e perfis

**Onde:** `app.py:273` (`login_required`) e `app.py:285` (`admin_required`), aplicados como decoradores em cada rota; dados financeiros só para administradores em `app.py:682` e `app.py:1181`.

```python
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if g.user["perfil"] != "ADMINISTRADOR":
            flash("Acesso exclusivo de administradores.", "error")
            return redirect(url_for("dashboard_page"))
        return f(*args, **kwargs)
    return decorated
```

**Como conferir**

```sh
curl -s --cacert $C -o /dev/null -w "%{http_code} -> %{redirect_url}\n" $B/clients     # sem login
```

Resultado obtido: `302 -> https://localhost:5000/login`.

Com um usuário **Operador** (crie em **Usuários**): o menu não mostra *Usuários* nem *Auditoria*; abrir `https://localhost:5000/users` volta para o painel com "Acesso exclusivo de administradores."; um processo não mostra a seção **Financeiro**; e não há botões de exclusão. O caso do DAST *operador sem privilégios* tenta até excluir um cliente enviando o formulário direto e confere que o cliente continua lá.

---

## 14. Uploads

**Onde:** `app.py:1723` (`_detect_mime`), `app.py:975` (`document_upload`), `app.py:1363` (`process_file_upload`), `app.py:107` (`MAX_CONTENT_LENGTH`), `app.py:1757` (`too_large`), `app.py:1389-1393` (limite de pixels e regravação da foto).

```python
def _detect_mime(content, filename):
    if content[:4] == b"%PDF":
        return "application/pdf"
    if content[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    ...
    # Nunca confiar na extensão do nome: um executável renomeado para .pdf é recusado.
    return "application/octet-stream"
```

**Como conferir — arquivo disfarçado:** renomeie qualquer arquivo que não seja PDF (um `.txt` ou um executável) para `contrato.pdf` e envie em **Documentos** de um cliente: aparece "Envie um PDF, JPEG ou PNG." e nada é gravado.

**Como conferir — tamanho:** gere um arquivo de 11 MB e envie:

```sh
( printf '%%PDF-1.4\n'; head -c 11000000 /dev/zero ) > /tmp/grande.pdf
```

Aparece "O arquivo passa do limite de 10 MB."

**Como conferir — metadados da foto:** envie em um processo uma foto de celular (com GPS), baixe-a e compare:

```sh
python3 -c "from PIL import Image; print(dict(Image.open('foto-original.jpg').getexif()) or 'sem EXIF')"
python3 -c "from PIL import Image; print(dict(Image.open('processo-1-1.jpg').getexif()) or 'sem EXIF')"
```

A original lista os metadados; a baixada do sistema mostra `sem EXIF`.

**Downloads** (`app.py:1023`) saem com `as_attachment=True` e nome gerado pelo sistema: o navegador baixa em vez de abrir dentro do site.

---

## 15. Redirecionamento aberto

**Onde:** `app.py:1716` (`toggle_preference`).

```python
if not re.fullmatch(r"/(?![/\\])[^\\\s]*", nxt):
    nxt = url_for("dashboard_page")
```

**Como conferir:** o caso do DAST *redirecionamento aberto* envia `next=//evil.example`, `next=https://evil.example/` e `next=/\evil.example` e confere que o destino continua no próprio sistema. Esse caso encontrou e fez corrigir a variante com barra invertida.

---

## 16. SSRF no envio de e-mail

**Onde:** `mailer.py:42-90` (`is_public_ip`, `resolve_public_host`, `_PinnedSMTP`, `_PinnedSMTPSSL`).

```python
def is_public_ip(address):
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast
```

**Como conferir**

```sh
python3 -c "
import mailer
for h in ('localhost', '127.0.0.1', '10.0.0.5', '169.254.169.254'):
    try: mailer.resolve_public_host(h); print(h, '-> aceito')
    except ValueError as e: print(h, '->', e)"
```

Resultado obtido:

```text
localhost -> Destino de rede inválido.
127.0.0.1 -> Destino de rede privado ou reservado recusado.
10.0.0.5 -> Destino de rede privado ou reservado recusado.
169.254.169.254 -> Destino de rede privado ou reservado recusado.
```

`169.254.169.254` é o endereço de metadados de nuvem, alvo clássico de SSRF. A conexão SMTP é fixada no IP validado e o certificado é conferido com o nome original (`server_hostname=self._host`, `mailer.py:90`).

---

## 17. Validação de entrada

**Onde:** `validators.py` — `validate_client` (165), `validate_process` (223), `valid_cpf_cnpj` (97), `valid_cnj` (115), `validate_contact` (186), `_text`/`_multiline` com bloqueio de caracteres de controle (36-62).

**Como conferir:** desligue o JavaScript do navegador (para provar que a validação é do servidor) e tente salvar um cliente com CPF `111.111.111-11` → "CPF/CNPJ inválido para o tipo de pessoa."; um processo com número CNJ de dígito errado → "Número CNJ inválido."; um contato do tipo e-mail com `abc` → "E-mail de contato inválido."

---

## 18. Auditoria

**Onde:** `app.py:157` (`audit`), chamada em login, logout, leituras, inclusões, alterações, exclusões e downloads.

**Como conferir:** entre como administrador → **Auditoria**. Cada ação feita nos testes acima aparece com data, usuário, ação (`LOGIN`, `LEITURA`, `CADASTRO`, `EXCLUSAO`…) e o registro afetado, sem nenhum dado pessoal copiado.

---

## 19. Arquivos sensíveis e configuração de produção

**Onde:** permissões em `manage.py:53-67`, `125-152`, `165-173`, `187-195`; recusas de produção em `app.py:89-99` e `main`.

**Como conferir — permissões**

```sh
ls -la data data/tls
```

Resultado obtido:

```text
drwx------  data/
-rw-------  advocacia.sqlite
-rw-------  encryption.key
-rw-------  localhost-cert.pem
-rw-------  localhost-key.pem
```

**Como conferir — produção insegura é recusada**

```sh
TLS_MODE=off APP_ENV=production python app.py
APP_ENV=production MFA_MODE=console APP_ORIGIN=https://localhost:5000 python app.py
```

Resultado obtido:

```text
Em produção, APP_ORIGIN deve usar HTTPS.
Em produção, MFA_MODE deve ser smtp.
```

**Segredos fora do Git:** `git check-ignore -v data/encryption.key data/smtp.env credenciais.txt` mostra a regra do `.gitignore` que exclui cada um.

---

## 20. SAST (Semgrep)

**Onde:** regras em `.semgrep/python-rules.yml` (14 regras), alvo `sast` no `Makefile`, job **SAST** no pipeline.

**Como conferir**

```sh
pipx install semgrep==1.182.1
make sast
```

Resultado atual: `Findings: 0 (0 blocking)` em 14 regras.

**Prova de que as regras detectam:** crie um arquivo ruim fora do projeto e rode as regras nele:

```sh
mkdir -p /tmp/sast-teste && cat > /tmp/sast-teste/ruim.py <<'EOF'
db.execute(f"SELECT * FROM usuarios WHERE email = '{email}'")
app.secret_key = "segredo123"
app.run(debug=True)
hashlib.md5(b"x")
os.system("ls " + nome)
EOF
semgrep scan --config .semgrep --metrics=off /tmp/sast-teste
```

Cada linha é apontada pela regra correspondente (`sql-montado-com-texto`, `chave-secreta-no-codigo`, `flask-modo-debug`, `hash-fraco`, `comando-de-shell`). Num teste com 20 falhas plantadas, as 14 regras encontraram todas.

---

## 21. DAST (casos hostis)

**Onde:** `tests/dast/hostile_cases.py`, alvo `dast` no `Makefile`, job **DAST** no pipeline.

O script cria uma base temporária, sobe o sistema com HTTPS e MFA e o ataca **pela rede**, sem importar o código, como um atacante faria.

**Como conferir**

```sh
make dast
```

Resultado obtido:

```text
PASS  cabecalhos de seguranca
PASS  http sem tls recusado
PASS  host falso
PASS  metodos nao permitidos
PASS  paginas protegidas sem login
PASS  senha errada
PASS  injecao sql no login
PASS  login sem token csrf
PASS  senha sozinha nao basta
PASS  codigo mfa errado 5 vezes
PASS  formulario de outro site
PASS  xss armazenado
PASS  injecao sql na busca
PASS  path traversal
PASS  upload executavel disfarcado
PASS  upload gigante
PASS  redirecionamento aberto
PASS  erros sem detalhes internos
PASS  operador sem privilegios
PASS  logout encerra sessao
PASS  forca bruta bloqueada
PASS  servidor continua no ar

22 de 22 casos hostis passaram.
```

Se algum caso falhar, o script mostra qual ataque deu certo, o comportamento esperado e o log do servidor.

---

## 22. Testes automatizados

**Onde:** `tests/test_app.py` (11 testes), alvo `test` no `Makefile`.

```sh
make test
```

Resultado obtido: `Ran 11 tests ... OK`. Cobrem senha errada, MFA obrigatório, limite de tentativas do MFA, código não reutilizável, CSRF, origem externa, cabeçalhos, método não permitido, aviso de formulário expirado, upload grande e o fluxo completo (cliente, processo, upload disfarçado recusado, recebimento e permissões do operador).

---

## 23. Pipeline no GitHub Actions

**Onde:** `.github/workflows/projeto-extensao.yml` (na raiz do repositório).

**Como conferir:** no GitHub, abra a aba **Actions** do repositório → **CI - Projeto Extensão**. Cada execução mostra os jobs **Build**, **SAST**, **Tests** e **DAST**; clique em um job para ver a saída completa (os mesmos resultados dos itens 20 a 22). O workflow roda a cada push e pull request na `main` que altere o projeto, todo dia às 06:00 de Brasília e pelo botão **Run workflow**.
