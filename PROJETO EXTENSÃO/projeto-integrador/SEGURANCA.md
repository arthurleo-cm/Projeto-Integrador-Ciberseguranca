# Segurança e tecnologias — Marquezi Gestão

Visão geral da stack e de todos os controles de segurança do sistema. Onde cada controle está no código e como conferir cada um na prática: [SEGURANCA-EVIDENCIAS.md](SEGURANCA-EVIDENCIAS.md).

---

## 1. Stack

| Camada | Tecnologia | Versão testada | Para quê |
| --- | --- | --- | --- |
| Linguagem | Python | 3.12 (CI) e 3.14 | Todo o servidor |
| Framework web | Flask | 3.1.3 | Rotas, sessão, respostas |
| Templates | Jinja2 (vem com o Flask) | 3.1.6 | HTML montado no servidor, com escape automático |
| Servidor HTTP | Werkzeug (vem com o Flask) | 3.1.9 | Atende as requisições, com HTTPS direto |
| Banco de dados | SQLite (módulo `sqlite3` do Python) | — | Um arquivo, sem servidor separado |
| Criptografia | cryptography | 50.0.2 | AES-256-GCM e geração do certificado TLS |
| Imagens | Pillow | 13.0.0 | Regrava fotos sem metadados e gera miniaturas |
| E-mail do MFA | `smtplib` + `ssl` do Python | — | Envio do código de acesso |
| Hashes e tokens | `hashlib`, `hmac`, `secrets` do Python | — | scrypt, HMAC-SHA256, tokens aleatórios |
| TLS | OpenSSL (usado pelo Python) | 3.6 | Protocolo HTTPS |
| Telas | HTML + CSS puro | — | Interface |
| JavaScript | `static/app.js` (66 linhas) | — | **Opcional**: só formata campos ao digitar |
| SAST | Semgrep | 1.182.1 | Análise estática com 14 regras próprias |
| DAST | Script próprio em Python (`tests/dast/hostile_cases.py`) | — | 22 ataques contra o sistema rodando |
| Testes | `unittest` do Python | — | 11 testes automatizados |
| CI | GitHub Actions | — | Build, SAST, testes e DAST a cada push e todo dia |
| Produção (opcional) | Caddy | — | Proxy reverso com certificado público (Let's Encrypt) |

Dependências instaladas pelo `pip`: apenas **flask**, **cryptography** e **pillow** (`requirements.txt`).

---

## 2. HTTPS e TLS

| Controle | Como está |
| --- | --- |
| HTTPS por padrão | `python manage.py setup` gera um certificado autoassinado e o sistema sobe em `https://localhost:5000` |
| Certificado | RSA **3072 bits**, assinatura **SHA-256**, válido por 1 ano, `CN=localhost`, SAN `localhost`, `127.0.0.1` e `::1`, `CA:FALSE`, uso só para servidor |
| Versão mínima | **TLS 1.2** (TLS 1.0 e 1.1 recusados) |
| Cifra negociada em TLS 1.3 | `TLS_AES_256_GCM_SHA384` |
| Cifra negociada em TLS 1.2 | `ECDHE-RSA-AES256-GCM-SHA384` (troca de chaves com sigilo futuro, cifra autenticada) |
| Chave privada | Arquivo com permissão `600`; o sistema se recusa a iniciar se outros usuários puderem lê-la |
| HTTP sem TLS | A porta só fala TLS: conexão HTTP pura não recebe páginas |
| HSTS | Navegador passa a usar só HTTPS por 2 anos (`Strict-Transport-Security`) |
| Validação do Host | Requisição com `Host` diferente do domínio configurado recebe **421** |
| Redirecionamento | Atrás de proxy, GET em HTTP é redirecionado para HTTPS (308); POST em HTTP é recusado |
| E-mail (SMTP) | TLS 1.2+ com verificação de certificado e do nome do servidor |
| Produção | Com `APP_ENV=production`, o sistema não inicia sem HTTPS; o Caddy emite certificado público |

---

## 3. Cabeçalhos de segurança (um a um)

Enviados em **todas** as respostas (`security_headers` em `app.py`):

| Cabeçalho | Valor | O que impede |
| --- | --- | --- |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; upgrade-insecure-requests` | XSS: só carrega script, estilo e imagem do próprio sistema; bloqueia scripts e eventos inline (`onclick`), `style=""`, plugins, `<base>` falso, envio de formulário para outro site e exibição dentro de iframe |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Rebaixamento para HTTP e roubo de cookie em rede insegura |
| `X-Frame-Options` | `DENY` | Clickjacking (página escondida dentro de outro site) — proteção para navegadores antigos |
| `X-Content-Type-Options` | `nosniff` | Navegador "adivinhar" o tipo de um arquivo e executá-lo como script |
| `Referrer-Policy` | `same-origin` | Vazamento de endereços internos para outros sites |
| `Cross-Origin-Opener-Policy` | `same-origin` | Outra aba de outro site controlar a janela do sistema |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Carregar recursos de terceiros sem autorização explícita |
| `Cross-Origin-Resource-Policy` | `same-origin` | Outros sites embutirem as páginas e arquivos do sistema |
| `Permissions-Policy` | `accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()` | Uso de câmera, microfone, localização, pagamentos e outros recursos do navegador |
| `X-Robots-Tag` | `noindex, nofollow, noarchive, nosnippet` | Indexação do sistema interno por buscadores |
| `Cache-Control` | `no-store` (páginas) | Dados de clientes ficarem gravados no cache do navegador ou de proxies |
| `Server` | `Marquezi` | Anunciar as versões do Werkzeug e do Python (facilitaria procurar falhas conhecidas) |
| `Set-Cookie` | `__Host-sessao=…; Secure; HttpOnly; Path=/; SameSite=Strict` | Roubo do cookie por JavaScript (`HttpOnly`), envio sem HTTPS (`Secure`), envio a partir de outro site (`SameSite=Strict`) e sobrescrita por subdomínio (prefixo `__Host-`) |

---

## 4. Criptografia em repouso

| Controle | Detalhe |
| --- | --- |
| Algoritmo | **AES-256-GCM** (cifra autenticada: qualquer alteração no dado cifrado é detectada) |
| Chave | 256 bits aleatórios (`secrets.token_bytes(32)`) em `data/encryption.key`, permissão `600` |
| Nonce (IV) | 96 bits aleatórios **por registro** (`os.urandom(12)`) |
| Tag de autenticação | 128 bits |
| Dado associado (AAD) | Tipo do dado (`usuario`, `cliente`, `processo-arquivo:7` …): um bloco cifrado não pode ser copiado para outro tipo ou outro processo |
| O que é cifrado | Nome, e-mail, CPF/CNPJ, contatos, endereços, dados dos processos, histórico, recebimentos, documentos, fotos e miniaturas |
| O que não é cifrado | IDs, datas, perfil, situação e valores em centavos (necessários para filtros e totais) |
| Busca sem texto claro | **Índices HMAC-SHA256** de e-mail, CPF/CNPJ, número CNJ e contatos: permitem achar e impedir duplicados sem guardar o valor |

---

## 5. Hashes e códigos

| Uso | Algoritmo |
| --- | --- |
| Senhas | **scrypt** (N=32768, r=8, p=3, 64 bytes), salt aleatório de 128 bits por usuário, comparação em tempo constante (`hmac.compare_digest`) |
| Código MFA e token do desafio | HMAC-SHA256 (o código de 6 dígitos nunca fica gravado) |
| Índices de busca, tentativas de login, IP no desafio | HMAC-SHA256 com prefixo por finalidade (`lookup:`, `ip:`, `mfa-code:` …) |
| Chave do cookie de sessão | HMAC-SHA256 da chave de cifragem (nenhum segredo extra no código) |
| Assinatura do cookie | HMAC-SHA1 do Flask/itsdangerous — HMAC continua seguro com SHA-1, e o cookie só leva IDs; a sessão é validada no banco |
| Certificado TLS | RSA-3072 com SHA-256 |
| Tokens | `secrets` (gerador criptográfico): sessão 192 bits, CSRF 256 bits, desafio MFA 256 bits |

---

## 6. Autenticação e sessão

| Controle | Detalhe |
| --- | --- |
| Política de senha | 12 a 128 caracteres, sem caracteres de controle, sem repetição de um só caractere, fora da lista de senhas fracas |
| MFA obrigatório | Depois da senha, código de 6 dígitos enviado ao e-mail; expira em 10 min, 5 tentativas, reenvio após 60 s, no máximo 5 envios em 15 min, ligado ao IP e à versão da senha, uso único |
| Enumeração de usuários | Mesma mensagem para e-mail inexistente e senha errada, e um hash falso é calculado para o tempo de resposta não denunciar |
| Força bruta | 10 tentativas por conta **e** por IP → bloqueio de 15 min (gravado no banco, sobrevive a reinícios) |
| Limite geral | 600 requisições a cada 5 min por IP |
| Sessão | Guardada no servidor (tabela `sessoes`), expira em 8 h (configurável de 1 a 24), no máximo 5 sessões por usuário |
| Logout e troca de senha | Apagam a sessão no servidor; troca de senha ou alteração da conta encerram **todas** as sessões e desafios MFA do usuário |

---

## 7. Autorização

| Controle | Detalhe |
| --- | --- |
| Login obrigatório | Toda página interna, download e ação passa por `login_required` |
| Perfis | `ADMINISTRADOR` e `OPERADOR`; usuários, auditoria e exclusões só para administradores (`admin_required`) |
| Dados financeiros | Valores, recebimentos e situação de pagamento nem são enviados ao operador |
| Exclusões | Página de confirmação "Tem certeza?" e bloqueio se houver registros dependentes |
| Administrador | O sistema impede remover o último administrador ativo |
| Edição simultânea | Controle de versão em clientes e processos: uma edição não sobrescreve outra |

---

## 8. Proteção contra injeção e ataques web

| Ataque | Defesa |
| --- | --- |
| **Injeção de SQL** | 100% das consultas usam parâmetros (`?`); nenhum valor do usuário entra no texto do SQL. O SAST bloqueia SQL montado com f-string, `%`, `.format` ou `+` |
| **XSS** | Escape automático do Jinja em tudo que vem do banco, CSP sem scripts inline e regra de SAST contra `| safe`, `Markup` e `render_template_string` |
| **CSRF** | Token secreto por sessão em todo formulário POST, cookie `SameSite=Strict` e checagem dos cabeçalhos `Origin` e `Sec-Fetch-Site` |
| **Clickjacking** | `frame-ancestors 'none'` e `X-Frame-Options: DENY` |
| **Redirecionamento aberto** | O parâmetro `next` só aceita caminhos internos (`/…`, sem `//` nem `\`) |
| **SSRF** | O servidor nunca acessa URLs do usuário; o SMTP só conecta em IPs públicos e recusa respostas DNS mistas, fixando o IP validado |
| **Injeção de comandos** | Nenhum comando de shell no código (regra de SAST) |
| **Path traversal** | Arquivos ficam dentro do banco, sem pasta pública; downloads por ID numérico |
| **Métodos HTTP** | Só GET, HEAD e POST; o resto recebe 405 |
| **Vazamento de erros** | Modo debug sempre desligado; erros não mostram rastros do Python |

---

## 9. Uploads

| Controle | Detalhe |
| --- | --- |
| Tipos | PDF, JPEG, PNG e WebP, conferidos pela **assinatura do conteúdo**, nunca pela extensão |
| Tamanho | 10 MB por arquivo; requisições acima de 10,5 MB são recusadas **antes** de serem lidas |
| Fotos | Recusadas acima de 40 megapixels (bomba de descompressão), orientadas e regravadas em JPEG, o que remove metadados como GPS |
| Armazenamento | Cifrado com AES-256-GCM dentro do banco |
| Download | Sempre como anexo, com nome gerado pelo sistema, e registrado na auditoria |

---

## 10. Validação de entrada

Todo dado é validado **no servidor** (`validators.py`), mesmo com o JavaScript desligado: tamanhos máximos, caracteres de controle, datas (sem datas futuras onde não faz sentido), CPF/CNPJ e **número CNJ com dígito verificador (Módulo 97)**, e-mails, telefones, CEP, UF, valores monetários em centavos, listas fechadas para status, ramos e perfis.

---

## 11. Auditoria, segredos e configuração

| Controle | Detalhe |
| --- | --- |
| Auditoria | Registra login, logout, consultas, inclusões, alterações, exclusões e downloads, com usuário e horário, sem copiar dados pessoais |
| Permissões de arquivo | `data/` com `700`; chave, banco, certificado e `smtp.env` com `600` |
| Segredos fora do Git | `.gitignore` exclui `data/`, `*.env`, bancos e `credenciais.txt`; senha de app do e-mail digitada de forma oculta |
| Produção | Com `APP_ENV=production` o sistema se recusa a iniciar sem HTTPS, sem MFA por SMTP ou com o SMTP fora do ar |
| Proxy | `TRUST_PROXY` para obter o IP real atrás do Caddy; não pode ser combinado com TLS direto |

---

## 12. SAST, DAST e pipeline

| Verificação | Ferramenta | O que faz | Comando |
| --- | --- | --- | --- |
| **SAST** | Semgrep 1.182.1 + 14 regras em `.semgrep/python-rules.yml` | Lê o código sem executar e bloqueia: SQL montado com texto, debug ligado, chave secreta no código, MD5/SHA-1, `random` em segredos, shell, `eval`/`exec`, pickle/yaml inseguros, TLS sem verificação, redirecionamento aberto, HTML sem escape (Python e templates), quebra da CSP nos templates e formulário sem token CSRF | `make sast` |
| **Testes** | `unittest` (11 testes) | MFA, CSRF, cabeçalhos, permissões, uploads, fluxo completo | `make test` |
| **DAST** | `tests/dast/hostile_cases.py` (22 casos) | Sobe o sistema com HTTPS e MFA e o ataca pela rede: cabeçalhos, HTTP sem TLS, Host falso, métodos, páginas sem login, senha errada, injeção de SQL no login e na busca, CSRF, MFA, XSS armazenado, path traversal, upload malicioso e gigante, redirecionamento aberto, vazamento de erros, privilégios, logout e força bruta | `make dast` |
| **Pipeline** | GitHub Actions (`.github/workflows/projeto-extensao.yml`) | Build → SAST, Tests e DAST em paralelo, a cada push/PR na `main`, **todo dia às 06:00** e sob demanda | automático |

Problemas reais que essas ferramentas já encontraram e que foram corrigidos: upload aceitando executável renomeado para `.pdf`, consulta de clientes montada com texto, parâmetro `next` aceitando `/\site-externo` e cabeçalho `Server` expondo versões.

---

## 13. Limitações conhecidas

- Não há verificação automática de **bibliotecas vulneráveis** (ex.: `pip-audit`) nem versões fixas no `requirements.txt`.
- O SAST e o DAST cobrem o que foi planejado; não substituem um scanner amplo (OWASP ZAP) nem um pentest.
- A chave de cifragem fica no mesmo servidor do banco; quem invadir o servidor acessa os dois.
- O bloqueio por IP pode travar todo o escritório se todos saírem pela mesma internet.
- O servidor embutido do Werkzeug é adequado para um escritório pequeno atrás do Caddy, não para alto volume.
- O MFA por e-mail é tão forte quanto a conta de e-mail do usuário.
- Sem antivírus nos uploads, sem tempo de inatividade na sessão e sem backup automático.
