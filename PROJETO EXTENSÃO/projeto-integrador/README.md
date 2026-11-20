# Marquezi — Gestão da advocacia

Aplicação de uso interno para clientes, processos jurídicos não penais, recebimentos, contatos, endereços, documentos, usuários e auditoria. Interface responsiva em português, montada no servidor em Python. Não há contas padrão nem dados pessoais guardados no navegador.

## Tecnologias

| Parte | Tecnologia |
| --- | --- |
| Servidor | **Python 3.11+** com **Flask** (traz Jinja2 e Werkzeug) |
| Banco de dados | **SQLite** (módulo `sqlite3` do Python) |
| Criptografia | **cryptography** (AES-256-GCM e certificado TLS local) |
| Imagens | **Pillow** (reprocessa fotos e gera miniaturas) |
| Telas | HTML (templates Jinja) + CSS puro |
| E-mail do MFA | `smtplib` do Python |

O arquivo `static/app.js` (66 linhas) é **opcional**: só formata CPF/CNPJ, CNJ, OAB e CEP enquanto o usuário digita. O sistema funciona inteiro com o JavaScript desligado, e todas as regras são validadas no servidor.

## Iniciar

Na pasta do projeto:

```sh
python3 -m venv venv
source venv/bin/activate          # no Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py setup            # cria data/, a chave de cifragem, o banco e o primeiro administrador
python manage.py tls              # opcional: certificado HTTPS local
python app.py
```

Acesse **https://localhost:5000** (com `tls`) ou **http://localhost:5000** (sem). Com o certificado local, o navegador mostra um aviso na primeira vez, o que é esperado porque não existe autoridade pública para `localhost`.

O `setup` pede nome, e-mail e senha do primeiro administrador (mínimo de 12 caracteres, entrada oculta). Rodar de novo preserva as contas existentes e nunca gera uma chave nova sobre um banco já existente. O administrador cadastra a equipe em **Usuários**: uma conta individual por funcionário, com um e-mail que só ele acessa, porque é para lá que vai o código de acesso. Não existe recuperação de senha por e-mail; um administrador pode redefini-la.

## Verificação em duas etapas (MFA)

O login exige a senha **e** um código de 6 dígitos enviado ao e-mail do usuário.

- Em desenvolvimento, o padrão é `MFA_MODE=console`: o código aparece no terminal que roda `python app.py`. Esse modo é recusado com `APP_ENV=production`.
- Para envio real, configure uma vez a conta remetente:

```sh
python manage.py smtp             # pede a conta @gmail.com e a senha de app (entrada oculta)
```

O comando grava `data/smtp.env` com permissão só para o dono, e o `app.py` carrega esse arquivo sozinho. No Gmail, use uma **senha de app**, nunca a senha normal da conta. Para outro provedor, defina `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` e `SMTP_FROM` (a porta 465 usa TLS desde o início; as demais exigem STARTTLS). Ao iniciar, o servidor testa a conexão SMTP: em produção uma falha impede a inicialização; localmente ele avisa e segue, mas novos logins falham até o SMTP voltar, e o código nunca é desviado para o terminal.

## Comandos (`manage.py`)

| Comando | O que faz |
| --- | --- |
| `python manage.py setup` | Cria a estrutura e o primeiro administrador |
| `python manage.py tls [--renew]` | Certificado autoassinado RSA 3072, válido por 1 ano, para `localhost`, `127.0.0.1` e `::1` |
| `python manage.py smtp [--replace]` | Configura a conta que envia os códigos de acesso |
| `python manage.py backup /pasta/nova` | Copia o banco (backup consistente do SQLite) e a chave de cifragem |
| `python manage.py demo --confirm-demo-data` | Cria 3 operadores, 5 clientes e 3 processos fictícios |
| `python manage.py dns` | Cria o registro DNS na Name.com (veja `deploy/DNS.md`) |
| `python -m unittest discover tests` | Roda os testes automatizados |

O comando `demo` é idempotente, cria só usuários com perfil `OPERADOR` e gera senhas fortes diferentes, mostradas uma única vez. Os e-mails `.example` não recebem mensagens; para entrar com eles use `MFA_MODE=console`. Não use a base de demonstração para dados reais.

## Banco de dados e modelagem

O SQL original está em `docs/modelagem-original.mysql.sql`. A implementação adapta as entidades para **SQLite**, com esquema em `database/schema.sqlite.sql`; não há servidor de banco separado. Não coloque o arquivo do banco em pasta de rede compartilhada.

A pasta `data/` (fora do Git) contém:

- `advocacia.sqlite`: o banco.
- `encryption.key`: chave aleatória de 256 bits. **Sua perda torna os dados cifrados irrecuperáveis.** Faça backups com `manage.py backup`.
- `smtp.env` e `tls/`: quando configurados.

Campos pessoais e descritivos ficam em colunas binárias cifradas. E-mail, CPF/CNPJ, número CNJ e contatos têm índices HMAC, que permitem buscar e impedir duplicidade sem guardar o valor em texto claro. Arquivos e fotos ficam cifrados dentro do banco, sem pasta pública. O número CNJ segue o padrão `NNNNNNN-DD.AAAA.J.TR.OOOO`, com dígito verificador Módulo 97. Clientes e processos têm controle de versão, para que uma edição simultânea não sobrescreva outra.

## Operação e permissões

| Ação | Operador | Administrador |
| --- | --- | --- |
| Consultar, cadastrar, editar e desativar clientes | Sim | Sim |
| Manter contatos e endereços | Sim | Sim |
| Consultar, cadastrar e atualizar processos | Sim | Sim |
| Enviar e baixar anexos, fotos e documentos | Sim | Sim |
| Consultar valores e registrar recebimentos | Não | Sim |
| Excluir processos, anexos, recebimentos, clientes ou documentos | Não | Sim |
| Gerenciar usuários e consultar auditoria | Não | Sim |
| Alterar a própria senha e aparência | Sim | Sim |

Valores estimados, previsão de recebimento, situação de pagamento e recebimentos não são enviados a operadores. Toda exclusão passa por uma página de confirmação. Um cliente com processos ou documentos não pode ser excluído; prefira desativá-lo. O sistema mantém sempre pelo menos um administrador ativo.

Anexos aceitos: PDF, JPEG, PNG e WebP até 10 MB. O tipo é conferido pelo **conteúdo** (assinatura do arquivo), nunca pela extensão. Fotos acima de 40 megapixels são recusadas; as demais são orientadas, redimensionadas e regravadas em JPEG, o que remove metadados como GPS. Downloads saem sempre como anexo. Essa verificação não substitui um antivírus.

As preferências de tema (claro, noturno ou automático), tamanho das letras e alto contraste ficam salvas no cadastro do usuário.

A auditoria registra inclusões, alterações, exclusões, login, logout, consultas individuais e downloads, com responsável e horário UTC, sem copiar conteúdo pessoal. Quem administra o sistema operacional ainda pode alterar o banco: a trilha não tem armazenamento externo imutável.

## Proteções implementadas

- **Senhas:** scrypt (N=32768, r=8, p=3) com salt individual e comparação em tempo constante. Quando o e-mail não existe, um hash falso é calculado mesmo assim, para o tempo de resposta não revelar quais contas existem.
- **MFA:** código aleatório de 6 dígitos guardado só como HMAC, ligado ao IP e à versão da senha, válido por 10 minutos, com 5 tentativas, reenvio a cada 60 segundos, no máximo 5 envios a cada 15 minutos, e sem reutilização.
- **Sessão:** guardada no servidor (tabela `sessoes`) e identificada por um cookie `HttpOnly` e `SameSite=Strict`; em HTTPS ele se chama `__Host-sessao` e é `Secure`. Expira em `SESSION_HOURS`, com no máximo 5 sessões por usuário. Alterações de conta ou senha encerram todas as sessões e desafios MFA do usuário.
- **CSRF:** token secreto por sessão em todo formulário, mais conferência dos cabeçalhos `Origin` e `Sec-Fetch-Site`.
- **Força bruta:** bloqueio de 15 minutos após 10 tentativas por conta e por IP (persistente no banco), e limite geral de 600 requisições a cada 5 minutos por IP.
- **Validação no servidor:** CPF/CNPJ e CNJ com dígitos verificadores, datas, contatos, valores em centavos, caracteres de controle e versões de edição.
- **Injeção e XSS:** consultas SQL parametrizadas, escape automático do Jinja e CSP sem scripts, estilos ou eventos inline.
- **Criptografia em repouso:** AES-256-GCM com nonce aleatório e contexto autenticado por tipo de dado.
- **Cabeçalhos:** CSP fechada por padrão, HSTS (em HTTPS), COOP, COEP e CORP, `Referrer-Policy: same-origin` (nada é enviado a outros sites), anti-iframe, `nosniff`, Permissions-Policy, bloqueio de indexação e `Cache-Control: no-store` nas páginas.
- **Rede:** validação do `Host` (421 se não bater), redirecionamento para HTTPS, aceitação só dos métodos GET, HEAD e POST, e limite de 10,5 MB por requisição aplicado antes de ler o envio.
- **SSRF:** o servidor nunca busca URLs informadas por usuários. O único tráfego externo, o SMTP, só conecta em IPs públicos: endereços locais, privados ou reservados e respostas DNS mistas são recusados, e a conexão é fixada no IP validado, mantendo o nome original para conferir o certificado TLS.
- **Arquivos do sistema:** `data/` com permissão 700, chave e banco com 600. A chave privada TLS é recusada se outros usuários puderem lê-la.

## Produção

Em produção, rode o Python atrás do **Caddy**, que cuida do certificado público (Let's Encrypt) e do HTTP/2/3:

1. Copie `deploy/production.env.example` para `/etc/marquezi/marquezi.env` (permissão 600) e ajuste o domínio e o SMTP.
2. Inicie a aplicação com essas variáveis (`python app.py`), ligada só a `127.0.0.1:5000`, com um usuário sem privilégios de administrador.
3. Inicie o Caddy: `APP_DOMAIN=gestao.marquezi.com caddy run --config deploy/Caddyfile`.

Com `APP_ENV=production`, a aplicação se recusa a iniciar se `APP_ORIGIN` não usar HTTPS, se o MFA não for por SMTP ou se o SMTP não responder. Configuração de DNS em `deploy/DNS.md`.

| Variável | Padrão | Uso |
| --- | --- | --- |
| `APP_ENV` | vazio | `production` ativa as exigências acima |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Endereço em que o Python escuta |
| `APP_ORIGIN` | `http(s)://localhost:PORT` | Origem pública exata, sem barra final |
| `TLS_MODE` | `auto` | `auto`, `on` (TLS no Python) ou `off` (atrás do Caddy) |
| `TRUST_PROXY` | `0` | Número de proxies confiáveis (use `1` atrás do Caddy) |
| `SESSION_HOURS` | `8` | Duração da sessão (1 a 24) |
| `MFA_MODE` | `console` local / `smtp` em produção | `smtp`, `console` ou `test` |
| `SMTP_*` | | Configuração do envio de e-mail |
| `DATA_DIR` | `data` | Pasta do banco e da chave |

Limitação conhecida: o servidor embutido do Flask (Werkzeug) atende bem um escritório pequeno atrás do Caddy, mas não foi feito para alto volume. Se precisar, troque por um servidor WSGI como o `waitress` sem mudar o código.
