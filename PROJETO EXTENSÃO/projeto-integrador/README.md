# Marquezi — Gestão da advocacia

Aplicação de uso interno para clientes, processos jurídicos não penais, recebimentos, contatos, endereços, documentos, usuários e auditoria. Interface responsiva em português e servidor Node.js. Não há contas padrão nem armazenamento de dados pessoais no localStorage. Um conjunto opcional de dados inteiramente fictícios pode ser instalado para treinamento.

## Iniciar

Requer Node.js 24 ou superior e npm. Na pasta do projeto:

```sh
npm ci
npm run setup
npm run setup:tls
npm start
```

O assistente solicita o nome, e-mail e senha do primeiro administrador no terminal. A senha exige pelo menos 12 caracteres e fica oculta em terminais interativos. Executar o assistente novamente preserva as contas existentes. `setup:tls` gera um certificado autoassinado de 3072 bits válido por um ano, com SAN para `localhost`, `127.0.0.1` e `::1`. Acesse **https://localhost:3000** e aceite ou instale o certificado local. O aviso inicial do navegador é esperado porque não existe autoridade pública para `localhost`.

O primeiro administrador pode cadastrar a equipe na página **Usuários**. Para cada funcionário, use uma conta individual e um e-mail controlado por ele; o mesmo endereço é usado no login e no recebimento do código MFA. O usuário pode trocar a própria senha em **Minha conta**; um administrador pode redefinir senha e e-mail pela edição de usuários. Alterações de conta e senha encerram sessões e desafios desse usuário. Não existe recuperação de senha por e-mail.

Os funcionários não configuram SMTP nem criam senhas de app. A credencial de 16 caracteres pertence somente à conta remetente configurada uma vez no servidor. Para cadastrar um colega, solicite nome, e-mail individual acessível e o perfil necessário; defina uma senha inicial e entregue-a por um canal separado. No primeiro acesso, o código MFA será enviado ao e-mail cadastrado.

O login exige senha e um código de seis dígitos. Em desenvolvimento, o padrão `MFA_MODE=console` mostra o código no terminal que executa `npm start`, permitindo testar sem uma conta de e-mail. Esse modo não é aceito com `NODE_ENV=production`. Para envio real, configure SMTP com TLS:

```sh
MFA_MODE=smtp \
SMTP_HOST=smtp.gmail.com \
SMTP_PORT=465 \
SMTP_USER=seu-email@gmail.com \
SMTP_PASS='SENHA_DE_APP' \
SMTP_FROM=seu-email@gmail.com \
npm start
```

No Gmail, use uma senha de app, nunca a senha normal da conta. Para configurá-la localmente sem exibir a credencial no terminal nem gravá-la no código, execute `npm run setup:smtp`; o assistente armazena a configuração em `data/smtp.env`, com permissão somente para o usuário do sistema. Depois, `npm start` carrega esse arquivo automaticamente. O servidor valida a conexão SMTP ao iniciar. Em produção, uma falha nessa validação impede a inicialização. No ambiente local, o servidor inicia com um aviso para permitir diagnóstico, mas novos logins retornam indisponibilidade enquanto o SMTP estiver inacessível; o sistema nunca transfere silenciosamente o código para o terminal. Para outro provedor, configure as variáveis manualmente; a porta 465 usa TLS desde o início e as demais exigem STARTTLS.

O processo deve permanecer em execução. Para disponibilização contínua, configure o gerenciador de serviços do sistema com a pasta de trabalho deste projeto, usuário sem privilégios administrativos e um único processo da aplicação.

## Dados de demonstração

Depois do setup, é possível criar três operadores, cinco clientes e três processos fictícios:

```sh
npm run seed:demo -- --confirm-demo-data
```

O comando é idempotente, concede somente o perfil `OPERADOR` e gera senhas fortes diferentes, mostradas uma única vez no terminal. Os domínios `.example` indicam que os e-mails não pertencem a pessoas ou empresas reais. Não use a base de demonstração para dados pessoais verdadeiros; antes da operação real, desative ou altere as contas de exemplo e remova os clientes fictícios.

## Banco de dados e modelagem

O SQL recebido foi preservado em `database/modelagem-original.mysql.sql`. A implementação adapta as seis entidades e seus relacionamentos para **SQLite**, com esquema em `database/schema.sqlite.sql`. Não é necessário importar o SQL MySQL nem instalar um servidor de banco separado. SQLite é adequado a esta instalação em um único servidor; não coloque seu arquivo em uma pasta de rede compartilhada nem use múltiplas réplicas do servidor.

O diretório `data/`, criado pelo setup, contém:

- `advocacia.sqlite`: banco persistente; arquivos auxiliares `-wal` e `-shm` podem existir durante o uso.
- `encryption.key`: chave aleatória de 256 bits. Sua perda torna os dados cifrados irrecuperáveis. O setup se recusa a gerar outra chave sobre um banco existente.

Além das tabelas de usuários e clientes, o banco possui `processos`, `historico_processos`, `recebimentos` e `arquivos_processos`. Os campos pessoais e conteúdos descritivos são agrupados em colunas binárias cifradas. E-mail, CPF/CNPJ, número CNJ e valores de contato têm índices HMAC para unicidade sem manter o valor em texto claro. Arquivos e fotos ficam cifrados no banco, sem diretório público ou URL anônima.

As chaves estrangeiras impedem registros órfãos; índices únicos parciais garantem no máximo um contato principal por tipo e um endereço principal por cliente. IDs internos não são reutilizados. A numeração oficial usa o padrão `NNNNNNN-DD.AAAA.J.TR.OOOO` e o Módulo 97 Base 10 do CNJ. Clientes e processos usam controle de versão para impedir que uma edição simultânea sobrescreva outra. Migrações são aplicadas automaticamente e preservam a base existente.

## Operação e permissões

| Ação                                              | Operador | Administrador |
| ------------------------------------------------- | -------- | ------------- |
| Consultar, cadastrar, editar e desativar clientes | Sim      | Sim           |
| Manter contatos e endereços                       | Sim      | Sim           |
| Consultar, cadastrar e atualizar processos        | Sim      | Sim           |
| Enviar e baixar anexos e fotos de processos       | Sim      | Sim           |
| Consultar valores e registrar recebimentos        | Não      | Sim           |
| Excluir processos, anexos ou recebimentos         | Não      | Sim           |
| Enviar e baixar documentos                        | Sim      | Sim           |
| Excluir clientes ou documentos                    | Não      | Sim           |
| Gerenciar usuários e consultar auditoria          | Não      | Sim           |
| Alterar a própria senha                           | Sim      | Sim           |

Todos os funcionários ativos têm acesso à base de clientes e ao andamento dos processos. Valores estimados, previsão de recebimento, situação de pagamento, totais recebidos, saldos e lançamentos financeiros são omitidos das respostas destinadas a operadores. A situação financeira é calculada a partir do valor estimado e dos recebimentos. Para preservar o histórico, prefira encerrar ou arquivar um processo e desativar o cliente. Um cliente com processos não pode ser excluído. Contas são desativadas, sem exclusão física, e o sistema preserva pelo menos um administrador ativo.

Os anexos aceitos são PDF, JPEG, PNG e WebP de até 10 MB. O servidor verifica a assinatura do formato. Fotos são decodificadas, limitadas a 40 megapixels, orientadas, redimensionadas e recodificadas em JPEG para remover metadados; uma miniatura privada é gerada. Todo conteúdo é cifrado e exige sessão. A verificação de formato não substitui uma solução antivírus.

Contatos podem ser telefone, WhatsApp, e-mail, Instagram, LinkedIn, Facebook, site ou outro. URLs aceitam apenas HTTP/HTTPS sem credenciais. As preferências de tema claro/noturno/sistema, tamanho das letras e alto contraste são salvas no cadastro do usuário e aplicadas em toda a interface.

A auditoria registra alterações, inclusões, exclusões, login, logout, consulta individual de clientes e downloads, com responsável e horário UTC. Não copia os conteúdos pessoais. Administradores do próprio sistema operacional ainda podem alterar o banco: a trilha não tem armazenamento externo imutável.

## Proteções implementadas

- Senhas com scrypt assíncrono, salt individual e comparação em tempo constante.
- MFA obrigatório após a senha, com código aleatório de seis dígitos enviado ao e-mail individual. O código fica somente como HMAC, é ligado ao IP e à versão da senha, expira em 10 minutos, permite cinco tentativas, possui intervalo de reenvio e não pode ser reutilizado.
- JWTs de acesso HS256 com chave derivada por contexto, emissor, audiência, identificador único e validade curta de 15 minutos. Os tokens ficam somente em cookies HttpOnly, Secure em HTTPS e SameSite=Strict; não são armazenados no localStorage.
- Refresh tokens aleatórios, armazenados somente como HMAC, com rotação a cada uso e detecção de reutilização. Reuso revoga a família da sessão; logout, alteração de conta e troca de senha também revogam os tokens.
- CSRF com token sincronizado, secreto e vinculado à sessão, exigido em cabeçalho nas operações de escrita, além de validação exata de Origin, Sec-Fetch-Site e cookies SameSite=Strict.
- Limite persistente de tentativas de login por conta e IP; bloqueio por até 15 minutos após 10 tentativas.
- Autorização em cada rota do servidor, validação estrita com Zod, CPF/CNPJ e número CNJ com dígitos verificadores, datas, contatos, URLs, valores monetários em centavos, caracteres de controle, versões de edição e tipos de conteúdo HTTP.
- Consultas parametrizadas, transações, escape de conteúdo na interface e CSP sem scripts inline.
- AES-256-GCM com nonce aleatório e autenticação dos dados cifrados; metadados operacionais como IDs, datas, perfil e situação não são cifrados.
- Arquivos da aplicação publicados por lista explícita; banco, código do servidor, chave e dependências não são publicados. Permissões restritivas no diretório de dados.
- Código principal do navegador entregue somente após autenticação, sem cache; `/app.js` não é uma rota pública. O pequeno bootstrap de login, HTML e CSS continuam necessariamente públicos. Usuários autenticados podem inspecionar qualquer JavaScript executado pelo próprio navegador, portanto toda autorização permanece no servidor.
- CSP fechada por padrão, HSTS em HTTPS, COOP/COEP/CORP, política de referenciador, anti-iframe, MIME sniffing desabilitado, Permissions Policy, bloqueio de indexação e validação do Host.
- Limite geral por IP, limite específico e persistente no login, lista fechada de métodos HTTP e recusa de tráfego HTTP acidental quando a origem configurada usa HTTPS.
- Proteção SSRF por ausência de busca de URLs fornecidas pelos usuários e por validação de DNS no único tráfego externo do servidor: o SMTP recusa endereços locais, privados, reservados e respostas DNS mistas, fixa o IP público validado e mantém o nome original na validação TLS.
- Limites de corpo e upload, detecção do formato real de arquivos, nomes de download gerados pelo servidor, timeouts HTTP e encerramento gracioso.

Referências técnicas: [segurança no Express](https://expressjs.com/en/advanced/best-practice-security.html) e [criptografia no Node.js](https://nodejs.org/api/crypto.html).

## HTTP e configuração

Localmente, o processo Node pode servir HTTPS diretamente com o certificado de `npm run setup:tls`. Em produção, coloque-o atrás do Caddy, mantenha o Node ligado somente a `127.0.0.1` e use certificado público. Quando `NODE_ENV=production`, a aplicação se recusa a iniciar se `APP_ORIGIN` não usar HTTPS.

| Variável     | Padrão                  | Finalidade                               |
| ------------ | ----------------------- | ---------------------------------------- |
| `DATA_DIR`   | `./data`                | Diretório persistente com banco e chave  |
| `HOST`       | `127.0.0.1`             | Interface em que o servidor escuta       |
| `PORT`       | `3000`                  | Porta HTTP                               |
| `APP_ORIGIN` | `http://localhost:PORT` | Origem exata autorizada, sem barra final |
| `SESSION_HOURS` | `8`                  | Validade da sessão, entre 1 e 24 horas   |
| `ACCESS_TOKEN_MINUTES` | `15`          | Validade do JWT de acesso, entre 5 e 30 minutos |
| `TRUST_PROXY` | desabilitado           | Quantidade de proxies reversos confiáveis |
| `TLS_MODE`   | `auto`                   | `auto`, `on` para TLS direto ou `off` atrás do Caddy |
| `TLS_CERT_FILE` | `DATA_DIR/tls/localhost-cert.pem` | Certificado do TLS direto |
| `TLS_KEY_FILE` | `DATA_DIR/tls/localhost-key.pem` | Chave privada do TLS direto |
| `MFA_MODE` | `console` local / `smtp` em produção | Entrega do código: `smtp`, `console` ou `test` |
| `SMTP_HOST` | obrigatório em modo SMTP | Servidor SMTP |
| `SMTP_PORT` | `587` | Porta SMTP; use 465 para TLS imediato |
| `SMTP_USER` | obrigatório em modo SMTP | Usuário de autenticação SMTP |
| `SMTP_PASS` | obrigatório em modo SMTP | Senha de app ou credencial SMTP |
| `SMTP_FROM` | valor de `SMTP_USER` | Endereço remetente validado |
| `NODE_ENV`   | não definido            | Use `production` na instalação real      |

Para acesso em uma rede interna controlada, configure `HOST` com o IP dessa interface e `APP_ORIGIN` com o endereço exato utilizado pelo navegador. A exposição à rede deve ser uma decisão de instalação; ela não é habilitada automaticamente. Se houver exatamente um proxy reverso confiável entre o usuário e o Node, configure `TRUST_PROXY=1`; isso permite que o limite por IP use o endereço encaminhado pelo proxy. Não aceite cabeçalhos encaminhados diretamente da internet. `APP_ORIGIN=https://...` habilita cookies Secure e HSTS, mas a variável sozinha não instala TLS.

Uma configuração típica atrás do Caddy é:

```sh
NODE_ENV=production \
HOST=127.0.0.1 \
PORT=3000 \
APP_ORIGIN=https://gestao.exemplo.com.br \
TRUST_PROXY=1 \
TLS_MODE=off \
npm start
```

O arquivo `deploy/Caddyfile` limita requisições a 11 MB, preserva o host e termina TLS. Com um domínio real apontado para o servidor, o Caddy obtém e renova certificados da Let's Encrypt automaticamente. A configuração DNS sugerida para não substituir o site existente em `marquezi.com` está em `deploy/DNS.md`; ela usa `gestao.marquezi.com`. A porta 3000 não deve ser liberada no firewall. Restrinja o acesso por VPN ou rede corporativa sempre que possível. Execute uma única instância do Node para este banco SQLite.

Para configurar o registro da Name.com pela API depois de gerar um token de produção, use `npm run dns:configure`. O comando é idempotente e não sobrescreve registros conflitantes.

## Backup e restauração

Crie um backup consistente, inclusive com o servidor em execução:

```sh
npm run backup -- /caminho/seguro/backup-advocacia-2026-10-07
```

A pasta de destino deve ser nova e seu diretório pai deve existir. A operação usa a API de backup do SQLite e copia a chave. Guarde o backup em armazenamento cifrado com acesso restrito: quem obtiver o banco e a chave juntos poderá decifrar os dados. Não envie a chave ao Git ou a terceiros. Não existe agendamento automático; configure uma rotina de backups e teste a restauração regularmente.

Para restaurar:

1. Pare o servidor.
2. Preserve o diretório de dados atual inteiro em outro local.
3. Crie um diretório `data/` vazio com permissão 700 e copie para ele `advocacia.sqlite` e `encryption.key` do mesmo backup, ambos com permissão 600. Não reutilize arquivos `-wal`/`-shm` da instalação anterior.
4. Inicie `npm start`, confira cadastros e baixe um documento conhecido.

Não execute o setup para substituir uma chave perdida. Não há rotação automática de chaves nesta versão.

## Verificação

```sh
npm test
npx playwright install chromium
npm run test:browser
npm audit --omit=dev
```

Os testes usam diretórios temporários isolados e são removidos ao terminar. Cobrem validações, migração, processos, recebimentos, isolamento financeiro por perfil, fotos reprocessadas, preferências visuais, filtros, persistência, transações, conflitos de edição, CSRF, sessões, arquivos privados, cifragem, auditoria, cargas de SQLi/XSS/SSTI/path traversal e o fluxo responsivo no navegador.

O sistema controla processos, histórico, anexos e recebimentos internos. Prazos processuais, agenda, emissão fiscal, conciliação bancária, assinatura digital e integrações automáticas com tribunais continuam fora deste escopo.
