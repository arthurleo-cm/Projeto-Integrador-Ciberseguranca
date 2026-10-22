# 🔐 Projeto Integrador em Cibersegurança – Programação Segura

Projeto Integrador do curso de Cibersegurança da **Escola Politécnica da PUC-Campinas** (Cyberbank), composto por duas atividades: um **sistema de cadastro de clientes** para um escritório de advocacia (extensão) e um **programa em C que combina criptografia e esteganografia** (autônoma).

## 👥 Integrantes

- Alexandre Monda
- Arthur Henrique
- Gabriel Lira
- Maria Eduarda Marquezi
- Murilo Augusto

**Instituição parceira (extensão):** Advocacia Pedro Marquezi

## 📂 Estrutura do repositório

```
├── PROJETO EXTENSÃO/    # Sistema de cadastro de clientes
├── PROJETO AUTÔNOMO/    # Cifragem ChaCha20 + esteganografia em PNG
├── LICENSE
└── README.md
```

---

## 🏛️ Projeto Extensão – Sistema de Cadastro de Clientes

O escritório parceiro armazena hoje seus documentos em papel. A proposta é um sistema para **cadastrar, organizar e consultar clientes**, com foco em sigilo e controle de acesso. O público beneficiário é a equipe do escritório.

### Funcionalidades (requisitos)

| Código | Requisito |
| --- | --- |
| RE1 | Cadastrar, consultar, alterar e excluir clientes |
| RE2 | Consultar clientes por filtros e buscas |
| RE3 | Autenticação com perfis de **administrador** e **operador** |
| RE4 | Validação de entradas e consultas parametrizadas (prevenção de SQL Injection) |
| RE5 | Proteção dos campos sensíveis e comunicação via HTTPS |

**Requisitos não funcionais:** interface simples, senhas protegidas por hash e chaves criptográficas fora do código-fonte.

**Fora do escopo:** gestão de processos judiciais.

### Tecnologias

- **JavaScript**: interface e funcionalidades
- **MySQL Server**: armazenamento e consulta
- **HTTPS/TLS**: proteção dos dados em trânsito
- **Wireshark** e **sqlmap**: verificação de tráfego e de falhas de injeção SQL (ambiente de testes)

---

## 🕵️ Projeto Autônomo – Criptografia + Esteganografia

Programa em **C** que cifra uma mensagem com **ChaCha20**, oculta o conteúdo cifrado dentro de uma imagem e permite recuperá-lo depois.

> A esteganografia oculta a *existência* da mensagem; a proteção do *conteúdo* vem da criptografia.

### Funcionalidades (requisitos)

| Código | Requisito |
| --- | --- |
| RA1 | Cifrar e decifrar texto com ChaCha20 (biblioteca consolidada) |
| RA2 | Ocultar o conteúdo cifrado em uma imagem e extraí-lo depois |
| RA3 | Verificar se a imagem tem capacidade suficiente para a mensagem |

**Detalhes de segurança:** cada cifragem usa um *nonce* que nunca se repete com a mesma chave; a chave é mantida em sigilo e necessária para a decifragem. Funciona com imagens **sem perda** (ex.: PNG).

### Como usar

```bash
# Compilar
[comando de compilação]

# Cifrar e ocultar
[exemplo de uso]

# Extrair e decifrar
[exemplo de uso]
```

---

## 🛡️ Desenvolvimento Seguro

Práticas aplicadas nas duas atividades:

- Autenticação e controle de acesso por perfil
- Validação de entradas e consultas parametrizadas
- Tratamento seguro de erros e proteção de informações sensíveis
- **SAST**: análise estática do código-fonte
- **DAST**: análise dinâmica da aplicação em execução (autenticação, autorização, validação de entradas, injeção SQL e exposição indevida de informações)

## 🧪 Testes

| Código | Caso de teste |
| --- | --- |
| CT-01 | CRUD completo de clientes |
| CT-02 | Login válido/inválido e perfis de acesso |
| CT-03 | Entradas inválidas e proteção contra SQL Injection |
| CT-04 | HTTPS e armazenamento dos campos sensíveis |
| CT-05 | Cifrar e decifrar uma mensagem |
| CT-06 | Ocultar, extrair e decifrar em imagem |
| CT-07 | Imagem sem espaço suficiente ou arquivo inválido |

## 📅 Status

- [ ] Modelagem e implementação do MySQL
- [ ] Interface, autenticação e perfis de acesso
- [ ] Proteção de dados sensíveis e HTTPS
- [ ] Cifragem/decifragem com ChaCha20
- [ ] Esteganografia em PNG
- [ ] Testes finais e documentação

## 🔒 Privacidade

Todo o desenvolvimento e os testes usam **dados fictícios ou anonimizados**. Nenhuma informação real de clientes do escritório é armazenada neste repositório.

## ⚠️ Aviso

Conteúdo com fins **exclusivamente educacionais**. Não utilize as técnicas aqui descritas em sistemas sem autorização.

## 📄 Licença

Distribuído sob a licença MIT. Veja o arquivo [LICENSE](LICENSE).
