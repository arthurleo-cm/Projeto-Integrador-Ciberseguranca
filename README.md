# Projeto Integrador — Cibersegurança em Programação Segura

Escola Politécnica — PUC-Campinas · 2º semestre de 2026 · Prof. Dr. Felix Carvalho Rodrigues

**Integrantes:** Alexandre Monda, Arthur Henrique, Gabriel Lira, Maria Eduarda Marquezi, Murilo Augusto

| Projeto | Pasta | Linguagem |
| --- | --- | --- |
| [Projeto Autônomo — ChaCha20 e Esteganografia](#projeto-autônomo--criptografia-chacha20-e-esteganografia) | [`PROJETO AUTÔNOMO/`](PROJETO%20AUTÔNOMO/) | C |
| [Projeto Extensão — Marquezi Gestão](#projeto-extensão--marquezi-gestão) | [`PROJETO EXTENSÃO/projeto-integrador/`](PROJETO%20EXTENSÃO/projeto-integrador/) | Python (Flask) |

---

## Projeto Autônomo — Criptografia ChaCha20 e Esteganografia

O projeto autônomo tem como objetivo implementar um sistema de criptografia e descriptografia de mensagens utilizando o algoritmo **ChaCha20**, desenvolvido em linguagem C, com a possibilidade de ocultar as mensagens cifradas em imagens por meio de esteganografia.

O funcionamento é dividido em três etapas:

1. **Cifragem:** o usuário informa uma mensagem pelo terminal. O programa aplica o algoritmo ChaCha20, utilizando uma chave de 256 bits e um nonce de 96 bits, gerando um arquivo binário (`mensagem.bin`) com o conteúdo cifrado.
2. **Esteganografia:** o arquivo cifrado pode ser ocultado em uma imagem JPEG utilizando a ferramenta Steghide, dificultando a identificação da existência da mensagem.
3. **Decifragem:** após extrair o arquivo da imagem, o segundo programa realiza a operação inversa com ChaCha20, recuperando a mensagem original por meio da mesma chave e do nonce armazenado no arquivo.

O projeto demonstra a combinação de duas técnicas de proteção da informação: **criptografia**, responsável por preservar a confidencialidade do conteúdo, e **esteganografia**, utilizada para ocultar a presença da mensagem.

### Pré-requisitos

- **Linux** (ou WSL no Windows): o programa usa `/dev/urandom` para gerar o nonce.
- **GCC** e **Steghide**. No Ubuntu, Debian ou Kali:

```sh
sudo apt install gcc steghide
```

### Como executar

Dentro da pasta `PROJETO AUTÔNOMO`:

**1. Compilar os dois programas**

```sh
gcc -Wall -Wextra cifrar.c -o cifrar
gcc -Wall -Wextra decifrar.c -o decifrar
```

**2. Cifrar uma mensagem** (até 255 caracteres)

```sh
./cifrar
```

O programa mostra a mensagem cifrada em hexadecimal e grava `mensagem.bin`.

**3. Esconder o arquivo cifrado na imagem**

```sh
steghide embed -cf imagem_teste.jpg -ef mensagem.bin -sf imagem_oculta.jpg -e none -f
```

O Steghide pede uma senha (*passphrase*). Use `-e none` porque a mensagem já foi cifrada pelo ChaCha20.

**4. Apagar o arquivo original e extraí-lo da imagem**

```sh
rm mensagem.bin
steghide extract -sf imagem_oculta.jpg -xf mensagem.bin
```

Informe a mesma senha usada no passo 3. Apagar o arquivo antes prova que a mensagem veio da imagem.

**5. Decifrar**

```sh
./decifrar
```

Exemplo de saída:

```text
$ ./cifrar
Digite a mensagem que deseja cifrar: Mensagem secreta do PI
Mensagem cifrada (HEX): 6f0c2a...
Mensagem salva em mensagem.bin

$ ./decifrar
Mensagem decifrada: Mensagem secreta do PI
```

### Observações

- O `decifrar` sempre lê o arquivo `mensagem.bin` da pasta atual.
- Cada execução do `cifrar` substitui o `mensagem.bin` anterior.
- A chave é fixa no código por ser um projeto didático. Ela não deve ser usada para proteger dados reais (detalhes no relatório da Entrega 3).

---

## Projeto Extensão — Marquezi Gestão

O projeto de extensão tem como objetivo desenvolver um sistema web de uso interno para o escritório de advocacia Marquezi, permitindo organizar clientes, processos, documentos e recebimentos em um só lugar, com foco na proteção dos dados pessoais dos clientes. O sistema foi desenvolvido em **Python** com **Flask** e utiliza banco de dados **SQLite**.

O funcionamento é dividido em três frentes:

1. **Acesso seguro:** o usuário entra com e-mail e senha e, em seguida, informa um código de 6 dígitos enviado por e-mail (MFA). As senhas são armazenadas apenas como hash (scrypt), e existem dois perfis de acesso: **Operador** e **Administrador**, sendo que apenas o administrador visualiza valores financeiros, gerencia usuários e consulta a auditoria.
2. **Gestão do escritório:** o sistema permite cadastrar clientes (pessoa física e jurídica) com contatos, endereços e documentos, além de processos com número CNJ validado, histórico, anexos e registro de recebimentos. Todas as ações sensíveis ficam registradas em uma trilha de auditoria.
3. **Proteção dos dados:** toda a comunicação ocorre via **HTTPS** (com certificado autoassinado gerado na instalação), e os dados pessoais e arquivos são cifrados no banco com **AES-256-GCM**, de modo que o arquivo do banco, sozinho, não expõe nenhuma informação dos clientes.

O projeto aplica na prática os conteúdos de programação segura (proteção contra SQL injection, XSS, CSRF e força bruta), banco de dados e criptografia. A segurança é verificada continuamente por **SAST** (Semgrep), **testes automatizados** e **DAST** (22 ataques simulados), executados pelo GitHub Actions a cada atualização do código e diariamente.

### Pré-requisitos

- **Python 3.11 ou mais novo** (Linux, macOS ou Windows).

### Como executar

Dentro da pasta `PROJETO EXTENSÃO/projeto-integrador`:

**1. Criar o ambiente e instalar as dependências**

```sh
python3 -m venv venv
source venv/bin/activate          # no Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**2. Configurar o sistema** (só na primeira vez)

```sh
python3 manage.py setup
```

O comando cria o banco, a chave de cifragem e o certificado HTTPS. Depois pede o **nome, o e-mail e a senha do primeiro administrador** (a senha precisa ter pelo menos 12 caracteres).

**3. Iniciar**

```sh
python3 app.py
```

**4. Acessar** https://localhost:5000

- O navegador mostra um aviso de segurança na primeira vez. Isso é esperado, porque o certificado é autoassinado: clique em *Avançado → Continuar*.
- Entre com o e-mail e a senha criados no passo 2.
- **O código de 6 dígitos aparece no terminal onde o `app.py` está rodando** (modo de desenvolvimento). Para enviá-lo por e-mail de verdade, configure uma conta com `python3 manage.py smtp`.

**Opcional — dados de exemplo:** `python3 manage.py demo --confirm-demo-data` cria 3 operadores, 5 clientes e 3 processos fictícios.

### Verificações de segurança

```sh
make test     # testes automatizados
make dast     # 22 ataques simulados contra o sistema rodando
make sast     # análise estática (requer: pipx install semgrep==1.182.1)
make          # tudo acima em sequência
```

Mais detalhes (configuração de e-mail, produção, permissões e controles de segurança) estão no [README do projeto](PROJETO%20EXTENSÃO/projeto-integrador/README.md) e em [SEGURANCA.md](PROJETO%20EXTENSÃO/projeto-integrador/SEGURANCA.md).
