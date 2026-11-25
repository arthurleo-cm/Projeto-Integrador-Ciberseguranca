### Projeto Autônomo — Criptografia ChaCha20 e Esteganografia

O projeto autônomo tem como objetivo implementar um sistema de criptografia e descriptografia de mensagens utilizando o algoritmo **ChaCha20**, desenvolvido em linguagem C, com a possibilidade de ocultar as mensagens cifradas em imagens por meio de esteganografia.

O funcionamento é dividido em três etapas:

1. **Cifragem:** o usuário informa uma mensagem pelo terminal. O programa aplica o algoritmo ChaCha20, utilizando uma chave de 256 bits e um nonce de 96 bits, gerando um arquivo binário (`mensagem.bin`) com o conteúdo cifrado.
2. **Esteganografia:** o arquivo cifrado pode ser ocultado em uma imagem JPEG utilizando a ferramenta Steghide, dificultando a identificação da existência da mensagem.
3. **Decifragem:** após extrair o arquivo da imagem, o segundo programa realiza a operação inversa com ChaCha20, recuperando a mensagem original por meio da mesma chave e do nonce armazenado no arquivo.

O projeto demonstra a combinação de duas técnicas de proteção da informação: **criptografia**, responsável por preservar a confidencialidade do conteúdo, e **esteganografia**, utilizada para ocultar a presença da mensagem.

Obs: Na hora de compliar os arquivos, utilize os comandos:
gcc -Wall -Wextra cifrar.c -o cifrar
gcc -Wall -Wextra decifrar.c -o decifrar


### Projeto Extensão — Marquezi Gestão

O projeto de extensão tem como objetivo desenvolver um sistema web de uso interno para o escritório de advocacia Marquezi, permitindo organizar clientes, processos, documentos e recebimentos em um só lugar, com foco na proteção dos dados pessoais dos clientes. O sistema foi desenvolvido em **Python** com **Flask** e utiliza banco de dados **SQLite**.

O funcionamento é dividido em três frentes:

1. **Acesso seguro:** o usuário entra com e-mail e senha e, em seguida, informa um código de 6 dígitos enviado por e-mail (MFA). As senhas são armazenadas apenas como hash (scrypt), e existem dois perfis de acesso: **Operador** e **Administrador**, sendo que apenas o administrador visualiza valores financeiros, gerencia usuários e consulta a auditoria.
2. **Gestão do escritório:** o sistema permite cadastrar clientes (pessoa física e jurídica) com contatos, endereços e documentos, além de processos com número CNJ validado, histórico, anexos e registro de recebimentos. Todas as ações sensíveis ficam registradas em uma trilha de auditoria.
3. **Proteção dos dados:** toda a comunicação ocorre via **HTTPS** (com certificado autoassinado gerado na instalação), e os dados pessoais e arquivos são cifrados no banco com **AES-256-GCM**, de modo que o arquivo do banco, sozinho, não expõe nenhuma informação dos clientes.

O projeto aplica na prática os conteúdos de programação segura (proteção contra SQL injection, XSS, CSRF e força bruta), banco de dados e criptografia. A segurança é verificada continuamente por **SAST** (Semgrep), **testes automatizados** e **DAST** (22 ataques simulados), executados pelo GitHub Actions a cada atualização do código e diariamente.

Obs: Para executar o sistema, dentro da pasta `PROJETO EXTENSÃO/projeto-integrador`, utilize os comandos:
pip install -r requirements.txt
python manage.py setup
python app.py
Depois, acesse https://localhost:5000
