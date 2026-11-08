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
