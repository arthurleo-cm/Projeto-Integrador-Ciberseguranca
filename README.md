🔐 Projeto Integrador — Cibersegurança e Programação Segura

Repositório acadêmico do Projeto Integrador da área de Cibersegurança e Programação Segura, desenvolvido no contexto do Cyberbank, da Escola Politécnica da PUC-Campinas.

O projeto reúne duas atividades complementares: o desenvolvimento de um sistema seguro para gerenciamento de clientes de um escritório de advocacia e a implementação de uma aplicação em C para criptografia de mensagens e esteganografia em imagens.

📌 Sobre o projeto

O objetivo é aplicar conceitos de banco de dados, desenvolvimento seguro e criptografia no desenvolvimento de soluções que contribuam para a proteção e a confidencialidade das informações.

O repositório está organizado conceitualmente em dois projetos:

1. 🏢 Sistema de cadastro e gerenciamento de clientes

Projeto de extensão

Desenvolvimento de um sistema para digitalizar e organizar o cadastro de clientes da Advocacia Pedro Marquezi, buscando facilitar o armazenamento, a consulta e a manutenção dos registros, com atenção à segurança das informações.

Funcionalidades previstas:

Cadastro, consulta, alteração e exclusão de clientes (CRUD).

Pesquisa e filtragem de registros.

Autenticação de usuários.

Controle de acesso por perfil: administrador e operador.

Validação de dados de entrada.

Consultas parametrizadas para prevenir injeção de SQL.

Proteção de informações sensíveis.

Comunicação segura por HTTPS com TLS.

Tecnologias previstas:

JavaScript

MySQL Server

HTTPS/TLS

2. 🔒 Criptografia de mensagens e esteganografia em imagens

Projeto autônomo

Desenvolvimento de um programa em C para cifrar e decifrar mensagens utilizando o algoritmo ChaCha20 e ocultar o conteúdo cifrado em imagens, permitindo sua extração e posterior recuperação da mensagem original.

Funcionalidades previstas:

Cifragem e decifragem de mensagens de texto com ChaCha20.

Ocultação de mensagens cifradas em imagens PNG.

Extração do conteúdo oculto.

Recuperação da mensagem original após a extração e a decifragem.

Verificação da capacidade da imagem para armazenar a mensagem.

Tratamento de imagens inválidas ou com espaço insuficiente.

Tecnologias previstas:

Linguagem C

Biblioteca criptográfica com suporte a ChaCha20

Biblioteca para leitura e escrita de imagens PNG
