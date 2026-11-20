-- Advocacia Pedro Marquezi
-- Projeto Integrador - Cyberbank - PUC-Campinas
-- Modelagem inicial para importacao no DrawSQL, dialeto MySQL.
-- Seis tabelas e cinco relacionamentos 1:N.
-- Campos de dados pessoais estao representados por seus tipos logicos.
-- Na implementacao da cifragem, adapte esses campos para comportar
-- ciphertext, nonce e tag, e revise as regras de busca e unicidade.
-- Este DDL define a estrutura; nao implementa criptografia ou autorizacao.

CREATE TABLE `usuarios` (
    `id_usuario` INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'Chave primaria do usuario',
    `nome` VARCHAR(150) NOT NULL COMMENT 'Nome do funcionario do escritorio',
    `email` VARCHAR(180) NOT NULL COMMENT 'Email utilizado no login',
    `senha_hash` VARCHAR(255) NOT NULL COMMENT 'Hash de senha gerado pela aplicacao; nunca senha em texto claro',
    `perfil` ENUM('ADMINISTRADOR', 'OPERADOR') NOT NULL DEFAULT 'OPERADOR' COMMENT 'Perfil de acesso aplicado pelo sistema',
    `ativo` TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'Permite desativar a conta preservando seu historico',
    `data_cadastro` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `data_atualizacao` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_usuario`),
    UNIQUE KEY `uk_usuarios_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Funcionarios autorizados a acessar o sistema';

CREATE TABLE `clientes` (
    `id_cliente` INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'Chave primaria do cliente',
    `tipo_pessoa` ENUM('PF', 'PJ') NOT NULL DEFAULT 'PF' COMMENT 'PF: pessoa fisica; PJ: pessoa juridica',
    `nome` VARCHAR(150) NOT NULL COMMENT 'Nome completo ou razao social',
    `cpf_cnpj` VARCHAR(14) NULL COMMENT 'CPF ou CNPJ normalizado, sem pontuacao; opcional',
    `data_nascimento` DATE NULL COMMENT 'Opcional e aplicavel a pessoa fisica',
    `observacoes` TEXT NULL COMMENT 'Observacoes sobre o cadastro, com acesso restrito',
    `ativo` TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'Indica se o cadastro esta ativo',
    `data_cadastro` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `data_atualizacao` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_cliente`),
    UNIQUE KEY `uk_clientes_cpf_cnpj` (`cpf_cnpj`),
    KEY `idx_clientes_nome` (`nome`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Cadastro central de pessoas fisicas e juridicas atendidas';

CREATE TABLE `contatos` (
    `id_contato` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `id_cliente` INT UNSIGNED NOT NULL COMMENT 'Cliente proprietario do contato',
    `tipo` ENUM('TELEFONE', 'EMAIL') NOT NULL,
    `valor` VARCHAR(180) NOT NULL COMMENT 'Telefone com DDD ou endereco de email',
    `principal` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Contato preferencial; a aplicacao limita a um por cliente e tipo',
    PRIMARY KEY (`id_contato`),
    UNIQUE KEY `uk_contatos_cliente_tipo_valor` (`id_cliente`, `tipo`, `valor`),
    CONSTRAINT `fk_contatos_clientes`
        FOREIGN KEY (`id_cliente`) REFERENCES `clientes` (`id_cliente`)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Um cliente pode possuir varios telefones e emails';

CREATE TABLE `enderecos` (
    `id_endereco` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `id_cliente` INT UNSIGNED NOT NULL COMMENT 'Cliente proprietario do endereco',
    `tipo` ENUM('RESIDENCIAL', 'COMERCIAL', 'OUTRO') NOT NULL DEFAULT 'RESIDENCIAL',
    `cep` CHAR(8) NULL COMMENT 'CEP sem pontuacao',
    `logradouro` VARCHAR(150) NOT NULL,
    `numero` VARCHAR(15) NOT NULL COMMENT 'Texto para permitir valores como s/n',
    `complemento` VARCHAR(100) NULL,
    `bairro` VARCHAR(100) NULL,
    `cidade` VARCHAR(100) NOT NULL,
    `uf` CHAR(2) NOT NULL COMMENT 'Sigla do estado',
    `principal` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Endereco preferencial; a aplicacao limita a um por cliente',
    PRIMARY KEY (`id_endereco`),
    KEY `idx_enderecos_cliente` (`id_cliente`),
    CONSTRAINT `fk_enderecos_clientes`
        FOREIGN KEY (`id_cliente`) REFERENCES `clientes` (`id_cliente`)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Enderecos residenciais e comerciais dos clientes';

CREATE TABLE `documentos` (
    `id_documento` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `id_cliente` INT UNSIGNED NOT NULL COMMENT 'Cliente ao qual o documento pertence',
    `id_usuario_envio` INT UNSIGNED NOT NULL COMMENT 'Usuario que cadastrou o arquivo',
    `titulo` VARCHAR(150) NOT NULL COMMENT 'Nome descritivo exibido no sistema',
    `tipo_documento` ENUM('IDENTIFICACAO', 'PROCURACAO', 'CONTRATO', 'OUTRO') NOT NULL DEFAULT 'OUTRO',
    `chave_arquivo` VARCHAR(255) NOT NULL COMMENT 'Identificador interno do arquivo em armazenamento privado; nao uma URL publica',
    `nome_original` VARCHAR(255) NOT NULL COMMENT 'Nome original do arquivo, utilizado apenas para exibicao',
    `tipo_mime` VARCHAR(100) NOT NULL COMMENT 'Tipo do arquivo verificado pelo servidor',
    `tamanho_bytes` BIGINT UNSIGNED NOT NULL COMMENT 'Tamanho do arquivo em bytes',
    `data_envio` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_documento`),
    UNIQUE KEY `uk_documentos_chave_arquivo` (`chave_arquivo`),
    KEY `idx_documentos_cliente` (`id_cliente`),
    KEY `idx_documentos_usuario_envio` (`id_usuario_envio`),
    CONSTRAINT `fk_documentos_clientes`
        FOREIGN KEY (`id_cliente`) REFERENCES `clientes` (`id_cliente`)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT `fk_documentos_usuarios`
        FOREIGN KEY (`id_usuario_envio`) REFERENCES `usuarios` (`id_usuario`)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Metadados de arquivos digitalizados vinculados a cada cliente';

CREATE TABLE `logs_auditoria` (
    `id_log` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `id_usuario` INT UNSIGNED NOT NULL COMMENT 'Usuario responsavel pela operacao',
    `acao` ENUM('CADASTRO', 'ALTERACAO', 'EXCLUSAO') NOT NULL,
    `tabela_afetada` VARCHAR(64) NOT NULL COMMENT 'Tabela em que ocorreu a operacao',
    `id_registro` INT UNSIGNED NOT NULL COMMENT 'Identificador historico; nao e FK, pois pode apontar para tabelas diferentes',
    `data_hora` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id_log`),
    KEY `idx_logs_usuario_data` (`id_usuario`, `data_hora`),
    KEY `idx_logs_tabela_registro` (`tabela_afetada`, `id_registro`),
    CONSTRAINT `fk_logs_usuarios`
        FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Historico das operacoes; preenchido pela aplicacao sem copiar dados pessoais';

-- Regras complementares a implementar na aplicacao:
-- 1. Autorizar cada operacao conforme o perfil; ENUM nao implementa permissoes.
-- 2. Validar CPF/CNPJ, emails, telefones, CEP e UF antes de salvar.
-- 3. Garantir um contato principal por cliente e tipo e um endereco principal
--    por cliente, incluindo tratamento de operacoes concorrentes.
-- 4. Gravar a operacao e o log na mesma transacao.
-- 5. Desativar usuarios em vez de excluir contas com documentos ou logs.
-- 6. Tratar registros e arquivos vinculados antes de excluir um cliente.
-- 7. Proteger os arquivos no armazenamento e verificar permissao no download.
-- 8. Usar consultas parametrizadas e cifrar os campos sensiveis conforme o PI.
