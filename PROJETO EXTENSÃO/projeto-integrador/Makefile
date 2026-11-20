# Alvos de verificação do Marquezi Gestão. São os mesmos que o pipeline do GitHub Actions executa
# (.github/workflows/projeto-extensao.yml, na raiz do repositório).

PYTHON ?= python3
SOURCES = app.py crypto_utils.py mailer.py manage.py validators.py

.PHONY: all install build sast test dast

all: build sast test dast

# Instala as dependências do sistema
install:
	$(PYTHON) -m pip install -r requirements.txt

# Confere que todo o código Python compila
build:
	$(PYTHON) -m compileall -q $(SOURCES) tests

# SAST: revisão automática do código com o Semgrep e as regras em .semgrep
sast:
	semgrep scan --config .semgrep --error --metrics=off --disable-version-check $(SOURCES) templates static

# Testes automatizados do sistema
test:
	$(PYTHON) -m unittest discover tests -v

# DAST: sobe o sistema com HTTPS e MFA e o ataca pela rede com casos hostis, sem olhar o código
dast:
	$(PYTHON) tests/dast/hostile_cases.py
