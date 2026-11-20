import re
from datetime import date, datetime

CONTROL_CHARS = re.compile(
    r"[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f‪-‮⁦-⁩]"
)
UFS = "AC AL AP AM BA CE DF ES GO MA MT MS MG PA PB PR PE PI RJ RN RS RO RR SC SP SE TO".split()
CONTACT_TYPES = ["TELEFONE", "WHATSAPP", "EMAIL", "INSTAGRAM", "LINKEDIN", "FACEBOOK", "SITE", "OUTRO"]
PROCESS_STATUS = [
    "EM_ANALISE", "EM_ANDAMENTO", "AGUARDANDO_AUDIENCIA", "AGUARDANDO_DECISAO",
    "SUSPENSO", "EM_RECURSO", "ENCERRADO", "ARQUIVADO",
]
PROCESS_TYPES = {
    "CIVEL": ["COBRANCA", "RESPONSABILIDADE_CIVIL", "OBRIGACAO_DE_FAZER", "EXECUCAO", "OUTRO"],
    "FAMILIA": ["DIVORCIO", "GUARDA", "ALIMENTOS", "UNIAO_ESTAVEL", "OUTRO"],
    "CONSUMIDOR": ["INDENIZACAO", "VICIO_PRODUTO", "NEGATIVACAO", "REVISAO_CONTRATUAL", "OUTRO"],
    "TRABALHISTA": ["RECLAMACAO", "RESCISAO", "VERBAS_TRABALHISTAS", "ACIDENTE_TRABALHO", "OUTRO"],
    "PREVIDENCIARIO": ["APOSENTADORIA", "BENEFICIO_INCAPACIDADE", "BPC_LOAS", "REVISAO_BENEFICIO", "OUTRO"],
    "EMPRESARIAL": ["CONTRATOS", "SOCIETARIO", "RECUPERACAO_CREDITO", "FALENCIA", "OUTRO"],
    "TRIBUTARIO": ["EXECUCAO_FISCAL", "REPETICAO_INDEBITO", "ANULATORIA", "CONSULTORIA", "OUTRO"],
    "ADMINISTRATIVO": ["SERVIDOR_PUBLICO", "LICITACAO", "IMPROBIDADE", "DESAPROPRIACAO", "OUTRO"],
    "IMOBILIARIO": ["DESPEJO", "USUCAPIAO", "LOCACAO", "REGULARIZACAO", "OUTRO"],
    "SUCESSOES": ["INVENTARIO", "ARROLAMENTO", "TESTAMENTO", "PARTILHA", "OUTRO"],
    "OUTRO": ["OUTRO"],
}
ASSOCIATE_ROLES = ["ADVOGADO", "ESTAGIARIO", "PARTE", "PERITO", "OUTRO"]
WEAK_PASSWORDS = ["123456789012", "administrador", "senha12345678", "password1234", "qwertyuiop12"]


class ValidationError(Exception):
    def __init__(self, message, field=None):
        super().__init__(message)
        self.field = field


def _text(value, max_len, field_name, required=True):
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} deve ser texto.", field_name)
    value = value.strip()
    if CONTROL_CHARS.search(value) or "\r" in value or "\n" in value:
        raise ValidationError(f"{field_name} contém caracteres inválidos.", field_name)
    if required and not value:
        raise ValidationError(f"{field_name} é obrigatório.", field_name)
    if len(value) > max_len:
        raise ValidationError(f"{field_name} excede {max_len} caracteres.", field_name)
    return value


def _optional_text(value, max_len, field_name):
    return _text(value or "", max_len, field_name, required=False)


def _multiline(value, max_len, field_name):
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if CONTROL_CHARS.search(value):
        raise ValidationError(f"{field_name} contém caracteres de controle.", field_name)
    if len(value) > max_len:
        raise ValidationError(f"{field_name} excede {max_len} caracteres.", field_name)
    return value


def _date(value, field_name, required=False, no_future=False):
    if not value:
        if required:
            raise ValidationError(f"{field_name} é obrigatória.", field_name)
        return ""
    value = str(value).strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        raise ValidationError(f"{field_name} inválida.", field_name)
    try:
        d = date.fromisoformat(value)
        if d.isoformat() != value:
            raise ValueError
    except ValueError:
        raise ValidationError(f"{field_name} inválida.", field_name)
    if no_future and d > date.today():
        raise ValidationError(f"{field_name} não pode ser futura.", field_name)
    return value


def _int(value, min_val, max_val, field_name, default=None):
    if value is None or value == "":
        if default is not None:
            return default
        raise ValidationError(f"{field_name} é obrigatório.", field_name)
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field_name} deve ser um número inteiro.", field_name)
    if n < min_val or n > max_val:
        raise ValidationError(f"{field_name} deve estar entre {min_val} e {max_val}.", field_name)
    return n


def valid_cpf_cnpj(s):
    s = re.sub(r"\D", "", s)
    if not re.match(r"^\d{11}$|^\d{14}$", s) or re.match(r"^(\d)\1+$", s):
        return False
    base_len = len(s) - 2
    for i in range(2):
        part = s[: base_len + i]
        if len(s) == 11:
            weights = list(range(base_len + i + 1, 1, -1))
        else:
            weights = [((base_len + i - 1 - j) % 8) + 2 for j in range(base_len + i)]
        total = sum(int(d) * w for d, w in zip(part, weights)) % 11
        expected = 0 if total < 2 else 11 - total
        if int(s[base_len + i]) != expected:
            return False
    return True


def valid_cnj(value):
    digits = re.sub(r"\D", "", str(value))
    if not re.match(r"^\d{20}$", digits):
        return False
    base = digits[:7] + digits[9:]
    expected = 98 - (int(base + "00") % 97)
    return digits[7:9] == str(expected).zfill(2)


def validate_password(password, field_name="Senha"):
    if not isinstance(password, str) or len(password) < 12:
        raise ValidationError(f"{field_name} deve ter no mínimo 12 caracteres.", field_name)
    if len(password) > 128:
        raise ValidationError(f"{field_name} excede 128 caracteres.", field_name)
    if CONTROL_CHARS.search(password):
        raise ValidationError(f"{field_name} contém caracteres inválidos.", field_name)
    if re.match(r"^(.)\1+$", password):
        raise ValidationError("Escolha uma senha menos previsível.", field_name)
    if password.lower() in WEAK_PASSWORDS:
        raise ValidationError("Escolha uma senha menos previsível.", field_name)
    return password


def validate_login(form):
    email = _text(form.get("email", ""), 180, "E-mail").lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValidationError("E-mail inválido.", "email")
    senha = form.get("senha", "")
    if not senha or len(senha) > 128:
        raise ValidationError("Informe a senha.", "senha")
    return {"email": email, "senha": senha}


def validate_user(form, is_edit=False):
    nome = _text(form.get("nome", ""), 150, "Nome")
    email = _text(form.get("email", ""), 180, "E-mail").lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValidationError("E-mail inválido.", "email")
    perfil = form.get("perfil", "OPERADOR")
    if perfil not in ("ADMINISTRADOR", "OPERADOR"):
        raise ValidationError("Perfil inválido.", "perfil")
    ativo = form.get("ativo") == "on" or form.get("ativo") is True
    senha = form.get("senha", "").strip()
    if senha:
        validate_password(senha)
    elif not is_edit:
        raise ValidationError("Informe a senha inicial.", "senha")
    return {"nome": nome, "email": email, "perfil": perfil, "ativo": ativo, "senha": senha or None}


def validate_client(form):
    tipo_pessoa = form.get("tipo_pessoa", "PF")
    if tipo_pessoa not in ("PF", "PJ"):
        raise ValidationError("Tipo de pessoa inválido.")
    nome = _text(form.get("nome", ""), 150, "Nome")
    cpf_cnpj = re.sub(r"[.\-/\s]", "", form.get("cpf_cnpj", ""))
    if cpf_cnpj:
        expected_len = 14 if tipo_pessoa == "PJ" else 11
        if len(cpf_cnpj) != expected_len or not valid_cpf_cnpj(cpf_cnpj):
            raise ValidationError("CPF/CNPJ inválido para o tipo de pessoa.")
    data_nascimento = ""
    if tipo_pessoa == "PF":
        data_nascimento = _date(form.get("data_nascimento", ""), "Data de nascimento", no_future=True)
    observacoes = _multiline(form.get("observacoes", ""), 10000, "Observações")
    ativo = form.get("ativo") == "on" or form.get("ativo") is True
    return {
        "tipo_pessoa": tipo_pessoa, "nome": nome, "cpf_cnpj": cpf_cnpj,
        "data_nascimento": data_nascimento, "observacoes": observacoes, "ativo": ativo,
    }


def validate_contact(form):
    tipo = form.get("tipo", "")
    if tipo not in CONTACT_TYPES:
        raise ValidationError("Tipo de contato inválido.")
    valor = _text(form.get("valor", ""), 180, "Contato")
    principal = form.get("principal") == "on"
    if tipo == "EMAIL" and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", valor):
        raise ValidationError("E-mail de contato inválido.")
    if tipo in ("TELEFONE", "WHATSAPP"):
        cleaned = re.sub(r"[().\s-]", "", valor)
        if not re.match(r"^\+?\d{10,15}$", cleaned):
            raise ValidationError("Telefone inválido.")
        valor = cleaned
    if tipo == "EMAIL":
        valor = valor.lower()
    return {"tipo": tipo, "valor": valor, "principal": principal}


def validate_address(form):
    tipo = form.get("tipo", "RESIDENCIAL")
    if tipo not in ("RESIDENCIAL", "COMERCIAL", "OUTRO"):
        raise ValidationError("Tipo de endereço inválido.")
    cep = re.sub(r"\D", "", form.get("cep", ""))
    if cep and not re.match(r"^\d{8}$", cep):
        raise ValidationError("CEP deve ter 8 dígitos.")
    return {
        "tipo": tipo, "cep": cep,
        "logradouro": _text(form.get("logradouro", ""), 150, "Logradouro"),
        "numero": _text(form.get("numero", ""), 15, "Número"),
        "complemento": _optional_text(form.get("complemento", ""), 100, "Complemento"),
        "bairro": _optional_text(form.get("bairro", ""), 100, "Bairro"),
        "cidade": _text(form.get("cidade", ""), 100, "Cidade"),
        "uf": form.get("uf", "SP") if form.get("uf", "SP") in UFS else "SP",
        "principal": form.get("principal") == "on",
    }


def validate_process(form, is_admin=False, old=None):
    id_cliente = _int(form.get("id_cliente"), 1, 999999999, "Cliente")
    numero_cnj = re.sub(r"\D", "", form.get("numero_cnj", ""))
    if not valid_cnj(numero_cnj):
        raise ValidationError("Número CNJ inválido.")
    titulo = _text(form.get("titulo", ""), 180, "Título")
    status = form.get("status", "EM_ANALISE")
    if status not in PROCESS_STATUS:
        raise ValidationError("Status inválido.")
    ramo = form.get("ramo", "CIVEL")
    if ramo not in PROCESS_TYPES:
        raise ValidationError("Ramo inválido.")
    tipificacao = form.get("tipificacao", "OUTRO")
    if tipificacao not in PROCESS_TYPES.get(ramo, []):
        raise ValidationError("Tipificação incompatível com o ramo selecionado.")
    situacao = form.get("situacao", "ATIVO")
    if situacao not in ("ATIVO", "ENCERRADO", "ARQUIVADO"):
        raise ValidationError("Situação inválida.")
    if status == "ENCERRADO" and situacao != "ENCERRADO":
        raise ValidationError("Processo encerrado deve ter situação encerrada.")
    if status == "ARQUIVADO" and situacao != "ARQUIVADO":
        raise ValidationError("Processo arquivado deve ter situação arquivada.")
    if situacao == "ENCERRADO" and status != "ENCERRADO":
        raise ValidationError("Situação encerrada exige status encerrado.")
    if situacao == "ARQUIVADO" and status != "ARQUIVADO":
        raise ValidationError("Situação arquivada exige status arquivado.")
    data_abertura = _date(form.get("data_abertura", ""), "Data de abertura", required=True, no_future=True)
    valor_centavos = 0
    previsao = ""
    if is_admin:
        try:
            valor_reais = float(form.get("valor_estimado", "0") or "0")
            valor_centavos = round(valor_reais * 100)
            if valor_centavos < 0:
                valor_centavos = 0
        except ValueError:
            valor_centavos = 0
        previsao = _date(form.get("previsao_recebimento", ""), "Previsão de recebimento")
    elif old:
        valor_centavos = old["valor_estimado_centavos"]
        previsao = old.get("previsao_recebimento", "")
    observacoes = _multiline(form.get("observacoes", ""), 10000, "Observações")
    orgao = _optional_text(form.get("orgao", ""), 150, "Órgão")
    numero_oab = _optional_text(form.get("numero_oab", ""), 10, "OAB").upper().replace("OAB", "").replace(" ", "").replace(".", "")
    data_publicacao = _date(form.get("data_publicacao", ""), "Data de publicação")
    data_disponibilizacao = _date(form.get("data_disponibilizacao", ""), "Data de disponibilização")
    ultima_movimentacao = _date(form.get("ultima_movimentacao", ""), "Última movimentação")
    intimacao_data = _date(form.get("intimacao_data", ""), "Data da intimação")
    intimacao_prazo = _int(form.get("intimacao_prazo", "0") or "0", 0, 365, "Prazo", default=0)
    intimacao_descricao = _multiline(form.get("intimacao_descricao", ""), 2000, "Descrição da intimação")
    if intimacao_prazo > 0 and not intimacao_data:
        raise ValidationError("Informe a data da intimação para contar o prazo.")
    return {
        "id_cliente": id_cliente, "numero_cnj": numero_cnj, "titulo": titulo,
        "status": status, "ramo": ramo, "tipificacao": tipificacao, "situacao": situacao,
        "data_abertura": data_abertura, "valor_estimado_centavos": valor_centavos,
        "previsao_recebimento": previsao, "observacoes": observacoes,
        "orgao": orgao, "numero_oab": numero_oab,
        "data_publicacao": data_publicacao, "data_disponibilizacao": data_disponibilizacao,
        "ultima_movimentacao": ultima_movimentacao,
        "intimacao": {"data": intimacao_data, "prazo_dias": intimacao_prazo, "descricao": intimacao_descricao},
    }


def validate_associate(form):
    return {
        "nome": _text(form.get("nome", ""), 150, "Nome do associado"),
        "papel": form.get("papel", "ADVOGADO") if form.get("papel") in ASSOCIATE_ROLES else "ADVOGADO",
        "oab": _optional_text(form.get("oab", ""), 10, "OAB").upper().replace("OAB", "").replace(" ", "").replace(".", ""),
    }


def validate_precedent(form):
    return {
        "tribunal": _text(form.get("tribunal", ""), 60, "Tribunal"),
        "referencia": _text(form.get("referencia", ""), 180, "Referência"),
        "resumo": _multiline(form.get("resumo", ""), 2000, "Resumo"),
        "url": _optional_text(form.get("url", ""), 500, "URL"),
    }


def validate_receipt(form):
    try:
        valor_reais = float(form.get("valor", "0") or "0")
        valor_centavos = round(valor_reais * 100)
        if valor_centavos <= 0:
            raise ValidationError("Informe um valor positivo.")
    except ValueError:
        raise ValidationError("Valor inválido.")
    data = _date(form.get("data_recebimento", ""), "Data do recebimento", required=True, no_future=True)
    observacao = _multiline(form.get("observacao", ""), 1000, "Observação")
    return {"valor_centavos": valor_centavos, "data_recebimento": data, "observacao": observacao}


def validate_preferences(form):
    tema = form.get("tema", "SISTEMA")
    if tema not in ("CLARO", "ESCURO", "SISTEMA"):
        tema = "SISTEMA"
    fonte = form.get("fonte", "NORMAL")
    if fonte not in ("NORMAL", "GRANDE", "MUITO_GRANDE"):
        fonte = "NORMAL"
    alto_contraste = form.get("alto_contraste") == "on" or form.get("alto_contraste") is True
    return {"tema": tema, "fonte": fonte, "alto_contraste": alto_contraste}
