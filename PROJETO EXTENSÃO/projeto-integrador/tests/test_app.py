"""Testes automatizados. Rodar com: python -m unittest discover tests"""
import io
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="marquezi-test-")
os.environ.update(DATA_DIR=TMP, MFA_MODE="test", TLS_MODE="off")
os.environ.pop("APP_ORIGIN", None)
sys.path.insert(0, str(ROOT))

import crypto_utils  # noqa: E402

Path(TMP, "encryption.key").write_bytes(os.urandom(32))
crypto_utils.load_key(str(Path(TMP, "encryption.key")))
with sqlite3.connect(Path(TMP, "advocacia.sqlite")) as _db:
    _db.executescript((ROOT / "database" / "schema.sqlite.sql").read_text())
    for nome, email, perfil in [("Admin Teste", "admin@teste.com", "ADMINISTRADOR"), ("Operador Teste", "op@teste.com", "OPERADOR")]:
        _db.execute("INSERT INTO usuarios(dados,email_indice,senha_hash,perfil,ativo) VALUES(?,?,?,?,1)",
                    (crypto_utils.pack({"nome": nome, "email": email}, "usuario"), crypto_utils.hmac_index(email),
                     crypto_utils.hash_password("SenhaForte#2026"), perfil))

import app as appmod  # noqa: E402
import mailer  # noqa: E402

TODAY = date.today().isoformat()
_base = "0000001" + "2024826" + "0100"
CNJ = f"0000001{98 - int(_base + '00') % 97:02d}20248260100"


def csrf(html):
    return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)


class Base(unittest.TestCase):
    def client(self):
        c = appmod.app.test_client()
        c.environ_base["REMOTE_ADDR"] = f"10.0.0.{id(self) % 250}"
        return c

    def login(self, email="admin@teste.com", senha="SenhaForte#2026"):
        c = self.client()
        r = c.get("/login")
        r = c.post("/login", data={"email": email, "senha": senha, "_csrf": csrf(r.text)})
        self.assertEqual(r.status_code, 302, r.text)
        r = c.get("/login/codigo")
        code = mailer.test_codes.pop(email)
        r = c.post("/login/codigo", data={"codigo": code, "_csrf": csrf(r.text)}, follow_redirects=True)
        self.assertIn("Visão geral", r.text)
        return c, csrf(r.text)


class TestAuth(Base):
    def test_senha_errada(self):
        c = self.client()
        r = c.get("/login")
        r = c.post("/login", data={"email": "admin@teste.com", "senha": "errada-errada", "_csrf": csrf(r.text)})
        self.assertEqual(r.status_code, 401)
        self.assertNotIn("admin@teste.com", mailer.test_codes)

    def test_mfa_obrigatorio(self):
        c = self.client()
        r = c.get("/login")
        c.post("/login", data={"email": "admin@teste.com", "senha": "SenhaForte#2026", "_csrf": csrf(r.text)})
        mailer.test_codes.pop("admin@teste.com")
        self.assertEqual(c.get("/dashboard").status_code, 302, "senha sozinha não pode abrir o sistema")

    def test_mfa_limite_de_tentativas(self):
        c = self.client()
        r = c.get("/login")
        c.post("/login", data={"email": "op@teste.com", "senha": "SenhaForte#2026", "_csrf": csrf(r.text)})
        code = mailer.test_codes.pop("op@teste.com")
        wrong = f"{(int(code) + 1) % 1_000_000:06d}"
        token = csrf(c.get("/login/codigo").text)
        for _ in range(5):
            r = c.post("/login/codigo", data={"codigo": wrong, "_csrf": token})
        self.assertEqual(r.status_code, 302)
        r = c.post("/login/codigo", data={"codigo": code, "_csrf": token})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(c.get("/dashboard").status_code, 302, "código certo não vale depois do bloqueio")

    def test_codigo_nao_reutilizavel(self):
        c, _ = self.login()
        c2 = self.client()
        r = c2.get("/login")
        c2.post("/login", data={"email": "admin@teste.com", "senha": "SenhaForte#2026", "_csrf": csrf(r.text)})
        mailer.test_codes.pop("admin@teste.com")
        self.assertEqual(c2.post("/login/codigo", data={"codigo": "000000", "_csrf": csrf(c2.get('/login/codigo').text)}).status_code, 401)

    def test_token_antigo_mostra_aviso(self):
        c = self.client()
        c.get("/login")
        r = c.post("/login", data={"email": "admin@teste.com", "senha": "SenhaForte#2026", "_csrf": "token-antigo"},
                   follow_redirects=True)
        self.assertIn("O formulário expirou", r.text)

    def test_csrf(self):
        c, _ = self.login()
        self.assertEqual(c.post("/clients/new", data={"nome": "X"}).status_code, 302)  # 403 vira redirect ao login

    def test_origem_externa_recusada(self):
        c, token = self.login()
        r = c.post("/clients/new", data={"_csrf": token, "nome": "X"}, headers={"Origin": "https://malicioso.example"})
        self.assertNotEqual(r.status_code, 200)

    def test_cabecalhos_de_seguranca(self):
        r = self.client().get("/login")
        for h in ("Content-Security-Policy", "X-Frame-Options", "Cross-Origin-Opener-Policy", "Cache-Control"):
            self.assertIn(h, r.headers)
        self.assertIn("SameSite=Strict", r.headers.get("Set-Cookie", ""))
        self.assertIn("HttpOnly", r.headers.get("Set-Cookie", ""))

    def test_metodo_nao_permitido(self):
        self.assertEqual(self.client().put("/login").status_code, 405)


class TestFluxo(Base):
    def test_cliente_processo_anexos_financeiro(self):
        c, t = self.login()
        r = c.post("/clients/new", data={"_csrf": t, "tipo_pessoa": "PF", "nome": "Maria", "ativo": "on", "op": "add:contato"})
        self.assertIn("contato_tipo_0", r.text)
        r = c.post("/clients/new", data={"_csrf": t, "tipo_pessoa": "PF", "nome": "Maria", "cpf_cnpj": "529.982.247-25", "ativo": "on",
                                         "contato_tipo_0": "EMAIL", "contato_valor_0": "maria@ex.com"}, follow_redirects=True)
        self.assertIn("Cadastro salvo", r.text)
        cid = re.search(r"/clients/(\d+)/documents", r.text).group(1)

        r = c.post(f"/clients/{cid}/documents", data={"_csrf": t, "titulo": "Falso", "arquivo": (io.BytesIO(b"MZ\x90\x00exe"), "virus.pdf")},
                   content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("Envie um PDF", r.text, "assinatura do arquivo precisa ser conferida")

        r = c.post("/processes/new", data={"_csrf": t, "id_cliente": cid, "numero_cnj": CNJ, "titulo": "Cobrança", "data_abertura": TODAY,
                                           "classificacao": "CIVEL:COBRANCA", "status": "EM_ANDAMENTO", "valor_estimado": "1000"},
                   follow_redirects=True)
        self.assertIn("Processo salvo", r.text)
        pid = re.search(r"/processes/(\d+)/files", r.text).group(1)
        r = c.post(f"/processes/{pid}/receipts", data={"_csrf": t, "valor": "250", "data_recebimento": TODAY}, follow_redirects=True)
        self.assertIn("Parcial", r.text)
        rid = re.search(r"/receipts/(\d+)/delete", r.text).group(1)
        self.assertIn("Tem certeza?", c.post(f"/receipts/{rid}/delete", data={"_csrf": t}).text)

        op, _ = self.login("op@teste.com")
        r = op.get(f"/processes/{pid}")
        self.assertNotIn("R$ 1.000,00", r.text, "operador não vê valores")
        self.assertEqual(op.post(f"/receipts/{rid}/delete", data={"_csrf": csrf(r.text), "confirmado": "1"}).status_code, 302)
        self.assertIn("R$ 250,00", c.get(f"/processes/{pid}").text, "operador não pode excluir recebimento")

    def test_arquivo_grande(self):
        c, t = self.login()
        r = c.post("/clients/1/documents", data={"_csrf": t, "titulo": "x", "arquivo": (io.BytesIO(b"%PDF" + b"0" * (11 * 1024 * 1024)), "g.pdf")},
                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)


if __name__ == "__main__":
    unittest.main()
