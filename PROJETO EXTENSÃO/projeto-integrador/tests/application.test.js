import { test, after } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  readFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
const dir = mkdtempSync(join(tmpdir(), "advocacia-"));
process.env.DATA_DIR = dir;
process.env.APP_ORIGIN = "http://localhost:3000";
process.env.MFA_MODE = "test";
writeFileSync(join(dir, "encryption.key"), randomBytes(32), { mode: 0o600 });
const { db, pack, index, hashPassword, encrypt, decrypt } = await import(
  "../server/store.js"
);
const { validDocument, validCNJ } = await import("../server/validation.js");
const { isPublicIp } = await import("../server/network-security.js");
const { takeTestMfaCode, takeLatestTestMfaCode } = await import(
  "../server/mailer.js"
);
const { app } = await import("../server/app.js");
const password = "Senha-longa-para-testes-123";
const hash = await hashPassword(password);
for (const [nome, email, perfil, legacyMfaEmail] of [
  [
    "Responsável",
    "admin@escritorio.test",
    "ADMINISTRADOR",
    "destino-legado@escritorio.test",
  ],
  ["Equipe", "operador@escritorio.test", "OPERADOR", undefined],
])
  db.prepare(
    "INSERT INTO usuarios(dados,email_indice,senha_hash,perfil) VALUES(?,?,?,?)",
  ).run(
    pack(
      { nome, email, ...(legacyMfaEmail ? { email_mfa: legacyMfaEmail } : {}) },
      "usuario",
    ),
    index(email),
    hash,
    perfil,
  );
const server = app.listen(0, "127.0.0.1");
await new Promise((r) => server.once("listening", r));
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  await new Promise((r) => server.close(r));
  db.close();
  rmSync(dir, { recursive: true, force: true });
});
async function call(
  path,
  {
    method = "GET",
    body,
    session,
    origin = "http://localhost:3000",
    csrf = true,
  } = {},
) {
  const headers = { Origin: origin };
  if (session) {
    headers.Cookie = session.cookie;
    if (csrf) headers["X-CSRF-Token"] = session.csrf;
  }
  if (body && !(body instanceof FormData))
    headers["Content-Type"] = "application/json";
  const response = await fetch(base + "/api" + path, {
    method,
    headers,
    body:
      body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
  });
  const type = response.headers.get("content-type");
  const data = type?.includes("application/json")
    ? await response.json()
    : Buffer.from(await response.arrayBuffer());
  return { status: response.status, data, response };
}
const responseCookies = (response) =>
  response.headers
    .getSetCookie()
    .map((value) => value.split(";", 1)[0])
    .join("; ");
const cookieValue = (cookies, name) =>
  cookies
    .split(";")
    .map((value) => value.trim())
    .find((value) => value.startsWith(name + "="))
    ?.slice(name.length + 1);
async function login(email, loginPassword = password) {
  const r = await call("/login", {
    method: "POST",
    body: { email, senha: loginPassword },
  });
  assert.equal(r.status, 202);
  assert.equal(r.response.headers.get("set-cookie"), null);
  assert.equal(r.data.mfa_required, true);
  const code = takeTestMfaCode(r.data.desafio);
  assert.match(code, /^\d{6}$/);
  const verified = await call("/mfa/verify", {
    method: "POST",
    body: { desafio: r.data.desafio, codigo: code },
  });
  assert.equal(verified.status, 200, JSON.stringify(verified.data));
  return {
    cookie: responseCookies(verified.response),
    csrf: verified.data.csrf,
  };
}
const client = {
  nome: "Cliente de verificação",
  tipo_pessoa: "PF",
  cpf_cnpj: "52998224725",
  data_nascimento: "1990-05-20",
  observacoes: "Informação confidencial única",
  ativo: true,
  contatos: [
    { tipo: "EMAIL", valor: "cliente@escritorio.test", principal: true },
    { tipo: "TELEFONE", valor: "11999999999", principal: true },
  ],
  enderecos: [
    {
      tipo: "RESIDENCIAL",
      cep: "13000000",
      logradouro: "Rua Central",
      numero: "123",
      complemento: "",
      bairro: "Centro",
      cidade: "Campinas",
      uf: "SP",
      principal: true,
    },
  ],
};
test("validação de documentos e cifragem autenticada", () => {
  assert.equal(validDocument(client.cpf_cnpj), true);
  assert.equal(validDocument("11222333000181"), true);
  assert.equal(validDocument("11111111111"), false);
  assert.equal(validDocument("52998224726"), false);
  assert.equal(validCNJ("0200043-65.2009.2.00.0000"), true);
  assert.equal(validCNJ("0200043-66.2009.2.00.0000"), false);
  const bytes = encrypt(Buffer.from("confidencial"), "arquivo");
  assert.equal(decrypt(bytes, "arquivo").toString(), "confidencial");
  assert.throws(() => decrypt(bytes, "outro"));
  bytes[30] ^= 1;
  assert.throws(() => decrypt(bytes, "arquivo"));
});
test("proteção SSRF recusa endereços locais, privados e reservados", () => {
  for (const address of [
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
  ])
    assert.equal(isPublicIp(address), false, address);
  assert.equal(isPublicIp("8.8.8.8"), true);
  assert.equal(isPublicIp("2607:f8b0:4004:800::200e"), true);
});
test("MFA cria sessão somente após código válido, limita e impede reuso", async () => {
  const started = await call("/login", {
    method: "POST",
    body: { email: "admin@escritorio.test", senha: password },
  });
  assert.equal(started.status, 202);
  assert.equal(started.response.headers.get("set-cookie"), null);
  assert.equal(started.data.mfa_required, true);
  assert.match(started.data.destino, /^a\*+@escritorio\.test$/);
  const code = takeTestMfaCode(started.data.desafio);
  assert.equal(takeLatestTestMfaCode("admin@escritorio.test"), code);
  assert.equal(
    takeLatestTestMfaCode("destino-legado@escritorio.test"),
    undefined,
  );
  assert.match(code, /^\d{6}$/);
  const stored = db
    .prepare("SELECT codigo_hash,tentativas FROM desafios_mfa")
    .get();
  assert.notEqual(stored.codigo_hash, code);
  assert.equal(stored.tentativas, 0);

  const immediateResend = await call("/mfa/resend", {
    method: "POST",
    body: { desafio: started.data.desafio },
  });
  assert.equal(immediateResend.status, 429);
  assert.ok(Number(immediateResend.response.headers.get("retry-after")) > 0);

  const wrong = code === "000000" ? "000001" : "000000";
  assert.equal(
    (
      await call("/mfa/verify", {
        method: "POST",
        body: { desafio: started.data.desafio, codigo: wrong },
      })
    ).status,
    401,
  );
  assert.equal(
    db.prepare("SELECT tentativas FROM desafios_mfa").get().tentativas,
    1,
  );
  const verified = await call("/mfa/verify", {
    method: "POST",
    body: { desafio: started.data.desafio, codigo: code },
  });
  assert.equal(verified.status, 200);
  assert.ok(verified.response.headers.get("set-cookie"));
  assert.equal(db.prepare("SELECT count(*) n FROM desafios_mfa").get().n, 0);
  assert.equal(
    (
      await call("/mfa/verify", {
        method: "POST",
        body: { desafio: started.data.desafio, codigo: code },
      })
    ).status,
    401,
  );
  await call("/logout", {
    method: "POST",
    session: {
      cookie: responseCookies(verified.response),
      csrf: verified.data.csrf,
    },
  });
});
test("JWT é validado e refresh token rotaciona com detecção de reuso", async () => {
  const original = await login("admin@escritorio.test");
  const access = cookieValue(original.cookie, "access");
  const refresh = cookieValue(original.cookie, "refresh");
  assert.equal(access.split(".").length, 3);
  assert.match(refresh, /^[A-Za-z0-9_-]{43}$/);

  const refreshed = await call("/refresh", {
    method: "POST",
    body: {},
    session: original,
  });
  assert.equal(refreshed.status, 200, JSON.stringify(refreshed.data));
  const rotatedCookies = responseCookies(refreshed.response);
  assert.notEqual(cookieValue(rotatedCookies, "access"), access);
  assert.notEqual(cookieValue(rotatedCookies, "refresh"), refresh);
  assert.notEqual(refreshed.data.csrf, original.csrf);

  const replay = await call("/refresh", {
    method: "POST",
    body: {},
    session: original,
  });
  assert.equal(replay.status, 401);
  assert.equal(
    (
      await call("/me", {
        session: { cookie: rotatedCookies, csrf: refreshed.data.csrf },
      })
    ).status,
    401,
  );

  const fresh = await login("admin@escritorio.test");
  const freshAccess = cookieValue(fresh.cookie, "access");
  const altered =
    freshAccess.slice(0, -1) + (freshAccess.endsWith("A") ? "B" : "A");
  const tamperedCookies = fresh.cookie.replace(freshAccess, altered);
  assert.equal(
    (
      await call("/me", {
        session: { cookie: tamperedCookies, csrf: fresh.csrf },
      })
    ).status,
    401,
  );
});
test("processos, finanças, fotos, contatos sociais e preferências respeitam perfis", async () => {
  const admin = await login("admin@escritorio.test");
  const operator = await login("operador@escritorio.test");
  const newClient = await call("/clients", {
    method: "POST",
    session: operator,
    body: {
      nome: "Cliente do processo",
      tipo_pessoa: "PJ",
      cpf_cnpj: "",
      data_nascimento: "",
      observacoes: "Cadastro para testar processos",
      ativo: true,
      contatos: [
        { tipo: "WHATSAPP", valor: "(11) 99999-0000", principal: true },
        { tipo: "INSTAGRAM", valor: "@cliente.processo", principal: true },
        {
          tipo: "SITE",
          valor: "https://cliente.example",
          principal: true,
        },
      ],
      enderecos: [],
    },
  });
  assert.equal(newClient.status, 201, JSON.stringify(newClient.data));
  const clientId = newClient.data.id_cliente;
  const options = await call("/process-options", { session: operator });
  assert.equal(options.status, 200);
  assert.equal(Object.hasOwn(options.data.tipos, "PENAL"), false);

  const processBody = {
    id_cliente: clientId,
    numero_cnj: "02000436520092000000",
    titulo: "Ação de cobrança contratual",
    status: "EM_ANALISE",
    ramo: "CIVEL",
    tipificacao: "COBRANCA",
    situacao: "ATIVO",
    data_abertura: "2026-01-10",
    valor_estimado_centavos: 999999,
    observacoes: "Processo fictício para testes",
  };
  assert.equal(
    (
      await call("/processes", {
        method: "POST",
        session: operator,
        body: { ...processBody, numero_cnj: "02000436620092000000" },
      })
    ).status,
    400,
  );
  const created = await call("/processes", {
    method: "POST",
    session: operator,
    body: processBody,
  });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const processId = created.data.id_processo;
  const operatorView = await call(`/processes/${processId}`, {
    session: operator,
  });
  assert.equal(operatorView.status, 200);
  assert.equal("valor_estimado_centavos" in operatorView.data, false);
  assert.equal("recebimentos" in operatorView.data, false);
  assert.equal(operatorView.data.historico[0].evento, "PROCESSO_CADASTRADO");
  const adminView = await call(`/processes/${processId}`, { session: admin });
  assert.equal(adminView.data.valor_estimado_centavos, 0);

  const updated = await call(`/processes/${processId}`, {
    method: "PUT",
    session: admin,
    body: {
      ...processBody,
      status: "EM_ANDAMENTO",
      valor_estimado_centavos: 150000,
      previsao_recebimento: "2026-12-15",
      versao: 1,
    },
  });
  assert.equal(updated.status, 200, JSON.stringify(updated.data));
  assert.equal(
    (
      await call(`/processes/${processId}/receipts`, {
        method: "POST",
        session: operator,
        body: {
          valor_centavos: 50000,
          data_recebimento: "2026-02-01",
          observacao: "Entrada",
        },
      })
    ).status,
    403,
  );
  const receipt = await call(`/processes/${processId}/receipts`, {
    method: "POST",
    session: admin,
    body: {
      valor_centavos: 50000,
      data_recebimento: "2026-02-01",
      observacao: "Entrada contratual",
    },
  });
  assert.equal(receipt.status, 201, JSON.stringify(receipt.data));

  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "base64",
  );
  const upload = new FormData();
  upload.set("titulo", "Foto da vistoria");
  upload.set("arquivo", new Blob([png], { type: "image/png" }), "../foto.png");
  const file = await call(`/processes/${processId}/files`, {
    method: "POST",
    session: operator,
    body: upload,
  });
  assert.equal(file.status, 201, JSON.stringify(file.data));
  const fileId = file.data.id_arquivo;
  const preview = await call(`/process-files/${fileId}/preview`, {
    session: operator,
  });
  assert.equal(preview.status, 200);
  assert.equal(preview.response.headers.get("content-type"), "image/jpeg");
  assert.deepEqual(preview.data.subarray(0, 2), Buffer.from([0xff, 0xd8]));

  assert.equal(
    (
      await call(`/processes?valor_min=1`, {
        session: operator,
      })
    ).status,
    403,
  );
  const filtered = await call(
    `/processes?q=${encodeURIComponent("Cliente do processo")}&ramo=CIVEL&valor_min=100000&recebido_min=40000&com_anexos=FOTO`,
    { session: admin },
  );
  assert.equal(filtered.status, 200);
  assert.equal(filtered.data.total, 1);
  assert.equal(filtered.data.items[0].id_processo, processId);
  assert.equal(
    (await call("/processes?status=' OR 1=1--", { session: admin })).status,
    400,
  );

  const preference = await call("/preferences", {
    method: "PUT",
    session: operator,
    body: { tema: "ESCURO", fonte: "GRANDE", alto_contraste: true },
  });
  assert.equal(preference.status, 200);
  const me = await call("/me", { session: operator });
  assert.deepEqual(me.data.user.preferencias, {
    tema: "ESCURO",
    fonte: "GRANDE",
    alto_contraste: true,
  });

  let detail = await call(`/processes/${processId}`, { session: admin });
  assert.equal(detail.data.valor_recebido_centavos, 50000);
  assert.equal(detail.data.saldo_centavos, 100000);
  assert.equal(detail.data.status_pagamento, "PARCIAL");
  assert.equal(detail.data.previsao_recebimento, "2026-12-15");
  const restrictedDetail = await call(`/processes/${processId}`, {
    session: operator,
  });
  assert.equal("previsao_recebimento" in restrictedDetail.data, false);
  assert.equal("status_pagamento" in restrictedDetail.data, false);
  assert.equal(detail.data.arquivos[0].categoria, "FOTO");
  assert.equal(detail.data.arquivos[0].nome_original.includes("/"), false);
  assert.equal(
    (
      await call(`/processes/${processId}`, {
        method: "DELETE",
        session: admin,
        body: { versao: detail.data.versao },
      })
    ).status,
    409,
  );
  assert.equal(
    (await call(`/process-files/${fileId}`, { method: "DELETE", session: admin }))
      .status,
    200,
  );
  assert.equal(
    (
      await call(`/receipts/${receipt.data.id_recebimento}`, {
        method: "DELETE",
        session: admin,
      })
    ).status,
    200,
  );
  detail = await call(`/processes/${processId}`, { session: admin });
  assert.equal(
    (
      await call(`/processes/${processId}`, {
        method: "DELETE",
        session: admin,
        body: { versao: detail.data.versao },
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await call(`/clients/${clientId}`, {
        method: "DELETE",
        session: admin,
        body: { versao: 1 },
      })
    ).status,
    200,
  );
});
test("fluxos reais, persistência, permissões, sessões e auditoria", async () => {
  assert.equal((await call("/clients")).status, 401);
  assert.equal(
    (
      await call("/login", {
        method: "POST",
        body: { email: "admin@escritorio.test", senha: password },
        origin: "http://outro.local",
      })
    ).status,
    403,
  );
  const admin = await login("admin@escritorio.test"),
    operator = await login("operador@escritorio.test");
  assert.equal((await call("/users", { session: operator })).status, 403);
  assert.equal((await call("/audit", { session: operator })).status, 403);
  assert.equal(
    (
      await call("/clients", {
        method: "POST",
        body: client,
        session: admin,
        csrf: false,
      })
    ).status,
    403,
  );
  const bad = { ...client, cpf_cnpj: "11111111111" };
  assert.equal(
    (await call("/clients", { method: "POST", body: bad, session: admin }))
      .status,
    400,
  );
  assert.equal(
    (
      await call("/clients", {
        method: "POST",
        body: { ...client, data_nascimento: "2023-02-30" },
        session: admin,
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await call("/clients", {
        method: "POST",
        body: {
          ...client,
          contatos: [
            client.contatos[0],
            { tipo: "EMAIL", valor: "outro@escritorio.test", principal: true },
          ],
        },
        session: admin,
      })
    ).status,
    400,
  );
  const created = await call("/clients", {
    method: "POST",
    body: client,
    session: operator,
  });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const cid = created.data.id_cliente;
  assert.equal(
    (await call("/clients", { method: "POST", body: client, session: admin }))
      .status,
    409,
  );
  const detail = await call("/clients/" + cid, { session: admin });
  assert.equal(detail.data.nome, client.nome);
  assert.equal(detail.data.contatos.length, 2);
  assert.equal(detail.data.enderecos.length, 1);
  assert.equal(
    (await call("/clients?q=Cliente", { session: admin })).data.total,
    1,
  );
  const logsBefore = db
    .prepare("SELECT count(*) n FROM logs_auditoria")
    .get().n;
  assert.equal(
    (
      await call("/clients/" + cid, {
        method: "PUT",
        body: { ...client, versao: 2 },
        session: operator,
      })
    ).status,
    409,
  );
  assert.equal(
    db.prepare("SELECT count(*) n FROM logs_auditoria").get().n,
    logsBefore,
  );
  assert.equal(
    (
      await call("/clients/" + cid, {
        method: "PUT",
        body: { ...client, nome: "Nome atualizado", versao: 1 },
        session: operator,
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await call("/clients/" + cid, {
        method: "PUT",
        body: { ...client, versao: 1 },
        session: admin,
      })
    ).status,
    409,
  );
  const pdf = Buffer.from(
    "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF",
  );
  const upload = new FormData();
  upload.set("titulo", "Procuração");
  upload.set("tipo_documento", "PROCURACAO");
  upload.set(
    "arquivo",
    new Blob([pdf], { type: "application/pdf" }),
    "procuracao.pdf",
  );
  const sent = await call(`/clients/${cid}/documents`, {
    method: "POST",
    body: upload,
    session: operator,
  });
  assert.equal(sent.status, 201, JSON.stringify(sent.data));
  const docId = sent.data.id_documento;
  assert.equal((await call("/documents/" + docId + "/download")).status, 401);
  const download = await call("/documents/" + docId + "/download", {
    session: operator,
  });
  assert.deepEqual(download.data, pdf);
  assert.match(
    download.response.headers.get("content-disposition"),
    /^attachment/,
  );
  const invalid = new FormData();
  invalid.set("titulo", "Arquivo inválido");
  invalid.set("tipo_documento", "OUTRO");
  invalid.set(
    "arquivo",
    new Blob(["texto"], { type: "application/pdf" }),
    "arquivo.pdf",
  );
  assert.equal(
    (
      await call(`/clients/${cid}/documents`, {
        method: "POST",
        body: invalid,
        session: admin,
      })
    ).status,
    400,
  );
  assert.equal(
    (await call("/documents/" + docId, { method: "DELETE", session: operator }))
      .status,
    403,
  );
  assert.equal(
    (
      await call("/clients/" + cid, {
        method: "DELETE",
        session: operator,
        body: { versao: 2 },
      })
    ).status,
    403,
  );
  assert.equal(
    (
      await call("/clients/" + cid, {
        method: "DELETE",
        session: admin,
        body: { versao: 2 },
      })
    ).status,
    409,
  );
  assert.equal(
    (await call("/dashboard", { session: admin })).data.documentos,
    1,
  );
  assert.equal(
    (
      await call("/users/1", {
        method: "PUT",
        session: admin,
        body: {
          nome: "Responsável",
          email: "admin@escritorio.test",
          perfil: "OPERADOR",
          ativo: true,
        },
      })
    ).status,
    400,
  );
  const newUser = await call("/users", {
    method: "POST",
    session: admin,
    body: {
      nome: "Assistente",
      email: "assistente@escritorio.test",
      perfil: "OPERADOR",
      ativo: true,
      senha: password,
    },
  });
  assert.equal(newUser.status, 201);
  const assistant = await login("assistente@escritorio.test");
  assert.equal(
    (
      await call("/users/" + newUser.data.id_usuario, {
        method: "PUT",
        session: admin,
        body: {
          nome: "Assistente",
          email: "assistente@escritorio.test",
          perfil: "OPERADOR",
          ativo: false,
        },
      })
    ).status,
    200,
  );
  assert.equal((await call("/me", { session: assistant })).status, 401);
  const raw = db
    .prepare("SELECT dados FROM clientes WHERE id_cliente=?")
    .get(cid);
  assert.equal(
    Buffer.from(raw.dados).includes(Buffer.from(client.observacoes)),
    false,
  );
  db.exec("PRAGMA wal_checkpoint(FULL)");
  assert.equal(
    readFileSync(join(dir, "advocacia.sqlite")).includes(
      Buffer.from(client.cpf_cnpj),
    ),
    false,
  );
  assert.equal(
    (await call("/documents/" + docId, { method: "DELETE", session: admin }))
      .status,
    200,
  );
  assert.equal(
    (
      await call("/clients/" + cid, {
        method: "DELETE",
        session: admin,
        body: { versao: 2 },
      })
    ).status,
    200,
  );
  assert.equal((await call("/clients/" + cid, { session: admin })).status, 404);
  const recreated = await call("/clients", {
    method: "POST",
    session: admin,
    body: client,
  });
  assert.ok(recreated.data.id_cliente > cid);
  assert.ok(
    (await call("/audit", { session: admin })).data.items.some(
      (x) => x.acao === "EXCLUSAO" && x.tabela_afetada === "clientes",
    ),
  );
  assert.equal(
    (
      await call("/password", {
        method: "POST",
        session: operator,
        body: { atual: password, nova: "Nova-senha-comprida-456" },
      })
    ).status,
    200,
  );
  assert.equal((await call("/me", { session: operator })).status, 401);
  assert.equal(
    (await call("/logout", { method: "POST", session: admin })).status,
    200,
  );
  assert.equal((await call("/me", { session: admin })).status, 401);
});
test("cargas hostis são tratadas como dados e as bordas HTTP são fechadas", async () => {
  const health = await call("/health");
  assert.equal(health.status, 200);
  assert.deepEqual(health.data, { status: "ok" });
  assert.equal(health.response.headers.get("cache-control"), "no-store");

  assert.equal(
    (
      await call("/login", {
        method: "POST",
        body: { email: "admin' OR 1=1--", senha: "qualquer" },
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await call("/login", {
        method: "POST",
        body: {
          email: "admin@escritorio.test",
          senha: "' OR '1'='1' --",
        },
      })
    ).status,
    401,
  );

  const admin = await login("admin@escritorio.test");
  const hostileName =
    '<img src=x onerror=alert(1)> {{7*7}} ${constructor.constructor("return 1")()}';
  const created = await call("/clients", {
    method: "POST",
    session: admin,
    body: {
      ...client,
      nome: hostileName,
      cpf_cnpj: "",
      observacoes: "Linha segura\n<script>alert(1)</script>",
      contatos: [],
      enderecos: [],
    },
  });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const clientId = created.data.id_cliente;
  const detail = await call(`/clients/${clientId}`, { session: admin });
  assert.equal(detail.data.nome, hostileName);
  assert.equal(detail.data.observacoes, "Linha segura\n<script>alert(1)</script>");
  assert.notEqual(detail.data.nome, "49");

  assert.equal(
    (
      await call(`/clients/${clientId}`, {
        method: "PUT",
        session: admin,
        body: {
          ...client,
          nome: hostileName,
          cpf_cnpj: "",
          contatos: [],
          enderecos: [],
        },
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await fetch(base + "/api/password", {
        method: "POST",
        headers: {
          Origin: "http://localhost:3000",
          Cookie: admin.cookie,
          "X-CSRF-Token": admin.csrf,
          "Content-Type": "text/plain",
        },
        body: "{}",
      })
    ).status,
    415,
  );
  assert.equal(
    (
      await fetch(base + "/api/login", {
        method: "POST",
        headers: {
          Origin: "http://localhost:3000",
          "Sec-Fetch-Site": "cross-site",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: "admin@escritorio.test",
          senha: password,
        }),
      })
    ).status,
    403,
  );
  assert.equal(
    (await fetch(base + "/..%2fserver%2fstore.js")).status,
    404,
  );
  assert.ok(
    [400, 404].includes(
      (await call("/clients/1%2f..%2fusers", { session: admin })).status,
    ),
  );
  assert.equal(
    (
      await call(`/clients/${clientId}`, {
        method: "DELETE",
        session: admin,
        body: { versao: 1 },
      })
    ).status,
    200,
  );
});
test("limite de login, arquivos privados e cabeçalhos", async () => {
  const authorized = await login("admin@escritorio.test");
  for (let i = 0; i < 10; i++)
    assert.equal(
      (
        await call("/login", {
          method: "POST",
          body: { email: "inexistente@escritorio.test", senha: "senha-errada" },
        })
      ).status,
      401,
    );
  assert.equal(
    (
      await call("/login", {
        method: "POST",
        body: { email: "inexistente@escritorio.test", senha: "senha-errada" },
      })
    ).status,
    429,
  );
  for (const path of [
    "/data/advocacia.sqlite",
    "/data/encryption.key",
    "/server/store.js",
    "/package.json",
    "/app.js",
  ])
    assert.equal((await fetch(base + path)).status, 404);
  assert.equal((await fetch(base + "/bootstrap.js")).status, 200);
  const anonymousSource = await fetch(base + "/assets/application.js");
  assert.equal(anonymousSource.status, 401);
  assert.equal(anonymousSource.headers.get("cache-control"), "private, no-store");
  const protectedSource = await fetch(base + "/assets/application.js", {
    headers: { Cookie: authorized.cookie },
  });
  assert.equal(protectedSource.status, 200);
  assert.equal(protectedSource.headers.get("cache-control"), "private, no-store");
  const response = await fetch(base);
  assert.equal(response.status, 200);
  assert.match(
    response.headers.get("content-security-policy"),
    /script-src 'self'/,
  );
  assert.equal(response.headers.get("strict-transport-security"), null);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("cross-origin-embedder-policy"), "require-corp");
  assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.match(response.headers.get("permissions-policy"), /camera=\(\)/);
  assert.match(response.headers.get("x-robots-tag"), /noindex/);
  assert.match(response.headers.get("ratelimit-policy"), /^600;w=300$/);
  const unsupported = await fetch(base, { method: "PATCH" });
  assert.equal(unsupported.status, 405);
});

test("migração v1 preserva contatos e amplia o esquema", () => {
  const legacyDir = join(dir, "legacy-v1");
  mkdirSync(legacyDir, { mode: 0o700 });
  writeFileSync(join(legacyDir, "encryption.key"), randomBytes(32), {
    mode: 0o600,
  });
  const legacy = new DatabaseSync(join(legacyDir, "advocacia.sqlite"));
  legacy.exec(`
    PRAGMA foreign_keys=ON;
    CREATE TABLE clientes(id_cliente INTEGER PRIMARY KEY AUTOINCREMENT,dados BLOB NOT NULL,documento_indice TEXT UNIQUE,ativo INTEGER NOT NULL DEFAULT 1,versao INTEGER NOT NULL DEFAULT 1,data_cadastro TEXT DEFAULT CURRENT_TIMESTAMP,data_atualizacao TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE contatos(id_contato INTEGER PRIMARY KEY AUTOINCREMENT,id_cliente INTEGER NOT NULL REFERENCES clientes ON DELETE RESTRICT,tipo TEXT NOT NULL CHECK(tipo IN('TELEFONE','EMAIL')),dados BLOB NOT NULL,valor_indice TEXT NOT NULL,principal INTEGER NOT NULL CHECK(principal IN(0,1)),UNIQUE(id_cliente,tipo,valor_indice));
    CREATE UNIQUE INDEX contato_principal ON contatos(id_cliente,tipo) WHERE principal=1;
    INSERT INTO clientes(dados) VALUES(X'01');
    INSERT INTO contatos(id_cliente,tipo,dados,valor_indice,principal) VALUES(1,'EMAIL',X'02','indice-legado',1);
    PRAGMA user_version=1;
  `);
  legacy.close();
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      'const s=await import("./server/store.js"); s.db.close();',
    ],
    { env: { ...process.env, DATA_DIR: legacyDir } },
  );
  const migrated = new DatabaseSync(join(legacyDir, "advocacia.sqlite"), {
    readOnly: true,
  });
  try {
    assert.equal(migrated.prepare("PRAGMA user_version").get().user_version, 4);
    assert.equal(migrated.prepare("SELECT count(*) n FROM contatos").get().n, 1);
    assert.match(
      migrated
        .prepare("SELECT sql FROM sqlite_master WHERE name='contatos'")
        .get().sql,
      /WHATSAPP/,
    );
    assert.ok(
      migrated
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type='table' AND name='refresh_tokens_usados'",
        )
        .get(),
    );
    assert.ok(
      migrated
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='processos'")
        .get(),
    );
    assert.ok(
      migrated
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='desafios_mfa'")
        .get(),
    );
  } finally {
    migrated.close();
  }
});

test("backup consistente preserva o banco e a chave para restauração", () => {
  const dest = join(dir, "backup");
  execFileSync(process.execPath, ["scripts/backup.js", dest], {
    env: { ...process.env, DATA_DIR: dir },
  });
  assert.deepEqual(
    readFileSync(join(dest, "encryption.key")),
    readFileSync(join(dir, "encryption.key")),
  );
  const restored = new DatabaseSync(join(dest, "advocacia.sqlite"), {
    readOnly: true,
  });
  try {
    assert.equal(
      restored.prepare("PRAGMA integrity_check").get().integrity_check,
      "ok",
    );
    assert.equal(
      restored.prepare("SELECT count(*) n FROM clientes").get().n,
      db.prepare("SELECT count(*) n FROM clientes").get().n,
    );
    assert.deepEqual(
      restored.prepare("SELECT dados FROM clientes").get().dados,
      db.prepare("SELECT dados FROM clientes").get().dados,
    );
  } finally {
    restored.close();
  }
});
