import { test, expect } from "@playwright/test";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
let server, db, dir, base;
test.beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "advocacia-ui-"));
  process.env.DATA_DIR = dir;
  process.env.MFA_MODE = "test";
  writeFileSync(join(dir, "encryption.key"), randomBytes(32), { mode: 0o600 });
  server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  process.env.APP_ORIGIN = base;
  const store = await import("../../server/store.js");
  db = store.db;
  db.prepare(
    "INSERT INTO usuarios(dados,email_indice,senha_hash,perfil) VALUES(?,?,?,?)",
  ).run(
    store.pack(
      { nome: "Responsável", email: "admin@escritorio.test" },
      "usuario",
    ),
    store.index("admin@escritorio.test"),
    await store.hashPassword("Senha-privada-para-teste"),
    "ADMINISTRADOR",
  );
  const { app } = await import("../../server/app.js");
  server.on("request", app);
});
test.afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.close();
  rmSync(dir, { recursive: true, force: true });
});
test("login, cliente, contatos, endereço, documento e equipe no navegador", async ({
  page,
}, testInfo) => {
  test.setTimeout(60_000);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(base);
  await page
    .getByRole("textbox", { name: "E-mail", exact: true })
    .fill("admin@escritorio.test");
  await page
    .getByLabel("Senha", { exact: true })
    .fill("Senha-privada-para-teste");
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  await expect(page.getByLabel("Código de 6 dígitos")).toBeVisible();
  const { takeLatestTestMfaCode } = await import("../../server/mailer.js");
  const mfaCode = takeLatestTestMfaCode("admin@escritorio.test");
  expect(mfaCode).toMatch(/^\d{6}$/);
  await page.getByLabel("Código de 6 dígitos").fill(mfaCode);
  await page.getByRole("button", { name: "Confirmar código" }).click();
  await expect(
    page.getByText("Clientes cadastrados", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Abrir clientes", exact: true })
    .click();
  await page
    .getByRole("button", { name: "+ Novo cliente", exact: true })
    .click();
  await page.getByLabel("Nome completo").fill("Cliente <script>texto</script>");
  await page.getByLabel("CPF", { exact: true }).fill("52998224725");
  await expect(page.getByLabel("CPF", { exact: true })).toHaveValue(
    "529.982.247-25",
  );
  await page.getByRole("button", { name: "+ Adicionar contato" }).click();
  await page.locator(".contact-row select").selectOption("EMAIL");
  await page
    .locator(".contact-row input[name=valor]")
    .fill("cliente@escritorio.test");
  await page.getByLabel("Principal deste tipo").check();
  await page.getByRole("button", { name: "+ Adicionar endereço" }).click();
  await page.getByLabel("Logradouro").fill("Rua Central");
  await page.getByLabel("Número", { exact: true }).fill("123");
  await page.getByLabel("Cidade", { exact: true }).fill("Campinas");
  await page.getByLabel("Endereço principal").check();
  await page
    .getByRole("button", { name: "Salvar cadastro", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Cadastro do cliente" }),
  ).toBeVisible();
  await expect(page.getByLabel("Nome completo")).toHaveValue(
    "Cliente <script>texto</script>",
  );
  await expect(page.locator(".contact-row input[name=valor]")).toHaveValue(
    "cliente@escritorio.test",
  );
  await page.getByLabel("Título", { exact: true }).fill("Documento cadastrado");
  await page
    .getByLabel("Arquivo", { exact: true })
    .setInputFiles({
      name: "arquivo.pdf",
      mimeType: "application/pdf",
      buffer: Buffer.from(
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF",
      ),
    });
  await page.getByRole("button", { name: "Enviar documento" }).click();
  await expect(
    page.getByText("Documento cadastrado", { exact: true }),
  ).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: "Baixar" }).click();
  expect((await downloadPromise).suggestedFilename()).toMatch(
    /documento-\d+\.pdf/,
  );
  await page.screenshot({
    path: testInfo.outputPath("cliente-desktop.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Voltar", exact: true }).click();
  await expect(
    page.getByRole("cell", {
      name: "Cliente <script>texto</script> Pessoa física",
      exact: true,
    }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByText("Clientes cadastrados", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Processos", exact: true }).click();
  await page.getByRole("button", { name: "+ Novo processo" }).click();
  await page
    .getByLabel("Número oficial CNJ")
    .fill("02000436520092000000");
  await expect(page.getByLabel("Número oficial CNJ")).toHaveValue(
    "0200043-65.2009.2.00.0000",
  );
  await page.getByLabel("Título ou resumo").fill("Cobrança contratual");
  await page.getByLabel("Valor estimado (R$)").fill("2500");
  await page.getByRole("button", { name: "Salvar processo" }).click();
  await expect(page.getByRole("heading", { name: /Processo #/ })).toBeVisible();
  await page.getByLabel("Valor recebido (R$)").fill("500");
  await page.getByLabel("Observação").fill("Entrada inicial");
  await page.getByRole("button", { name: "Registrar recebimento" }).click();
  await expect(page.getByText(/R\$\s*500,00/).first()).toBeVisible();
  await page.getByLabel("Título", { exact: true }).fill("Contrato do processo");
  await page
    .getByLabel("Arquivo", { exact: true })
    .setInputFiles({
      name: "contrato.pdf",
      mimeType: "application/pdf",
      buffer: Buffer.from(
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF",
      ),
    });
  await page.getByRole("button", { name: "Enviar anexo" }).click();
  await expect(page.getByText("Contrato do processo", { exact: true })).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("processo-desktop.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Processos", exact: true }).click();
  await page
    .getByLabel("Busca por ID, número CNJ, título ou cliente")
    .fill("Cobrança contratual");
  await page.getByRole("button", { name: "Buscar", exact: true }).click();
  await expect(page.getByText("Cobrança contratual", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Minha conta", exact: true }).click();
  await page.locator('select[name="tema"]').selectOption("ESCURO");
  await page.locator('select[name="fonte"]').selectOption("GRANDE");
  await page.getByLabel("Ativar alto contraste").check();
  await page.getByRole("button", { name: "Salvar preferências" }).click();
  await expect(page.locator("html")).toHaveClass(/theme-dark/);
  await expect(page.locator("html")).toHaveClass(/font-large/);
  await expect(page.locator("html")).toHaveClass(/high-contrast/);
  await page.getByRole("button", { name: "Usuários", exact: true }).click();
  await page.getByRole("button", { name: "+ Novo usuário" }).click();
  await page.getByLabel("Nome", { exact: true }).fill("Equipe");
  await page
    .getByRole("textbox", { name: "E-mail", exact: true })
    .fill("equipe@escritorio.test");
  await page.getByLabel("Senha inicial").fill("Senha-privada-da-equipe");
  await page.getByRole("button", { name: "Salvar usuário" }).click();
  await expect(
    page.getByText("equipe@escritorio.test", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Auditoria", exact: true }).click();
  await expect(page.getByRole("columnheader", { name: "Ação" })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Clientes", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Base de clientes" })).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("clientes-mobile.png"),
    fullPage: true,
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Sair", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Entrar", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("textbox", { name: "E-mail", exact: true })
    .fill("equipe@escritorio.test");
  await page
    .getByLabel("Senha", { exact: true })
    .fill("Senha-privada-da-equipe");
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  await expect(page.getByLabel("Código de 6 dígitos")).toBeVisible();
  const operatorMfaCode = takeLatestTestMfaCode("equipe@escritorio.test");
  expect(operatorMfaCode).toMatch(/^\d{6}$/);
  await page.getByLabel("Código de 6 dígitos").fill(operatorMfaCode);
  await page.getByRole("button", { name: "Confirmar código" }).click();
  await expect(
    page.getByText("Clientes cadastrados", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Usuários", exact: true }),
  ).toBeHidden();
  await page.getByRole("button", { name: "Processos", exact: true }).click();
  await page.getByRole("button", { name: "Abrir", exact: true }).click();
  await expect(page.getByText("Informações financeiras são restritas")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Financeiro" })).toBeHidden();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: testInfo.outputPath("processo-mobile.png"),
    fullPage: true,
  });
  expect(errors).toEqual([]);
});
