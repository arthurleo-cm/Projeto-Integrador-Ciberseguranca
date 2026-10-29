import { mkdirSync, existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { createInterface } from "node:readline/promises";
process.umask(0o077);
const dir = resolve(process.env.DATA_DIR || "data");
mkdirSync(dir, { recursive: true, mode: 0o700 });
if (!existsSync(resolve(dir, "encryption.key"))) {
  if (existsSync(resolve(dir, "advocacia.sqlite")))
    throw new Error("Banco existente sem chave. Restaure a chave original.");
  writeFileSync(resolve(dir, "encryption.key"), randomBytes(32), {
    mode: 0o600,
    flag: "wx",
  });
}
const { db, pack, index, hashPassword, transaction, audit } = await import(
  "../server/store.js"
);
const { userSchema } = await import("../server/validation.js");
if (db.prepare("SELECT count(*) n FROM usuarios").get().n) {
  console.log("Banco inicializado. As contas existentes foram preservadas.");
  process.exit(0);
}
if (!process.stdin.isTTY) throw new Error("Execute o setup em um terminal interativo para cadastrar a senha com entrada oculta.");
const rl = createInterface({ input: process.stdin, output: process.stdout });
try {
  const nome = await rl.question("Nome do administrador: "),
    email = await rl.question("E-mail do administrador (login e MFA): ");
  // Hidden input on terminals; do not accept passwords through process arguments.
  const hidden = async (prompt) => {
    process.stdout.write(prompt);
    rl.close();
    process.stdin.setRawMode(true);
    process.stdin.resume();
    return new Promise((resolve, reject) => {
      let value = "";
      const onData = (chunk) => {
        for (const char of chunk.toString()) {
          if (char === "\u0003") {
            cleanup();
            reject(new Error("Cancelado"));
            return;
          }
          if (char === "\r" || char === "\n") {
            cleanup();
            resolve(value);
            return;
          }
          if (char === "\u007f") {
            value = value.slice(0, -1);
          } else if (char >= " ") value += char;
        }
      };
      const cleanup = () => {
        process.stdin.off("data", onData);
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdout.write("\n");
      };
      process.stdin.on("data", onData);
    });
  };
  const senha = await hidden("Senha (mínimo 12 caracteres; entrada oculta): ");
  const confirmacao = await hidden("Confirme a senha: ");
  if (senha !== confirmacao) throw new Error("As senhas não correspondem. Execute o setup novamente.");
  const user = userSchema.parse({
    nome,
    email,
    senha,
    perfil: "ADMINISTRADOR",
    ativo: true,
  });
  const hash = await hashPassword(user.senha);
  transaction(() => {
    const row = db
      .prepare(
        "INSERT INTO usuarios(dados,email_indice,senha_hash,perfil) VALUES(?,?,?,?)",
      )
      .run(
        pack(
          {
            nome: user.nome,
            email: user.email,
          },
          "usuario",
        ),
        index(user.email),
        hash,
        user.perfil,
      );
    audit(
      Number(row.lastInsertRowid),
      "CADASTRO",
      "usuarios",
      Number(row.lastInsertRowid),
    );
  });
  console.log("Administrador criado. Inicie com npm start.");
} finally {
  rl.close();
  db.close();
}
