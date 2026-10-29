import {
  chmodSync,
  existsSync,
  mkdirSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { createInterface } from "node:readline/promises";

process.umask(0o077);

if (!process.stdin.isTTY)
  throw new Error(
    "Execute a configuração SMTP em um terminal interativo para manter a senha de app oculta.",
  );

const dataDirectory = resolve(process.env.DATA_DIR || "data");
const environmentFile = resolve(dataDirectory, "smtp.env");
const replace = process.argv.includes("--replace");

if (existsSync(environmentFile) && !replace)
  throw new Error(
    "A configuração SMTP já existe. Use npm run setup:smtp -- --replace para substituí-la.",
  );

mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
chmodSync(dataDirectory, 0o700);

const rl = createInterface({ input: process.stdin, output: process.stdout });

const hidden = async (prompt) => {
  process.stdout.write(prompt);
  rl.close();
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolveValue, reject) => {
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
          resolveValue(value);
          return;
        }
        if (char === "\u007f") value = value.slice(0, -1);
        else if (char >= " ") value += char;
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

try {
  const email = (await rl.question("Conta Gmail remetente: ")).trim().toLowerCase();
  if (!/^[^\s@]+@gmail\.com$/.test(email))
    throw new Error("Informe um endereço @gmail.com válido.");

  const appPassword = (await hidden("Senha de app do Google (entrada oculta): "))
    .replace(/\s/g, "");
  if (!/^[A-Za-z0-9]{16}$/.test(appPassword))
    throw new Error("A senha de app do Google deve ter 16 caracteres.");

  const temporaryFile = `${environmentFile}.${randomBytes(8).toString("hex")}.tmp`;
  writeFileSync(
    temporaryFile,
    [
      "MFA_MODE=smtp",
      "SMTP_HOST=smtp.gmail.com",
      "SMTP_PORT=465",
      `SMTP_USER=${email}`,
      `SMTP_PASS=${appPassword}`,
      `SMTP_FROM=${email}`,
      "",
    ].join("\n"),
    { mode: 0o600, flag: "wx" },
  );
  renameSync(temporaryFile, environmentFile);
  chmodSync(environmentFile, 0o600);
  console.log(`SMTP configurado em ${environmentFile}.`);
  console.log("Execute npm start; o servidor validará a conexão antes de iniciar.");
} finally {
  rl.close();
}
