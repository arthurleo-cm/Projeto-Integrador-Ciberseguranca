import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import {
  directTls,
  host,
  origin,
  port,
  tlsCertificateFile,
  tlsPrivateKeyFile,
} from "./config.js";
process.umask(0o077);
if (!existsSync(resolve(process.env.DATA_DIR || "data", "encryption.key"))) {
  console.error("Execute npm run setup para criar o banco e o administrador.");
  process.exit(1);
}
const { app } = await import("./app.js");
const { db } = await import("./store.js");
const { verifyMailer } = await import("./mailer.js");
if (
  !db
    .prepare(
      "SELECT count(*) n FROM usuarios WHERE ativo=1 AND perfil='ADMINISTRADOR'",
    )
    .get().n
) {
  console.error("Cadastre ao menos um administrador ativo antes de iniciar.");
  db.close();
  process.exit(1);
}
try {
  await verifyMailer();
} catch (error) {
  const reason = error.code || error.message;
  if (process.env.NODE_ENV === "production") {
    console.error("Não foi possível validar o servidor SMTP:", reason);
    db.close();
    process.exit(1);
  }
  console.warn(
    `Aviso: o SMTP está indisponível (${reason}). ` +
      "O servidor local continuará ativo, mas o login que solicitar um novo " +
      "código MFA retornará indisponível até a conexão SMTP voltar. " +
      "Nenhum código será exibido no terminal.",
  );
}
if (directTls && process.platform !== "win32") {
  const permissions = statSync(tlsPrivateKeyFile).mode & 0o077;
  if (permissions)
    throw new Error(
      "A chave privada TLS não pode ter permissões para grupo ou outros usuários.",
    );
}
const server = directTls
  ? createHttpsServer(
      {
        cert: readFileSync(tlsCertificateFile),
        key: readFileSync(tlsPrivateKeyFile),
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3",
      },
      app,
    )
  : createHttpServer(app);
server.requestTimeout = 30_000;
server.headersTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 1_000;
server.on("error", (error) => {
  console.error("Não foi possível iniciar o servidor:", error.message);
  if (!server.listening) {
    db.close();
    process.exit(1);
  }
});
server.listen(port, host, () => console.log(`Marquezi disponível em ${origin}`));

let stopping = false;
const shutdown = (signal) => {
  if (stopping) return;
  stopping = true;
  console.log(`${signal} recebido; encerrando conexões.`);
  const deadline = setTimeout(() => {
    server.closeAllConnections();
    process.exit(1);
  }, 10_000);
  deadline.unref();
  server.close(() => {
    clearTimeout(deadline);
    db.close();
    process.exit(0);
  });
};
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
