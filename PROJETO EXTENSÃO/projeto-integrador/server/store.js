import { DatabaseSync } from "node:sqlite";
import { mkdirSync, readFileSync, chmodSync, statSync } from "node:fs";
import { resolve } from "node:path";
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHmac,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
const scrypt = promisify(scryptCallback);
export const dataDir = resolve(process.env.DATA_DIR || "data");
mkdirSync(dataDir, { recursive: true, mode: 0o700 });
chmodSync(dataDir, 0o700);
const keyPath = resolve(dataDir, "encryption.key");
if (!statSync(keyPath).isFile())
  throw new Error("A chave de cifragem deve ser um arquivo regular.");
chmodSync(keyPath, 0o600);
const key = readFileSync(keyPath);
if (key.length !== 32) throw new Error("Chave de cifragem inválida.");
export function encrypt(value, context) {
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(context));
  const data = Buffer.concat([
    cipher.update(Buffer.from(value)),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]);
}
export function decrypt(value, context) {
  const b = Buffer.from(value),
    minimum = 29;
  if (b.length < minimum) throw new Error("Conteúdo cifrado inválido.");
  const decipher = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12));
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([decipher.update(b.subarray(28)), decipher.final()]);
}
export const pack = (value, context) => encrypt(JSON.stringify(value), context);
export const unpack = (value, context) => JSON.parse(decrypt(value, context));
export const index = (value) =>
  createHmac("sha256", key)
    .update("lookup:" + value)
    .digest("hex");
export async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = await scrypt(password, salt, 64, {
    N: 32768,
    r: 8,
    p: 3,
    maxmem: 64 * 1024 * 1024,
  });
  return `scrypt:32768:8:3:${salt}:${hash.toString("hex")}`;
}
export async function verifyPassword(password, stored) {
  const [algorithm, n, r, p, salt, hash] = stored.split(":");
  if (
    algorithm !== "scrypt" ||
    n !== "32768" ||
    r !== "8" ||
    p !== "3" ||
    !/^[a-f0-9]{32}$/.test(salt) ||
    !/^[a-f0-9]{128}$/.test(hash)
  )
    return false;
  const actual = await scrypt(password, salt, 64, {
    N: 32768,
    r: 8,
    p: 3,
    maxmem: 64 * 1024 * 1024,
  });
  return timingSafeEqual(actual, Buffer.from(hash, "hex"));
}
export const db = new DatabaseSync(resolve(dataDir, "advocacia.sqlite"));
chmodSync(resolve(dataDir, "advocacia.sqlite"), 0o600);
const schemaVersion = db.prepare("PRAGMA user_version").get().user_version;
db.exec(
  readFileSync(
    new URL("../database/schema.sqlite.sql", import.meta.url),
    "utf8",
  ),
);
if (schemaVersion > 4)
  throw new Error("O banco foi criado por uma versão mais recente da aplicação.");
let migratedVersion = schemaVersion;
if (schemaVersion === 1) {
  db.exec(`
    BEGIN IMMEDIATE;
    DROP INDEX IF EXISTS contato_principal;
    ALTER TABLE contatos RENAME TO contatos_legado_v1;
    CREATE TABLE contatos(
      id_contato INTEGER PRIMARY KEY AUTOINCREMENT,
      id_cliente INTEGER NOT NULL REFERENCES clientes ON DELETE RESTRICT,
      tipo TEXT NOT NULL CHECK(tipo IN('TELEFONE','WHATSAPP','EMAIL','INSTAGRAM','LINKEDIN','FACEBOOK','SITE','OUTRO')),
      dados BLOB NOT NULL,
      valor_indice TEXT NOT NULL,
      principal INTEGER NOT NULL CHECK(principal IN(0,1)),
      UNIQUE(id_cliente,tipo,valor_indice)
    );
    INSERT INTO contatos(id_contato,id_cliente,tipo,dados,valor_indice,principal)
      SELECT id_contato,id_cliente,tipo,dados,valor_indice,principal
      FROM contatos_legado_v1;
    DROP TABLE contatos_legado_v1;
    CREATE UNIQUE INDEX contato_principal ON contatos(id_cliente,tipo)
      WHERE principal=1;
    PRAGMA user_version=2;
    COMMIT;
  `);
  migratedVersion = 2;
} else if (schemaVersion === 0) {
  db.exec("PRAGMA user_version=4;");
  migratedVersion = 4;
}
if (migratedVersion === 2) {
  db.exec(`
    BEGIN IMMEDIATE;
    CREATE TABLE IF NOT EXISTS desafios_mfa(
      token_hash TEXT PRIMARY KEY,
      id_usuario INTEGER NOT NULL REFERENCES usuarios ON DELETE CASCADE,
      codigo_hash TEXT NOT NULL,
      ip_indice TEXT NOT NULL,
      senha_indice TEXT NOT NULL,
      tentativas INTEGER NOT NULL DEFAULT 0 CHECK(tentativas BETWEEN 0 AND 5),
      proximo_envio INTEGER NOT NULL,
      expira INTEGER NOT NULL,
      criado INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS desafios_mfa_usuario ON desafios_mfa(id_usuario);
    CREATE INDEX IF NOT EXISTS desafios_mfa_expira ON desafios_mfa(expira);
    PRAGMA user_version=3;
    COMMIT;
  `);
  migratedVersion = 3;
}
if (migratedVersion === 3) {
  db.exec(`
    BEGIN IMMEDIATE;
    DROP TABLE IF EXISTS sessoes;
    CREATE TABLE sessoes(
      id_sessao TEXT PRIMARY KEY,
      id_usuario INTEGER NOT NULL REFERENCES usuarios ON DELETE CASCADE,
      refresh_hash TEXT UNIQUE NOT NULL,
      csrf TEXT NOT NULL,
      expira INTEGER NOT NULL,
      criado INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS refresh_tokens_usados(
      token_hash TEXT PRIMARY KEY,
      id_sessao TEXT NOT NULL,
      id_usuario INTEGER NOT NULL,
      expira INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessoes_usuario ON sessoes(id_usuario);
    CREATE INDEX IF NOT EXISTS sessoes_expira ON sessoes(expira);
    CREATE INDEX IF NOT EXISTS refresh_tokens_usados_expira
      ON refresh_tokens_usados(expira);
    PRAGMA user_version=4;
    COMMIT;
  `);
}
db.exec("PRAGMA trusted_schema=OFF; PRAGMA secure_delete=ON;");
export function transaction(fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const v = fn();
    db.exec("COMMIT");
    return v;
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}
export function audit(user, action, table, id) {
  db.prepare(
    "INSERT INTO logs_auditoria(id_usuario,acao,tabela_afetada,id_registro) VALUES(?,?,?,?)",
  ).run(user, action, table, id);
}
export function publicUser(row) {
  const data = unpack(row.dados, "usuario");
  return {
    id_usuario: row.id_usuario,
    nome: data.nome,
    email: data.email,
    preferencias: data.preferencias || {
      tema: "SISTEMA",
      fonte: "NORMAL",
      alto_contraste: false,
    },
    perfil: row.perfil,
    ativo: !!row.ativo,
  };
}
