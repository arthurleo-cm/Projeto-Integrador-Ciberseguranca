import { backup } from "node:sqlite";
import { mkdirSync, copyFileSync, chmodSync } from "node:fs";
import { resolve } from "node:path";
process.umask(0o077);
const destination = process.argv[2];
if (!destination)
  throw new Error("Uso: npm run backup -- /caminho/novo/do/backup");
const { db, dataDir } = await import("../server/store.js");
try {
  const target = resolve(destination);
  mkdirSync(target, { mode: 0o700 });
  await backup(db, resolve(target, "advocacia.sqlite"));
  chmodSync(resolve(target, "advocacia.sqlite"), 0o600);
  copyFileSync(
    resolve(dataDir, "encryption.key"),
    resolve(target, "encryption.key"),
  );
  chmodSync(resolve(target, "encryption.key"), 0o600);
  console.log(
    "Backup concluído em " +
      target +
      ". Proteja a pasta, pois ela contém a chave de recuperação.",
  );
} finally {
  db.close();
}
