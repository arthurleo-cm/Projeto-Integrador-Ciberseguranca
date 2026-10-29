import { readFile } from "node:fs/promises";
import { isIP } from "node:net";

const domain = process.env.DNS_DOMAIN || "marquezi.com";
const host = process.env.DNS_HOST || "gestao";
const credentialsFile =
  process.env.CREDENTIALS_FILE || "/home/malingus/Projects/credenciais.txt";

const raw = await readFile(credentialsFile, "utf8");
const field = (label) =>
  raw.match(new RegExp(`^${label}\\s*:\\s*(.+)$`, "im"))?.[1]?.trim();
const username = process.env.NAMECOM_USERNAME || field("Usuário Name\\.com") || field("E-mail");
const token = process.env.NAMECOM_API_TOKEN || field("Token API");

if (!username || !token) {
  console.error(
    "Informe Usuário Name.com e Token API no arquivo de credenciais, ou use NAMECOM_USERNAME e NAMECOM_API_TOKEN.",
  );
  process.exit(1);
}

const timeout = () => AbortSignal.timeout(15_000);
const publicIp =
  process.env.PUBLIC_IPV4 ||
  (await (await fetch("https://api.ipify.org", { signal: timeout() })).text()).trim();
if (isIP(publicIp) !== 4) throw new Error("Não foi possível detectar um IPv4 público válido.");

const authorization = `Basic ${Buffer.from(`${username}:${token}`).toString("base64")}`;
const endpoint = `https://api.name.com/v4/domains/${encodeURIComponent(domain)}/records`;
const headers = { Authorization: authorization, Accept: "application/json" };
const listed = await fetch(endpoint, { headers, signal: timeout() });
if (!listed.ok) {
  console.error(
    `A API da Name.com recusou a consulta (HTTP ${listed.status}). Confira o token e a liberação de API com 2FA.`,
  );
  process.exit(1);
}

const records = (await listed.json()).records || [];
const sameHost = records.filter(
  (record) =>
    String(record.host || "").toLowerCase() === host.toLowerCase() ||
    String(record.fqdn || "").replace(/\.$/, "").toLowerCase() ===
      `${host}.${domain}`.toLowerCase(),
);
const expected = sameHost.find(
  (record) => record.type === "A" && record.answer === publicIp,
);
if (expected) {
  console.log(`${host}.${domain} já aponta para o IPv4 público atual; nenhuma alteração foi feita.`);
  process.exit(0);
}
if (sameHost.length) {
  console.error(
    `${host}.${domain} já possui um registro diferente. Por segurança, nenhuma alteração foi feita.`,
  );
  process.exit(1);
}

const created = await fetch(endpoint, {
  method: "POST",
  headers: { ...headers, "Content-Type": "application/json" },
  body: JSON.stringify({ host, type: "A", answer: publicIp, ttl: 300 }),
  signal: timeout(),
});
if (!created.ok) {
  console.error(`A criação do registro DNS falhou (HTTP ${created.status}).`);
  process.exit(1);
}
console.log(`${host}.${domain} foi configurado para o IPv4 público atual (TTL 300).`);
