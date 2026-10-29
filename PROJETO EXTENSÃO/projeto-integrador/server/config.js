import { existsSync } from "node:fs";
import { resolve } from "node:path";

const integer = (name, fallback, { min, max }) => {
  const raw = process.env[name] || String(fallback);
  if (!/^\d+$/.test(raw))
    throw new Error(`${name} deve ser um número inteiro.`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`${name} deve estar entre ${min} e ${max}.`);
  return value;
};

export const port = integer("PORT", 3000, { min: 1, max: 65535 });
export const host = process.env.HOST || "127.0.0.1";
export const sessionHours = integer("SESSION_HOURS", 8, {
  min: 1,
  max: 24,
});
export const accessTokenMinutes = integer("ACCESS_TOKEN_MINUTES", 15, {
  min: 5,
  max: 30,
});

const dataDirectory = resolve(process.env.DATA_DIR || "data");
export const tlsCertificateFile = resolve(
  process.env.TLS_CERT_FILE || `${dataDirectory}/tls/localhost-cert.pem`,
);
export const tlsPrivateKeyFile = resolve(
  process.env.TLS_KEY_FILE || `${dataDirectory}/tls/localhost-key.pem`,
);
const certificateExists = existsSync(tlsCertificateFile);
const privateKeyExists = existsSync(tlsPrivateKeyFile);
if (certificateExists !== privateKeyExists)
  throw new Error(
    "TLS incompleto: certificado e chave privada devem existir juntos.",
  );
const tlsMode = process.env.TLS_MODE || "auto";
if (!["auto", "on", "off"].includes(tlsMode))
  throw new Error("TLS_MODE deve ser auto, on ou off.");
if (tlsMode === "on" && !certificateExists)
  throw new Error("TLS_MODE=on exige um certificado e uma chave privada.");
export const directTls =
  tlsMode === "on" || (tlsMode === "auto" && certificateExists);

const rawOrigin =
  process.env.APP_ORIGIN ||
  `${directTls ? "https" : "http"}://localhost:${port}`;
let parsedOrigin;
try {
  parsedOrigin = new URL(rawOrigin);
} catch {
  throw new Error("APP_ORIGIN deve ser uma URL HTTP ou HTTPS válida.");
}
if (
  !["http:", "https:"].includes(parsedOrigin.protocol) ||
  parsedOrigin.username ||
  parsedOrigin.password ||
  parsedOrigin.pathname !== "/" ||
  parsedOrigin.search ||
  parsedOrigin.hash ||
  parsedOrigin.origin !== rawOrigin
)
  throw new Error(
    "APP_ORIGIN deve conter apenas a origem exata, sem credenciais, caminho, consulta ou barra final.",
  );

export const origin = parsedOrigin.origin;
export const secure = parsedOrigin.protocol === "https:";
export const expectedHost = parsedOrigin.host.toLowerCase();

if (directTls && !secure)
  throw new Error("APP_ORIGIN deve usar HTTPS quando o TLS local está ativo.");

if (process.env.NODE_ENV === "production" && !secure)
  throw new Error("Em produção, APP_ORIGIN deve usar HTTPS.");

const trustProxy = process.env.TRUST_PROXY;
if (trustProxy && !/^\d+$/.test(trustProxy))
  throw new Error(
    "TRUST_PROXY deve ser um número de proxies confiáveis (por exemplo, 1).",
  );
export const trustedProxyHops = trustProxy ? Number(trustProxy) : 0;

if (directTls && trustedProxyHops)
  throw new Error(
    "Não combine TLS direto com TRUST_PROXY; termine o TLS no Node ou no proxy.",
  );

export const mfaMode =
  process.env.MFA_MODE ||
  (process.env.NODE_ENV === "production" ? "smtp" : "console");
if (!["smtp", "console", "test"].includes(mfaMode))
  throw new Error("MFA_MODE deve ser smtp, console ou test.");
if (process.env.NODE_ENV === "production" && mfaMode !== "smtp")
  throw new Error("Em produção, MFA_MODE deve ser smtp.");

const smtpInteger = (name, fallback, min, max) =>
  integer(name, fallback, { min, max });
export const smtp =
  mfaMode === "smtp"
    ? {
        host: process.env.SMTP_HOST || "",
        port: smtpInteger("SMTP_PORT", 587, 1, 65535),
        user: process.env.SMTP_USER || "",
        pass: process.env.SMTP_PASS || "",
        from: (process.env.SMTP_FROM || process.env.SMTP_USER || "").toLowerCase(),
      }
    : null;
if (
  smtp &&
  (!/^[a-zA-Z0-9.-]+$/.test(smtp.host) ||
    !smtp.user ||
    !smtp.pass ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(smtp.from) ||
    [smtp.user, smtp.pass].some((value) => /[\r\n\0]/.test(value)))
)
  throw new Error(
    "Configure SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS e SMTP_FROM corretamente.",
  );
