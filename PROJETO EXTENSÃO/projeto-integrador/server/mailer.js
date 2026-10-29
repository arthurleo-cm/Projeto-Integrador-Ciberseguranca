import nodemailer from "nodemailer";
import { mfaMode, smtp } from "./config.js";
import { resolvePublicHost } from "./network-security.js";

const testCodes = new Map();
const testCodesByRecipient = new Map();
let transporter = null;

function discardTransporter(activeTransporter) {
  if (transporter === activeTransporter) transporter = null;
  activeTransporter?.close?.();
}

function createSmtpTransporter(address) {
  return nodemailer.createTransport({
    pool: true,
    maxConnections: 2,
    maxMessages: 100,
    host: address,
    port: smtp.port,
    secure: smtp.port === 465,
    requireTLS: smtp.port !== 465,
    auth: { user: smtp.user, pass: smtp.pass },
    tls: {
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
      servername: smtp.host,
    },
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 15_000,
    disableFileAccess: true,
    disableUrlAccess: true,
  });
}

const retryableConnectionError = (error) =>
  (!error.command || error.command === "CONN") &&
  [
    "ESOCKET",
    "ETIMEDOUT",
    "ECONNREFUSED",
    "ECONNRESET",
    "ENETUNREACH",
    "EHOSTUNREACH",
  ].includes(error.code);

async function useSmtp(operation) {
  if (mfaMode !== "smtp") return null;
  if (transporter) {
    try {
      return await operation(transporter);
    } catch (error) {
      discardTransporter(transporter);
      if (!retryableConnectionError(error)) throw error;
    }
  }

  const target = await resolvePublicHost(smtp.host);
  let lastError;
  for (const { address } of target.addresses) {
    const candidate = createSmtpTransporter(address);
    try {
      const result = await operation(candidate);
      transporter = candidate;
      return result;
    } catch (error) {
      discardTransporter(candidate);
      lastError = error;
      if (!retryableConnectionError(error)) throw error;
    }
  }
  throw lastError || new Error("Nenhum endereço SMTP público disponível.");
}

export async function verifyMailer() {
  await useSmtp((activeTransporter) => activeTransporter.verify());
}

export async function sendMfaCode({ to, code, challenge }) {
  if (mfaMode === "test") {
    testCodes.set(challenge, code);
    testCodesByRecipient.set(to, code);
    return;
  }
  if (mfaMode === "console") {
    console.log(`[MFA desenvolvimento] ${to}: ${code}`);
    return;
  }
  await useSmtp((activeTransporter) =>
    activeTransporter.sendMail({
      from: { name: "Marquezi Gestão", address: smtp.from },
      envelope: { from: smtp.from, to: [to] },
      to,
      subject: "Código de acesso — Marquezi Gestão",
      text:
        `Seu código de acesso é ${code}.\n\n` +
        "Ele expira em 10 minutos e só pode ser usado uma vez. " +
        "Se você não tentou entrar, ignore esta mensagem e avise o administrador.",
      disableFileAccess: true,
      disableUrlAccess: true,
    }),
  );
}

export function takeTestMfaCode(challenge) {
  if (mfaMode !== "test") throw new Error("Disponível somente em testes.");
  const code = testCodes.get(challenge);
  testCodes.delete(challenge);
  return code;
}

export function takeLatestTestMfaCode(recipient) {
  if (mfaMode !== "test") throw new Error("Disponível somente em testes.");
  const code = testCodesByRecipient.get(recipient);
  testCodesByRecipient.delete(recipient);
  return code;
}
