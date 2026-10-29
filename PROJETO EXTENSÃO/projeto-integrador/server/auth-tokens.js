import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const issuer = "marquezi-gestao";
const audience = "marquezi-web";
const header = { alg: "HS256", typ: "JWT" };
const encryptionKey = readFileSync(
  resolve(process.env.DATA_DIR || "data", "encryption.key"),
);
const signingKey = createHmac("sha256", encryptionKey)
  .update("jwt-access-signing-key:v1")
  .digest();

const jsonPart = (value) =>
  Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
const signature = (value) =>
  createHmac("sha256", signingKey).update(value).digest("base64url");
const safeEqual = (left, right) => {
  const a = Buffer.from(left || "", "ascii");
  const b = Buffer.from(right || "", "ascii");
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
};

export function signAccessToken({ userId, sessionId, lifetimeMilliseconds }) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    aud: audience,
    sub: String(userId),
    sid: sessionId,
    jti: randomBytes(16).toString("base64url"),
    iat: issuedAt,
    exp: issuedAt + Math.floor(lifetimeMilliseconds / 1000),
  };
  const unsigned = `${jsonPart(header)}.${jsonPart(payload)}`;
  return `${unsigned}.${signature(unsigned)}`;
}

export function verifyAccessToken(token, maximumLifetimeMilliseconds) {
  if (typeof token !== "string" || token.length > 2048) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, suppliedSignature] = parts;
  if (
    !safeEqual(
      signature(`${encodedHeader}.${encodedPayload}`),
      suppliedSignature,
    )
  )
    return null;

  let parsedHeader;
  let payload;
  try {
    parsedHeader = JSON.parse(Buffer.from(encodedHeader, "base64url"));
    payload = JSON.parse(Buffer.from(encodedPayload, "base64url"));
  } catch {
    return null;
  }
  if (
    parsedHeader?.alg !== "HS256" ||
    parsedHeader?.typ !== "JWT" ||
    payload?.iss !== issuer ||
    payload?.aud !== audience ||
    !/^[1-9]\d{0,9}$/.test(payload?.sub || "") ||
    !/^[A-Za-z0-9_-]{32}$/.test(payload?.sid || "") ||
    !/^[A-Za-z0-9_-]{22}$/.test(payload?.jti || "") ||
    !Number.isSafeInteger(payload?.iat) ||
    !Number.isSafeInteger(payload?.exp)
  )
    return null;

  const now = Math.floor(Date.now() / 1000);
  const maximumLifetime = Math.floor(maximumLifetimeMilliseconds / 1000);
  if (
    payload.iat > now + 30 ||
    payload.exp <= now ||
    payload.exp <= payload.iat ||
    payload.exp - payload.iat > maximumLifetime
  )
    return null;
  return {
    userId: Number(payload.sub),
    sessionId: payload.sid,
    expiresAt: payload.exp * 1000,
  };
}
