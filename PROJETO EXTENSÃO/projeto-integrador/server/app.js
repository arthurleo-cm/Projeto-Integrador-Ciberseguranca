import express from "express";
import helmet from "helmet";
import multer from "multer";
import { fileTypeFromBuffer } from "file-type";
import sharp from "sharp";
import {
  randomBytes,
  randomInt,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  db,
  pack,
  unpack,
  encrypt,
  decrypt,
  index,
  hashPassword,
  verifyPassword,
  publicUser,
  transaction,
  audit,
} from "./store.js";
import {
  clientSchema,
  userSchema,
  loginSchema,
  mfaChallengeSchema,
  mfaVerifySchema,
  passwordChangeSchema,
  deleteClientSchema,
  processSchema,
  receiptSchema,
  preferencesSchema,
  processFileSchema,
  PROCESS_STATUS,
  PROCESS_TYPES,
  documentSchema,
} from "./validation.js";
import { sendMfaCode } from "./mailer.js";
import { signAccessToken, verifyAccessToken } from "./auth-tokens.js";
import {
  accessTokenMinutes,
  expectedHost,
  origin,
  secure,
  sessionHours,
  trustedProxyHops,
} from "./config.js";
export const app = express();
const sessionMilliseconds = sessionHours * 60 * 60 * 1000;
const accessTokenMilliseconds = accessTokenMinutes * 60 * 1000;
const accessCookieName = secure ? "__Host-access" : "access";
const refreshCookieName = secure ? "__Host-refresh" : "refresh";
const cookieOptions = {
  httpOnly: true,
  sameSite: "strict",
  secure,
  path: "/",
  priority: "high",
};
app.set("query parser", "simple");
if (trustedProxyHops) app.set("trust proxy", trustedProxyHops);
app.disable("x-powered-by");
app.use(
  helmet({
    crossOriginEmbedderPolicy: { policy: "require-corp" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    frameguard: { action: "deny" },
    referrerPolicy: { policy: "no-referrer" },
    strictTransportSecurity: secure
      ? { maxAge: 63_072_000, includeSubDomains: true, preload: true }
      : false,
    contentSecurityPolicy: {
      directives: {
        "default-src": ["'none'"],
        "script-src": ["'self'"],
        "script-src-attr": ["'none'"],
        "style-src": ["'self'"],
        "style-src-attr": ["'none'"],
        "img-src": ["'self'"],
        "connect-src": ["'self'"],
        "font-src": ["'self'"],
        "manifest-src": ["'self'"],
        "media-src": ["'none'"],
        "worker-src": ["'none'"],
        "base-uri": ["'none'"],
        "form-action": ["'self'"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
        "upgrade-insecure-requests": secure ? [] : null,
      },
    },
  }),
);
app.use((req, res, next) => {
  req.requestId = randomUUID();
  res.set({
    "X-Request-Id": req.requestId,
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    "Permissions-Policy":
      "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), browsing-topics=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), speaker-selection=(), usb=(), web-share=(), xr-spatial-tracking=()",
  });
  if (secure && String(req.get("host") || "").toLowerCase() !== expectedHost)
    return res.status(421).type("text/plain").send("Destino HTTP inválido.");
  if (secure && !req.secure) {
    if (["GET", "HEAD"].includes(req.method))
      return res.redirect(308, origin + req.originalUrl);
    return res.status(400).json({ error: "Use uma conexão HTTPS." });
  }
  if (!["GET", "HEAD", "POST", "PUT", "DELETE"].includes(req.method)) {
    res.set("Allow", "GET, HEAD, POST, PUT, DELETE");
    return res.status(405).type("text/plain").send("Método não permitido.");
  }
  next();
});

const requestWindows = new Map();
const generalWindowMs = 5 * 60 * 1000;
const generalRequestLimit = 600;
app.use((req, res, next) => {
  const now = Date.now();
  const key = req.ip;
  let entry = requestWindows.get(key);
  if (!entry || entry.expires <= now) {
    entry = { total: 0, expires: now + generalWindowMs };
    requestWindows.set(key, entry);
  }
  entry.total += 1;
  res.set("RateLimit-Policy", `${generalRequestLimit};w=${generalWindowMs / 1000}`);
  res.set("RateLimit", `limit=${generalRequestLimit}, remaining=${Math.max(0, generalRequestLimit - entry.total)}, reset=${Math.ceil((entry.expires - now) / 1000)}`);
  if (entry.total > generalRequestLimit) {
    res.set("Retry-After", String(Math.ceil((entry.expires - now) / 1000)));
    return res.status(429).json({ error: "Muitas requisições. Aguarde alguns minutos." });
  }
  if (requestWindows.size > 10_000)
    for (const [candidate, value] of requestWindows)
      if (value.expires <= now) requestWindows.delete(candidate);
  next();
});
app.use("/api", (req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});
const fail = (status, message) => Object.assign(new Error(message), { status });
const id = (value) => {
  if (!/^[1-9]\d{0,9}$/.test(String(value)))
    throw fail(400, "Identificador inválido.");
  return Number(value);
};
app.use("/api", (req, res, next) => {
  if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    if (req.get("origin") !== origin)
      return next(fail(403, "Origem da requisição não autorizada."));
    const fetchSite = req.get("sec-fetch-site");
    if (fetchSite && !["same-origin", "none"].includes(fetchSite))
      return next(fail(403, "Contexto da requisição não autorizado."));
    const hasBody =
      req.get("transfer-encoding") || Number(req.get("content-length") || 0) > 0;
    if (hasBody) {
      const fileUpload =
        req.method === "POST" &&
        (/^\/clients\/[1-9]\d*\/documents$/.test(req.path) ||
          /^\/processes\/[1-9]\d*\/files$/.test(req.path));
      const accepted = fileUpload
        ? req.is("multipart/form-data")
        : req.is("application/json");
      if (!accepted)
        return next(fail(415, "Tipo de conteúdo não aceito nesta operação."));
    }
  }
  next();
});
app.use(express.json({ limit: "128kb" }));
const dummyHash = await hashPassword(randomBytes(32).toString("hex"));
const cookieValue = (req, name) =>
  (req.headers.cookie || "")
    .split(";")
    .map((x) => x.trim())
    .find((x) => x.startsWith(name + "="))
    ?.slice(name.length + 1) || "";
const clearAuthenticationCookies = (res) =>
  res
    .clearCookie(accessCookieName, cookieOptions)
    .clearCookie(refreshCookieName, cookieOptions);
const safeTextEqual = (left, right) => {
  const a = Buffer.from(left || "", "utf8");
  const b = Buffer.from(right || "", "utf8");
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
};
function auth(req, res, next) {
  const claims = verifyAccessToken(
    cookieValue(req, accessCookieName),
    accessTokenMilliseconds,
  );
  if (!claims)
    return next(fail(401, "Entre novamente para continuar."));
  const row = db
    .prepare(
      "SELECT s.id_sessao,s.csrf,s.expira,u.* FROM sessoes s JOIN usuarios u ON u.id_usuario=s.id_usuario WHERE s.id_sessao=? AND s.id_usuario=? AND s.expira>? AND u.ativo=1",
    )
    .get(claims.sessionId, claims.userId, Date.now());
  if (!row) return next(fail(401, "Entre novamente para continuar."));
  req.user = publicUser(row);
  req.session = row;
  if (
    !["GET", "HEAD"].includes(req.method) &&
    !safeTextEqual(req.get("x-csrf-token"), row.csrf)
  )
    return next(fail(403, "Sessão de formulário inválida. Atualize a página."));
  next();
}
const admin = (req, res, next) =>
  req.user.perfil === "ADMINISTRADOR"
    ? next()
    : next(fail(403, "Acesso exclusivo de administradores."));
app.get("/api/health", (req, res) => {
  db.prepare("SELECT 1").get();
  res.json({ status: "ok" });
});
const mfaLifetime = 10 * 60 * 1000;
const mfaResendDelay = 60 * 1000;
const maskEmail = (email) => {
  const [local, domain] = email.split("@");
  return `${local.slice(0, 1)}${"*".repeat(Math.min(6, Math.max(2, local.length - 1)))}@${domain}`;
};
const mfaTokenHash = (challenge) => index("mfa-token:" + challenge);
const mfaCodeHash = (challenge, code) =>
  index(`mfa-code:${challenge}:${code}`);
const safeHashEqual = (left, right) => {
  const a = Buffer.from(left || "", "hex");
  const b = Buffer.from(right || "", "hex");
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
};
function createSession(req, res, user) {
  const now = Date.now();
  const sessionId = randomBytes(24).toString("base64url");
  const refreshToken = randomBytes(32).toString("base64url");
  const csrf = randomBytes(32).toString("hex");
  const userData = unpack(user.dados, "usuario");
  transaction(() => {
    db.prepare("DELETE FROM desafios_mfa WHERE id_usuario=?").run(
      user.id_usuario,
    );
    for (const key of [
      index("ip:" + req.ip),
      index("login:" + userData.email),
      index("mfa-send:" + user.id_usuario),
    ])
      db.prepare("DELETE FROM tentativas WHERE chave=?").run(key);
    db.prepare(
      "INSERT INTO sessoes(id_sessao,id_usuario,refresh_hash,csrf,expira,criado) VALUES(?,?,?,?,?,?)",
    ).run(
      sessionId,
      user.id_usuario,
      index("refresh:" + refreshToken),
      csrf,
      now + sessionMilliseconds,
      now,
    );
    db.prepare(
      "DELETE FROM sessoes WHERE id_usuario=? AND id_sessao NOT IN (SELECT id_sessao FROM sessoes WHERE id_usuario=? ORDER BY criado DESC,rowid DESC LIMIT 5)",
    ).run(user.id_usuario, user.id_usuario);
    audit(user.id_usuario, "LOGIN", "usuarios", user.id_usuario);
  });
  const accessToken = signAccessToken({
    userId: user.id_usuario,
    sessionId,
    lifetimeMilliseconds: accessTokenMilliseconds,
  });
  res
    .cookie(accessCookieName, accessToken, {
      ...cookieOptions,
      maxAge: accessTokenMilliseconds,
    })
    .cookie(refreshCookieName, refreshToken, {
      ...cookieOptions,
      maxAge: sessionMilliseconds,
    })
    .json({
      user: publicUser(user),
      csrf,
      acesso_expira_em_segundos: accessTokenMilliseconds / 1000,
    });
}
app.post("/api/login", async (req, res) => {
  const v = loginSchema.parse(req.body),
    email = v.email;
  const keys = [index("ip:" + req.ip), index("login:" + email)];
  const now = Date.now();
  db.prepare("DELETE FROM tentativas WHERE expira<?").run(now);
  db.prepare("DELETE FROM sessoes WHERE expira<?").run(now);
  db.prepare("DELETE FROM refresh_tokens_usados WHERE expira<?").run(now);
  db.prepare("DELETE FROM desafios_mfa WHERE expira<?").run(now);
  for (const key of keys) {
    const row = db
      .prepare("SELECT total FROM tentativas WHERE chave=?")
      .get(key);
    if (row?.total >= 10)
      throw fail(429, "Muitas tentativas. Aguarde 15 minutos.");
  }
  for (const key of keys)
    db.prepare(
      "INSERT INTO tentativas(chave,total,expira) VALUES(?,1,?) ON CONFLICT(chave) DO UPDATE SET total=total+1,expira=excluded.expira",
    ).run(key, now + 15 * 60 * 1000);
  const user = db
    .prepare("SELECT * FROM usuarios WHERE email_indice=?")
    .get(index(email));
  const valid = await verifyPassword(v.senha, user?.senha_hash || dummyHash);
  const latest =
    user &&
    db
      .prepare("SELECT ativo,senha_hash FROM usuarios WHERE id_usuario=?")
      .get(user.id_usuario);
  if (!latest?.ativo || latest.senha_hash !== user.senha_hash || !valid)
    throw fail(401, "E-mail ou senha inválidos.");

  const sendKey = index("mfa-send:" + user.id_usuario);
  const sent = db.prepare("SELECT total FROM tentativas WHERE chave=?").get(sendKey);
  if (sent?.total >= 5)
    throw fail(429, "Muitos códigos solicitados. Aguarde 15 minutos.");
  const challenge = randomBytes(32).toString("base64url");
  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  const userData = unpack(user.dados, "usuario");
  const destination = userData.email;
  transaction(() => {
    db.prepare("DELETE FROM desafios_mfa WHERE id_usuario=?").run(
      user.id_usuario,
    );
    db.prepare(
      "INSERT INTO desafios_mfa(token_hash,id_usuario,codigo_hash,ip_indice,senha_indice,proximo_envio,expira,criado) VALUES(?,?,?,?,?,?,?,?)",
    ).run(
      mfaTokenHash(challenge),
      user.id_usuario,
      mfaCodeHash(challenge, code),
      index("mfa-ip:" + req.ip),
      index("mfa-password:" + user.senha_hash),
      now + mfaResendDelay,
      now + mfaLifetime,
      now,
    );
    db.prepare(
      "INSERT INTO tentativas(chave,total,expira) VALUES(?,1,?) ON CONFLICT(chave) DO UPDATE SET total=total+1,expira=excluded.expira",
    ).run(sendKey, now + 15 * 60 * 1000);
  });
  try {
    await sendMfaCode({ to: destination, code, challenge });
  } catch {
    db.prepare("DELETE FROM desafios_mfa WHERE token_hash=?").run(
      mfaTokenHash(challenge),
    );
    throw fail(503, "Não foi possível enviar o código de acesso. Tente novamente.");
  }
  res.status(202).json({
    mfa_required: true,
    desafio: challenge,
    destino: maskEmail(destination),
    expira_em_segundos: mfaLifetime / 1000,
  });
});
app.post("/api/mfa/verify", (req, res) => {
  const value = mfaVerifySchema.parse(req.body);
  const now = Date.now();
  const row = db
    .prepare(
      "SELECT d.*,u.* FROM desafios_mfa d JOIN usuarios u ON u.id_usuario=d.id_usuario WHERE d.token_hash=?",
    )
    .get(mfaTokenHash(value.desafio));
  const usable =
    row &&
    row.ativo &&
    row.expira > now &&
    row.tentativas < 5 &&
    row.ip_indice === index("mfa-ip:" + req.ip) &&
    row.senha_indice === index("mfa-password:" + row.senha_hash);
  if (!usable) {
    if (row)
      db.prepare("DELETE FROM desafios_mfa WHERE token_hash=?").run(
        row.token_hash,
      );
    throw fail(401, "Código inválido ou expirado. Entre novamente.");
  }
  const valid = safeHashEqual(
    row.codigo_hash,
    mfaCodeHash(value.desafio, value.codigo),
  );
  if (!valid) {
    const attempts = row.tentativas + 1;
    if (attempts >= 5)
      db.prepare("DELETE FROM desafios_mfa WHERE token_hash=?").run(
        row.token_hash,
      );
    else
      db.prepare(
        "UPDATE desafios_mfa SET tentativas=? WHERE token_hash=?",
      ).run(attempts, row.token_hash);
    throw fail(
      401,
      attempts >= 5
        ? "Limite de tentativas atingido. Entre novamente."
        : "Código inválido ou expirado.",
    );
  }
  createSession(req, res, row);
});
app.post("/api/mfa/resend", async (req, res) => {
  const value = mfaChallengeSchema.parse(req.body);
  const now = Date.now();
  const row = db
    .prepare(
      "SELECT d.*,u.dados,u.senha_hash,u.ativo FROM desafios_mfa d JOIN usuarios u ON u.id_usuario=d.id_usuario WHERE d.token_hash=?",
    )
    .get(mfaTokenHash(value.desafio));
  if (
    !row?.ativo ||
    row.expira <= now ||
    row.tentativas >= 5 ||
    row.ip_indice !== index("mfa-ip:" + req.ip) ||
    row.senha_indice !== index("mfa-password:" + row.senha_hash)
  )
    throw fail(401, "Desafio expirado. Entre novamente.");
  if (row.proximo_envio > now) {
    res.set("Retry-After", String(Math.ceil((row.proximo_envio - now) / 1000)));
    throw fail(429, "Aguarde um minuto antes de reenviar.");
  }
  const sendKey = index("mfa-send:" + row.id_usuario);
  const sent = db.prepare("SELECT total FROM tentativas WHERE chave=?").get(sendKey);
  if (sent?.total >= 5)
    throw fail(429, "Muitos códigos solicitados. Aguarde 15 minutos.");
  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  const data = unpack(row.dados, "usuario");
  const destination = data.email;
  transaction(() => {
    db.prepare(
      "UPDATE desafios_mfa SET codigo_hash=?,proximo_envio=?,expira=? WHERE token_hash=?",
    ).run(
      mfaCodeHash(value.desafio, code),
      now + mfaResendDelay,
      now + mfaLifetime,
      row.token_hash,
    );
    db.prepare(
      "INSERT INTO tentativas(chave,total,expira) VALUES(?,1,?) ON CONFLICT(chave) DO UPDATE SET total=total+1,expira=excluded.expira",
    ).run(sendKey, now + 15 * 60 * 1000);
  });
  try {
    await sendMfaCode({ to: destination, code, challenge: value.desafio });
  } catch {
    db.prepare("DELETE FROM desafios_mfa WHERE token_hash=?").run(row.token_hash);
    throw fail(503, "Não foi possível reenviar o código. Entre novamente.");
  }
  res.json({ ok: true, destino: maskEmail(destination) });
});
app.post("/api/refresh", (req, res) => {
  const refreshToken = cookieValue(req, refreshCookieName);
  if (!/^[A-Za-z0-9_-]{43}$/.test(refreshToken)) {
    clearAuthenticationCookies(res);
    throw fail(401, "Entre novamente para continuar.");
  }

  const now = Date.now();
  const refreshHash = index("refresh:" + refreshToken);
  db.prepare("DELETE FROM refresh_tokens_usados WHERE expira<?").run(now);
  db.prepare("DELETE FROM sessoes WHERE expira<?").run(now);
  const row = db
    .prepare(
      "SELECT s.id_sessao,s.id_usuario,s.csrf,s.expira,u.* FROM sessoes s JOIN usuarios u ON u.id_usuario=s.id_usuario WHERE s.refresh_hash=? AND s.expira>? AND u.ativo=1",
    )
    .get(refreshHash, now);

  if (!row) {
    const replay = db
      .prepare(
        "SELECT id_sessao,id_usuario FROM refresh_tokens_usados WHERE token_hash=? AND expira>?",
      )
      .get(refreshHash, now);
    if (replay)
      db.prepare(
        "DELETE FROM sessoes WHERE id_sessao=? AND id_usuario=?",
      ).run(replay.id_sessao, replay.id_usuario);
    clearAuthenticationCookies(res);
    throw fail(401, "Sessão expirada ou revogada. Entre novamente.");
  }

  const remaining = row.expira - now;
  if (remaining < 1000) {
    db.prepare("DELETE FROM sessoes WHERE id_sessao=?").run(row.id_sessao);
    clearAuthenticationCookies(res);
    throw fail(401, "Sessão expirada. Entre novamente.");
  }
  const newRefreshToken = randomBytes(32).toString("base64url");
  const newCsrf = randomBytes(32).toString("hex");
  transaction(() => {
    db.prepare(
      "INSERT INTO refresh_tokens_usados(token_hash,id_sessao,id_usuario,expira) VALUES(?,?,?,?)",
    ).run(refreshHash, row.id_sessao, row.id_usuario, row.expira);
    db.prepare(
      "UPDATE sessoes SET refresh_hash=?,csrf=? WHERE id_sessao=?",
    ).run(
      index("refresh:" + newRefreshToken),
      newCsrf,
      row.id_sessao,
    );
  });

  const accessLifetime = Math.min(accessTokenMilliseconds, remaining);
  const accessToken = signAccessToken({
    userId: row.id_usuario,
    sessionId: row.id_sessao,
    lifetimeMilliseconds: accessLifetime,
  });
  res
    .cookie(accessCookieName, accessToken, {
      ...cookieOptions,
      maxAge: accessLifetime,
    })
    .cookie(refreshCookieName, newRefreshToken, {
      ...cookieOptions,
      maxAge: remaining,
    })
    .json({
      user: publicUser(row),
      csrf: newCsrf,
      acesso_expira_em_segundos: Math.floor(accessLifetime / 1000),
    });
});
app.use("/api", auth);
app.get("/api/me", (req, res) =>
  res.json({ user: req.user, csrf: req.session.csrf }),
);
app.post("/api/logout", (req, res) => {
  transaction(() => {
    db.prepare("DELETE FROM sessoes WHERE id_sessao=?").run(
      req.session.id_sessao,
    );
    audit(req.user.id_usuario, "LOGOUT", "usuarios", req.user.id_usuario);
  });
  clearAuthenticationCookies(res)
    .set("Clear-Site-Data", '"cache", "storage"')
    .json({ ok: true });
});
app.post("/api/password", async (req, res) => {
  const v = passwordChangeSchema.parse(req.body);
  const row = db
    .prepare("SELECT senha_hash FROM usuarios WHERE id_usuario=?")
    .get(req.user.id_usuario);
  if (!(await verifyPassword(v.atual, row.senha_hash)))
    throw fail(400, "Senha atual incorreta.");
  const hash = await hashPassword(v.nova);
  transaction(() => {
    db.prepare(
      "UPDATE usuarios SET senha_hash=?,data_atualizacao=CURRENT_TIMESTAMP WHERE id_usuario=?",
    ).run(hash, req.user.id_usuario);
    db.prepare("DELETE FROM sessoes WHERE id_usuario=?").run(
      req.user.id_usuario,
    );
    db.prepare("DELETE FROM desafios_mfa WHERE id_usuario=?").run(
      req.user.id_usuario,
    );
    audit(req.user.id_usuario, "ALTERACAO", "usuarios", req.user.id_usuario);
  });
  clearAuthenticationCookies(res).json({ ok: true });
});
app.put("/api/preferences", (req, res) => {
  const preferencias = preferencesSchema.parse(req.body);
  transaction(() => {
    const row = db
      .prepare("SELECT dados FROM usuarios WHERE id_usuario=?")
      .get(req.user.id_usuario);
    const current = unpack(row.dados, "usuario");
    db.prepare(
      "UPDATE usuarios SET dados=?,data_atualizacao=CURRENT_TIMESTAMP WHERE id_usuario=?",
    ).run(
      pack({ ...current, preferencias }, "usuario"),
      req.user.id_usuario,
    );
    audit(req.user.id_usuario, "ALTERACAO", "usuarios", req.user.id_usuario);
  });
  res.json({ preferencias });
});
function clientRow(clientId) {
  const row = db
    .prepare("SELECT * FROM clientes WHERE id_cliente=?")
    .get(clientId);
  if (!row) throw fail(404, "Cliente não encontrado.");
  return row;
}
const clientView = (row) => ({
  id_cliente: row.id_cliente,
  ...unpack(row.dados, "cliente"),
  ativo: !!row.ativo,
  versao: row.versao,
  data_atualizacao: row.data_atualizacao,
});
app.get("/api/dashboard", (req, res) => {
  const data = {
    clientes: db.prepare("SELECT count(*) n FROM clientes").get().n,
    ativos: db.prepare("SELECT count(*) n FROM clientes WHERE ativo=1").get().n,
    documentos: db.prepare("SELECT count(*) n FROM documentos").get().n,
    processos: db.prepare("SELECT count(*) n FROM processos").get().n,
    processos_ativos: db
      .prepare("SELECT count(*) n FROM processos WHERE situacao='ATIVO'")
      .get().n,
    sem_atualizacao: db
      .prepare(
        "SELECT count(*) n FROM processos WHERE situacao='ATIVO' AND data_atualizacao<datetime('now','-30 days')",
      )
      .get().n,
    por_status: db
      .prepare("SELECT status,count(*) total FROM processos GROUP BY status")
      .all(),
  };
  if (req.user.perfil === "ADMINISTRADOR") {
    data.financeiro = {
      estimado: db
        .prepare("SELECT coalesce(sum(valor_estimado_centavos),0) total FROM processos")
        .get().total,
      recebido: db
        .prepare("SELECT coalesce(sum(valor_centavos),0) total FROM recebimentos")
        .get().total,
    };
  }
  res.json(data);
});
app.get("/api/clients", (req, res) => {
  const q = String(req.query.q || "")
      .toLocaleLowerCase("pt-BR")
      .slice(0, 180),
    page = Math.max(1, Math.min(100000, Number(req.query.page) || 1));
  const rows = db
    .prepare("SELECT * FROM clientes ORDER BY id_cliente DESC")
    .all()
    .map(clientView)
    .filter(
      (c) =>
        !q ||
        c.nome.toLocaleLowerCase("pt-BR").includes(q) ||
        c.cpf_cnpj.includes(q.replace(/[.\-/]/g, "")),
    );
  res.json({
    total: rows.length,
    page,
    items: rows
      .slice((page - 1) * 25, page * 25)
      .map(({ observacoes, data_nascimento, ...c }) => c),
  });
});
app.get("/api/clients/:id", (req, res) => {
  const clientId = id(req.params.id),
    c = clientView(clientRow(clientId));
  c.contatos = db
    .prepare("SELECT * FROM contatos WHERE id_cliente=?")
    .all(clientId)
    .map((x) => ({
      tipo: x.tipo,
      ...unpack(x.dados, "contato"),
      principal: !!x.principal,
    }));
  c.enderecos = db
    .prepare("SELECT * FROM enderecos WHERE id_cliente=?")
    .all(clientId)
    .map((x) => ({ ...unpack(x.dados, "endereco"), principal: !!x.principal }));
  c.documentos = db
    .prepare(
      "SELECT id_documento,dados,tamanho_bytes,data_envio FROM documentos WHERE id_cliente=? ORDER BY id_documento DESC",
    )
    .all(clientId)
    .map((x) => ({
      id_documento: x.id_documento,
      ...unpack(x.dados, "documento"),
      tamanho_bytes: x.tamanho_bytes,
      data_envio: x.data_envio,
    }));
  c.processos = db
    .prepare(
      "SELECT id_processo,dados,status,situacao,data_atualizacao FROM processos WHERE id_cliente=? ORDER BY id_processo DESC",
    )
    .all(clientId)
    .map((x) => ({
      id_processo: x.id_processo,
      ...unpack(x.dados, "processo"),
      status: x.status,
      situacao: x.situacao,
      data_atualizacao: x.data_atualizacao,
    }));
  audit(req.user.id_usuario, "LEITURA", "clientes", clientId);
  res.json(c);
});
function saveClient(req, res) {
  const v = clientSchema.parse(req.body),
    clientId = req.params.id ? id(req.params.id) : null;
  if (clientId && !v.versao)
    throw fail(400, "Informe a versão atual do cadastro.");
  const { contatos, enderecos, ativo, versao, ...data } = v;
  const result = transaction(() => {
    let saved = clientId;
    if (clientId) {
      const old = clientRow(clientId);
      if (old.versao !== versao)
        throw fail(
          409,
          "Cadastro alterado por outra pessoa. Reabra o cliente antes de salvar.",
        );
      db.prepare(
        "UPDATE clientes SET dados=?,documento_indice=?,ativo=?,versao=versao+1,data_atualizacao=CURRENT_TIMESTAMP WHERE id_cliente=?",
      ).run(
        pack(data, "cliente"),
        v.cpf_cnpj ? index(v.cpf_cnpj) : null,
        +ativo,
        clientId,
      );
      db.prepare("DELETE FROM contatos WHERE id_cliente=?").run(clientId);
      db.prepare("DELETE FROM enderecos WHERE id_cliente=?").run(clientId);
    } else
      saved = Number(
        db
          .prepare(
            "INSERT INTO clientes(dados,documento_indice,ativo) VALUES(?,?,?)",
          )
          .run(
            pack(data, "cliente"),
            v.cpf_cnpj ? index(v.cpf_cnpj) : null,
            +ativo,
          ).lastInsertRowid,
      );
    for (const c of contatos) {
      const valor = c.tipo === "EMAIL" ? c.valor.toLowerCase() : c.valor;
      db.prepare(
        "INSERT INTO contatos(id_cliente,tipo,dados,valor_indice,principal) VALUES(?,?,?,?,?)",
      ).run(
        saved,
        c.tipo,
        pack({ valor }, "contato"),
        index(valor),
        +c.principal,
      );
    }
    for (const { principal, ...a } of enderecos)
      db.prepare(
        "INSERT INTO enderecos(id_cliente,dados,principal) VALUES(?,?,?)",
      ).run(saved, pack(a, "endereco"), +principal);
    audit(
      req.user.id_usuario,
      clientId ? "ALTERACAO" : "CADASTRO",
      "clientes",
      saved,
    );
    return saved;
  });
  res.status(clientId ? 200 : 201).json({ id_cliente: result });
}
app.post("/api/clients", saveClient);
app.put("/api/clients/:id", saveClient);
app.delete("/api/clients/:id", admin, (req, res) => {
  const clientId = id(req.params.id),
    { versao } = deleteClientSchema.parse(req.body);
  transaction(() => {
    const row = clientRow(clientId);
    if (row.versao !== versao)
      throw fail(409, "Cadastro alterado. Reabra o cliente.");
    if (
      db
        .prepare("SELECT count(*) n FROM documentos WHERE id_cliente=?")
        .get(clientId).n
    )
      throw fail(
        409,
        "Remova os documentos vinculados ou desative o cadastro.",
      );
    if (
      db
        .prepare("SELECT count(*) n FROM processos WHERE id_cliente=?")
        .get(clientId).n
    )
      throw fail(409, "O cliente possui processos vinculados. Desative o cadastro.");
    db.prepare("DELETE FROM contatos WHERE id_cliente=?").run(clientId);
    db.prepare("DELETE FROM enderecos WHERE id_cliente=?").run(clientId);
    db.prepare("DELETE FROM clientes WHERE id_cliente=?").run(clientId);
    audit(req.user.id_usuario, "EXCLUSAO", "clientes", clientId);
  });
  res.json({ ok: true });
});
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
    files: 1,
    fields: 2,
    parts: 3,
    fieldSize: 1024,
  },
});
app.post(
  "/api/clients/:id/documents",
  upload.single("arquivo"),
  async (req, res) => {
    const clientId = id(req.params.id),
      v = documentSchema.parse(req.body);
    clientRow(clientId);
    if (!req.file) throw fail(400, "Selecione um arquivo.");
    const type = await fileTypeFromBuffer(req.file.buffer);
    if (
      !type ||
      !["application/pdf", "image/jpeg", "image/png"].includes(type.mime)
    )
      throw fail(400, "Envie um PDF, JPEG ou PNG válido.");
    const original =
      req.file.originalname
        .normalize("NFKC")
        .replace(/[\x00-\x1f\x7f/\\\u202a-\u202e\u2066-\u2069]/g, "_")
        .slice(0, 200) || `arquivo.${type.ext}`;
    const metadata = {
      ...v,
      nome_original: original,
      tipo_mime: type.mime,
      ext: type.ext,
    };
    const documentId = transaction(() => {
      clientRow(clientId);
      const row = db
        .prepare(
          "INSERT INTO documentos(id_cliente,id_usuario_envio,dados,conteudo,tamanho_bytes) VALUES(?,?,?,?,?)",
        )
        .run(
          clientId,
          req.user.id_usuario,
          pack(metadata, "documento"),
          encrypt(req.file.buffer, `arquivo:${clientId}`),
          req.file.size,
        );
      const docId = Number(row.lastInsertRowid);
      audit(req.user.id_usuario, "CADASTRO", "documentos", docId);
      return docId;
    });
    res.status(201).json({ id_documento: documentId });
  },
);
app.get("/api/documents/:id/download", (req, res) => {
  const documentId = id(req.params.id),
    row = db
      .prepare("SELECT * FROM documentos WHERE id_documento=?")
      .get(documentId);
  if (!row) throw fail(404, "Documento não encontrado.");
  const meta = unpack(row.dados, "documento"),
    content = decrypt(row.conteudo, `arquivo:${row.id_cliente}`);
  audit(req.user.id_usuario, "LEITURA", "documentos", documentId);
  res
    .attachment(`documento-${documentId}.${meta.ext}`)
    .type(meta.tipo_mime)
    .send(content);
});
app.delete("/api/documents/:id", admin, (req, res) => {
  const documentId = id(req.params.id);
  transaction(() => {
    const result = db
      .prepare("DELETE FROM documentos WHERE id_documento=?")
      .run(documentId);
    if (!result.changes) throw fail(404, "Documento não encontrado.");
    audit(req.user.id_usuario, "EXCLUSAO", "documentos", documentId);
  });
  res.json({ ok: true });
});
function processRow(processId) {
  const row = db
    .prepare("SELECT * FROM processos WHERE id_processo=?")
    .get(processId);
  if (!row) throw fail(404, "Processo não encontrado.");
  return row;
}
function processView(row, includeFinancial = false) {
  const decrypted = unpack(row.dados, "processo");
  const data = {
    id_processo: row.id_processo,
    id_cliente: row.id_cliente,
    ...decrypted,
    status: row.status,
    ramo: row.ramo,
    tipificacao: row.tipificacao,
    situacao: row.situacao,
    data_abertura: row.data_abertura,
    versao: row.versao,
    data_cadastro: row.data_cadastro,
    data_atualizacao: row.data_atualizacao,
  };
  if (row.cliente_dados)
    data.cliente = unpack(row.cliente_dados, "cliente").nome;
  if (includeFinancial) {
    const recebido = db
      .prepare(
        "SELECT coalesce(sum(valor_centavos),0) total FROM recebimentos WHERE id_processo=?",
      )
      .get(row.id_processo).total;
    data.valor_estimado_centavos = row.valor_estimado_centavos;
    data.valor_recebido_centavos = recebido;
    data.saldo_centavos = row.valor_estimado_centavos - recebido;
    data.status_pagamento =
      row.valor_estimado_centavos === 0
        ? "SEM_VALOR"
        : recebido === 0
          ? "PENDENTE"
          : recebido < row.valor_estimado_centavos
            ? "PARCIAL"
            : "QUITADO";
  } else {
    delete data.previsao_recebimento;
  }
  return data;
}
function addProcessHistory(processId, userId, event, details = {}) {
  db.prepare(
    "INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
  ).run(
    processId,
    userId,
    pack({ evento: event, ...details }, `historico:${processId}`),
  );
}
app.get("/api/process-options", (req, res) =>
  res.json({
    status: PROCESS_STATUS,
    tipos: PROCESS_TYPES,
    situacoes: ["ATIVO", "ENCERRADO", "ARQUIVADO"],
  }),
);
app.get("/api/client-options", (req, res) =>
  res.json(
    db
      .prepare("SELECT id_cliente,dados FROM clientes WHERE ativo=1 ORDER BY id_cliente")
      .all()
      .map((row) => ({
        id_cliente: row.id_cliente,
        nome: unpack(row.dados, "cliente").nome,
      }))
      .sort((a, b) => a.nome.localeCompare(b.nome, "pt-BR")),
  ),
);
const queryDate = (value, field) => {
  if (!value) return "";
  const text = String(value);
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(text) ||
    !Number.isFinite(Date.parse(text)) ||
    new Date(text).toISOString().slice(0, 10) !== text
  )
    throw fail(400, `${field} inválida.`);
  return text;
};
app.get("/api/processes", (req, res) => {
  const adminUser = req.user.perfil === "ADMINISTRADOR";
  const page = Math.max(1, Math.min(100000, Number(req.query.page) || 1));
  const q = String(req.query.q || "")
    .trim()
    .toLocaleLowerCase("pt-BR")
    .slice(0, 180);
  const where = [];
  const params = [];
  const exact = (name, values, column = name) => {
    if (!req.query[name]) return;
    const value = String(req.query[name]);
    if (!values.includes(value)) throw fail(400, `Filtro ${name} inválido.`);
    where.push(`p.${column}=?`);
    params.push(value);
  };
  exact("status", PROCESS_STATUS);
  exact("ramo", Object.keys(PROCESS_TYPES));
  exact("situacao", ["ATIVO", "ENCERRADO", "ARQUIVADO"]);
  if (req.query.tipificacao) {
    const value = String(req.query.tipificacao);
    if (!Object.values(PROCESS_TYPES).flat().includes(value))
      throw fail(400, "Filtro de tipificação inválido.");
    where.push("p.tipificacao=?");
    params.push(value);
  }
  if (req.query.id_cliente) {
    const clientId = id(req.query.id_cliente);
    where.push("p.id_cliente=?");
    params.push(clientId);
  }
  for (const [name, column, operator, label] of [
    ["abertura_de", "data_abertura", ">=", "Data inicial de abertura"],
    ["abertura_ate", "data_abertura", "<=", "Data final de abertura"],
    ["atualizacao_de", "date(data_atualizacao)", ">=", "Data inicial de atualização"],
    ["atualizacao_ate", "date(data_atualizacao)", "<=", "Data final de atualização"],
  ]) {
    const value = queryDate(req.query[name], label);
    if (value) {
      where.push(`${column}${operator}?`);
      params.push(value);
    }
  }
  for (const [name, operator] of [
    ["valor_min", ">="],
    ["valor_max", "<="],
  ]) {
    if (req.query[name] === undefined || req.query[name] === "") continue;
    if (!adminUser) throw fail(403, "Filtros financeiros exigem perfil administrador.");
    const value = Number(req.query[name]);
    if (!Number.isSafeInteger(value) || value < 0)
      throw fail(400, "Faixa de valor inválida.");
    where.push(`p.valor_estimado_centavos${operator}?`);
    params.push(value);
  }
  for (const [name, operator] of [
    ["recebido_min", ">="],
    ["recebido_max", "<="],
  ]) {
    if (req.query[name] === undefined || req.query[name] === "") continue;
    if (!adminUser) throw fail(403, "Filtros financeiros exigem perfil administrador.");
    const value = Number(req.query[name]);
    if (!Number.isSafeInteger(value) || value < 0)
      throw fail(400, "Faixa de recebimento inválida.");
    where.push(
      `(SELECT coalesce(sum(r.valor_centavos),0) FROM recebimentos r WHERE r.id_processo=p.id_processo)${operator}?`,
    );
    params.push(value);
  }
  if (req.query.com_anexos) {
    const attachmentFilter = String(req.query.com_anexos);
    if (!["1", "0", "FOTO", "DOCUMENTO"].includes(attachmentFilter))
      throw fail(400, "Filtro de anexos inválido.");
    if (["1", "0"].includes(attachmentFilter))
      where.push(
        `${attachmentFilter === "1" ? "" : "NOT "}EXISTS (SELECT 1 FROM arquivos_processos a WHERE a.id_processo=p.id_processo)`,
      );
    else {
      where.push(
        "EXISTS (SELECT 1 FROM arquivos_processos a WHERE a.id_processo=p.id_processo AND a.categoria=?)",
      );
      params.push(attachmentFilter);
    }
  }
  const rows = db
    .prepare(
      `SELECT p.*,c.dados cliente_dados FROM processos p JOIN clientes c ON c.id_cliente=p.id_cliente ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY p.id_processo DESC`,
    )
    .all(...params)
    .map((row) => processView(row, adminUser))
    .filter((process) => {
      if (!q) return true;
      const digits = q.replace(/\D/g, "");
      return (
        String(process.id_processo) === q ||
        process.titulo.toLocaleLowerCase("pt-BR").includes(q) ||
        process.cliente.toLocaleLowerCase("pt-BR").includes(q) ||
        (digits && process.numero_cnj.includes(digits))
      );
    });
  res.json({
    page,
    total: rows.length,
    items: rows.slice((page - 1) * 25, page * 25).map(({ observacoes, ...row }) => row),
  });
});
app.get("/api/processes/:id", (req, res) => {
  const processId = id(req.params.id);
  const row = db
    .prepare(
      "SELECT p.*,c.dados cliente_dados FROM processos p JOIN clientes c ON c.id_cliente=p.id_cliente WHERE p.id_processo=?",
    )
    .get(processId);
  if (!row) throw fail(404, "Processo não encontrado.");
  const result = processView(row, req.user.perfil === "ADMINISTRADOR");
  result.historico = db
    .prepare(
      "SELECT h.*,u.dados usuario_dados FROM historico_processos h JOIN usuarios u ON u.id_usuario=h.id_usuario WHERE h.id_processo=? ORDER BY h.id_historico DESC LIMIT 100",
    )
    .all(processId)
    .map((item) => ({
      id_historico: item.id_historico,
      ...unpack(item.dados, `historico:${processId}`),
      usuario: unpack(item.usuario_dados, "usuario").nome,
      data_hora: item.data_hora,
    }));
  result.arquivos = db
    .prepare(
      "SELECT id_arquivo,categoria,dados,tamanho_bytes,data_envio FROM arquivos_processos WHERE id_processo=? ORDER BY id_arquivo DESC",
    )
    .all(processId)
    .map((item) => ({
      id_arquivo: item.id_arquivo,
      categoria: item.categoria,
      ...unpack(item.dados, "processo-arquivo"),
      tamanho_bytes: item.tamanho_bytes,
      data_envio: item.data_envio,
    }));
  if (req.user.perfil === "ADMINISTRADOR")
    result.recebimentos = db
      .prepare(
        "SELECT id_recebimento,dados,valor_centavos,data_recebimento,data_cadastro FROM recebimentos WHERE id_processo=? ORDER BY data_recebimento DESC,id_recebimento DESC",
      )
      .all(processId)
      .map((item) => ({
        id_recebimento: item.id_recebimento,
        ...unpack(item.dados, `recebimento:${processId}`),
        valor_centavos: item.valor_centavos,
        data_recebimento: item.data_recebimento,
        data_cadastro: item.data_cadastro,
      }));
  audit(req.user.id_usuario, "LEITURA", "processos", processId);
  res.json(result);
});
function saveProcess(req, res) {
  const processId = req.params.id ? id(req.params.id) : null;
  const old = processId ? processRow(processId) : null;
  const oldData = old ? unpack(old.dados, "processo") : null;
  const input = {
    ...req.body,
    valor_estimado_centavos:
      req.user.perfil === "ADMINISTRADOR"
        ? req.body?.valor_estimado_centavos
        : old?.valor_estimado_centavos || 0,
    previsao_recebimento:
      req.user.perfil === "ADMINISTRADOR"
        ? req.body?.previsao_recebimento || ""
        : oldData?.previsao_recebimento || "",
  };
  const value = processSchema.parse(input);
  if (processId && !value.versao)
    throw fail(400, "Informe a versão atual do processo.");
  const client = clientRow(value.id_cliente);
  if (!client.ativo) throw fail(409, "Selecione um cliente ativo.");
  const {
    id_cliente,
    numero_cnj,
    titulo,
    observacoes,
    status,
    ramo,
    tipificacao,
    situacao,
    data_abertura,
    valor_estimado_centavos,
    previsao_recebimento,
    versao,
  } = value;
  const saved = transaction(() => {
    if (old) {
      if (old.versao !== versao)
        throw fail(409, "Processo alterado por outra pessoa. Reabra antes de salvar.");
      db.prepare(
        "UPDATE processos SET id_cliente=?,numero_indice=?,dados=?,status=?,ramo=?,tipificacao=?,situacao=?,data_abertura=?,valor_estimado_centavos=?,versao=versao+1,data_atualizacao=CURRENT_TIMESTAMP WHERE id_processo=?",
      ).run(
        id_cliente,
        index(numero_cnj),
        pack(
          { numero_cnj, titulo, observacoes, previsao_recebimento },
          "processo",
        ),
        status,
        ramo,
        tipificacao,
        situacao,
        data_abertura,
        valor_estimado_centavos,
        processId,
      );
      addProcessHistory(processId, req.user.id_usuario, "PROCESSO_ATUALIZADO", {
        status_anterior: old.status,
        status_atual: status,
      });
      audit(req.user.id_usuario, "ALTERACAO", "processos", processId);
      return processId;
    }
    const inserted = db
      .prepare(
        "INSERT INTO processos(id_cliente,numero_indice,dados,status,ramo,tipificacao,situacao,data_abertura,valor_estimado_centavos) VALUES(?,?,?,?,?,?,?,?,?)",
      )
      .run(
        id_cliente,
        index(numero_cnj),
        pack(
          { numero_cnj, titulo, observacoes, previsao_recebimento },
          "processo",
        ),
        status,
        ramo,
        tipificacao,
        situacao,
        data_abertura,
        valor_estimado_centavos,
      );
    const createdId = Number(inserted.lastInsertRowid);
    addProcessHistory(createdId, req.user.id_usuario, "PROCESSO_CADASTRADO", {
      status_atual: status,
    });
    audit(req.user.id_usuario, "CADASTRO", "processos", createdId);
    return createdId;
  });
  res.status(processId ? 200 : 201).json({ id_processo: saved });
}
app.post("/api/processes", saveProcess);
app.put("/api/processes/:id", saveProcess);
app.delete("/api/processes/:id", admin, (req, res) => {
  const processId = id(req.params.id);
  const { versao } = deleteClientSchema.parse(req.body);
  transaction(() => {
    const row = processRow(processId);
    if (row.versao !== versao) throw fail(409, "Processo alterado. Reabra antes de excluir.");
    const linked = db
      .prepare(
        "SELECT (SELECT count(*) FROM recebimentos WHERE id_processo=?) recebimentos,(SELECT count(*) FROM arquivos_processos WHERE id_processo=?) arquivos",
      )
      .get(processId, processId);
    if (linked.recebimentos || linked.arquivos)
      throw fail(409, "Remova recebimentos e anexos antes de excluir o processo.");
    db.prepare("DELETE FROM processos WHERE id_processo=?").run(processId);
    audit(req.user.id_usuario, "EXCLUSAO", "processos", processId);
  });
  res.json({ ok: true });
});
app.post("/api/processes/:id/receipts", admin, (req, res) => {
  const processId = id(req.params.id);
  processRow(processId);
  const value = receiptSchema.parse(req.body);
  const receiptId = transaction(() => {
    const row = db
      .prepare(
        "INSERT INTO recebimentos(id_processo,id_usuario,dados,valor_centavos,data_recebimento) VALUES(?,?,?,?,?)",
      )
      .run(
        processId,
        req.user.id_usuario,
        pack({ observacao: value.observacao }, `recebimento:${processId}`),
        value.valor_centavos,
        value.data_recebimento,
      );
    const saved = Number(row.lastInsertRowid);
    db.prepare(
      "UPDATE processos SET data_atualizacao=CURRENT_TIMESTAMP,versao=versao+1 WHERE id_processo=?",
    ).run(processId);
    addProcessHistory(processId, req.user.id_usuario, "RECEBIMENTO_REGISTRADO");
    audit(req.user.id_usuario, "CADASTRO", "recebimentos", saved);
    return saved;
  });
  res.status(201).json({ id_recebimento: receiptId });
});
app.delete("/api/receipts/:id", admin, (req, res) => {
  const receiptId = id(req.params.id);
  transaction(() => {
    const row = db
      .prepare("SELECT id_processo FROM recebimentos WHERE id_recebimento=?")
      .get(receiptId);
    if (!row) throw fail(404, "Recebimento não encontrado.");
    db.prepare("DELETE FROM recebimentos WHERE id_recebimento=?").run(receiptId);
    db.prepare(
      "UPDATE processos SET data_atualizacao=CURRENT_TIMESTAMP,versao=versao+1 WHERE id_processo=?",
    ).run(row.id_processo);
    addProcessHistory(row.id_processo, req.user.id_usuario, "RECEBIMENTO_REMOVIDO");
    audit(req.user.id_usuario, "EXCLUSAO", "recebimentos", receiptId);
  });
  res.json({ ok: true });
});
app.post(
  "/api/processes/:id/files",
  upload.single("arquivo"),
  async (req, res) => {
    const processId = id(req.params.id);
    processRow(processId);
    const value = processFileSchema.parse(req.body);
    if (!req.file) throw fail(400, "Selecione um arquivo.");
    const detected = await fileTypeFromBuffer(req.file.buffer);
    const allowed = ["application/pdf", "image/jpeg", "image/png", "image/webp"];
    if (!detected || !allowed.includes(detected.mime))
      throw fail(400, "Envie um PDF, JPEG, PNG ou WebP válido.");
    const photo = detected.mime.startsWith("image/");
    let content = req.file.buffer;
    let thumbnail = null;
    let mime = detected.mime;
    let ext = detected.ext;
    if (photo) {
      try {
        const source = sharp(req.file.buffer, {
          failOn: "error",
          limitInputPixels: 40_000_000,
          pages: 1,
        }).rotate();
        content = await source
          .clone()
          .resize({
            width: 2400,
            height: 2400,
            fit: "inside",
            withoutEnlargement: true,
          })
          .jpeg({ quality: 86, mozjpeg: true })
          .toBuffer();
        thumbnail = await source
          .clone()
          .resize({
            width: 480,
            height: 360,
            fit: "cover",
            withoutEnlargement: true,
          })
          .jpeg({ quality: 78, mozjpeg: true })
          .toBuffer();
      } catch {
        throw fail(400, "A imagem está corrompida ou excede o limite de resolução.");
      }
      mime = "image/jpeg";
      ext = "jpg";
    }
    const original =
      req.file.originalname
        .normalize("NFKC")
        .replace(/[\x00-\x1f\x7f/\\\u202a-\u202e\u2066-\u2069]/g, "_")
        .slice(0, 200) || `arquivo.${ext}`;
    const fileId = transaction(() => {
      const row = db
        .prepare(
          "INSERT INTO arquivos_processos(id_processo,id_usuario_envio,categoria,dados,conteudo,miniatura,tamanho_bytes) VALUES(?,?,?,?,?,?,?)",
        )
        .run(
          processId,
          req.user.id_usuario,
          photo ? "FOTO" : "DOCUMENTO",
          pack({ titulo: value.titulo, nome_original: original, tipo_mime: mime, ext }, "processo-arquivo"),
          encrypt(content, `processo-arquivo:${processId}`),
          thumbnail ? encrypt(thumbnail, `processo-miniatura:${processId}`) : null,
          content.length,
        );
      const saved = Number(row.lastInsertRowid);
      db.prepare(
        "UPDATE processos SET data_atualizacao=CURRENT_TIMESTAMP,versao=versao+1 WHERE id_processo=?",
      ).run(processId);
      addProcessHistory(processId, req.user.id_usuario, "ANEXO_INCLUIDO", {
        categoria: photo ? "FOTO" : "DOCUMENTO",
      });
      audit(req.user.id_usuario, "CADASTRO", "arquivos_processos", saved);
      return saved;
    });
    res.status(201).json({ id_arquivo: fileId });
  },
);
function processFile(fileId) {
  const row = db
    .prepare("SELECT * FROM arquivos_processos WHERE id_arquivo=?")
    .get(fileId);
  if (!row) throw fail(404, "Anexo não encontrado.");
  return row;
}
app.get("/api/process-files/:id/download", (req, res) => {
  const fileId = id(req.params.id);
  const row = processFile(fileId);
  const meta = unpack(row.dados, "processo-arquivo");
  audit(req.user.id_usuario, "LEITURA", "arquivos_processos", fileId);
  res
    .attachment(`processo-${row.id_processo}-anexo-${fileId}.${meta.ext}`)
    .type(meta.tipo_mime)
    .send(decrypt(row.conteudo, `processo-arquivo:${row.id_processo}`));
});
app.get("/api/process-files/:id/preview", (req, res) => {
  const row = processFile(id(req.params.id));
  if (row.categoria !== "FOTO" || !row.miniatura)
    throw fail(404, "Prévia não disponível.");
  res
    .set("Content-Disposition", "inline")
    .type("image/jpeg")
    .send(decrypt(row.miniatura, `processo-miniatura:${row.id_processo}`));
});
app.delete("/api/process-files/:id", admin, (req, res) => {
  const fileId = id(req.params.id);
  transaction(() => {
    const row = processFile(fileId);
    db.prepare("DELETE FROM arquivos_processos WHERE id_arquivo=?").run(fileId);
    db.prepare(
      "UPDATE processos SET data_atualizacao=CURRENT_TIMESTAMP,versao=versao+1 WHERE id_processo=?",
    ).run(row.id_processo);
    addProcessHistory(row.id_processo, req.user.id_usuario, "ANEXO_REMOVIDO");
    audit(req.user.id_usuario, "EXCLUSAO", "arquivos_processos", fileId);
  });
  res.json({ ok: true });
});
app.get("/api/users", admin, (req, res) =>
  res.json(
    db
      .prepare("SELECT * FROM usuarios ORDER BY id_usuario")
      .all()
      .map(publicUser),
  ),
);
async function saveUser(req, res) {
  const v = userSchema.parse(req.body),
    userId = req.params.id ? id(req.params.id) : null;
  if (!userId && !v.senha) throw fail(400, "Informe a senha inicial.");
  if (
    userId === req.user.id_usuario &&
    (!v.ativo || v.perfil !== "ADMINISTRADOR")
  )
    throw fail(
      400,
      "Você não pode remover seu próprio acesso de administrador.",
    );
  const hash = v.senha ? await hashPassword(v.senha) : null;
  const saved = transaction(() => {
    let result = userId;
    if (userId) {
      const old = db
        .prepare("SELECT * FROM usuarios WHERE id_usuario=?")
        .get(userId);
      if (!old) throw fail(404, "Usuário não encontrado.");
      const oldData = unpack(old.dados, "usuario");
      if (
        old.ativo &&
        old.perfil === "ADMINISTRADOR" &&
        (!v.ativo || v.perfil !== "ADMINISTRADOR") &&
        db
          .prepare(
            "SELECT count(*) n FROM usuarios WHERE ativo=1 AND perfil='ADMINISTRADOR'",
          )
          .get().n <= 1
      )
        throw fail(409, "Mantenha ao menos um administrador ativo.");
      db.prepare(
        "UPDATE usuarios SET dados=?,email_indice=?,senha_hash=?,perfil=?,ativo=?,data_atualizacao=CURRENT_TIMESTAMP WHERE id_usuario=?",
      ).run(
        pack(
          {
            nome: v.nome,
            email: v.email,
            ...(oldData.preferencias
              ? { preferencias: oldData.preferencias }
              : {}),
          },
          "usuario",
        ),
        index(v.email),
        hash || old.senha_hash,
        v.perfil,
        +v.ativo,
        userId,
      );
      db.prepare("DELETE FROM sessoes WHERE id_usuario=?").run(userId);
      db.prepare("DELETE FROM desafios_mfa WHERE id_usuario=?").run(userId);
    } else
      result = Number(
        db
          .prepare(
            "INSERT INTO usuarios(dados,email_indice,senha_hash,perfil,ativo) VALUES(?,?,?,?,?)",
          )
          .run(
            pack(
              {
                nome: v.nome,
                email: v.email,
              },
              "usuario",
            ),
            index(v.email),
            hash,
            v.perfil,
            +v.ativo,
          ).lastInsertRowid,
      );
    audit(
      req.user.id_usuario,
      userId ? "ALTERACAO" : "CADASTRO",
      "usuarios",
      result,
    );
    return result;
  });
  res.status(userId ? 200 : 201).json({ id_usuario: saved });
}
app.post("/api/users", admin, saveUser);
app.put("/api/users/:id", admin, saveUser);
app.get("/api/audit", admin, (req, res) => {
  const page = Math.max(1, Math.min(100000, Number(req.query.page) || 1));
  res.json({
    page,
    total: db.prepare("SELECT count(*) n FROM logs_auditoria").get().n,
    items: db
      .prepare(
        "SELECT l.*,u.dados FROM logs_auditoria l JOIN usuarios u ON u.id_usuario=l.id_usuario ORDER BY id_log DESC LIMIT 50 OFFSET ?",
      )
      .all((page - 1) * 50)
      .map(({ dados, ...r }) => ({
        ...r,
        usuario: unpack(dados, "usuario").nome,
      })),
  });
});
app.use("/api", (req, res) =>
  res.status(404).json({ error: "Recurso não encontrado." }),
);
const publicRoot = fileURLToPath(new URL("../", import.meta.url));
app.get("/", (req, res) =>
  res
    .set("Cache-Control", "no-store")
    .sendFile("index.html", { root: publicRoot, dotfiles: "deny" }),
);
app.get("/style.css", (req, res) =>
  res
    .set("Cache-Control", "no-cache")
    .sendFile("style.css", { root: publicRoot, dotfiles: "deny" }),
);
app.get("/bootstrap.js", (req, res) =>
  res
    .set("Cache-Control", "no-store")
    .sendFile("bootstrap.js", { root: publicRoot, dotfiles: "deny" }),
);
app.get(
  "/assets/application.js",
  (req, res, next) => {
    res.set({ "Cache-Control": "private, no-store", Vary: "Cookie" });
    next();
  },
  auth,
  (req, res) =>
    res.sendFile("app.js", { root: publicRoot, dotfiles: "deny" }),
);
app.use((req, res) =>
  res.status(404).type("text/plain").send("Recurso não encontrado."),
);
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error.name === "ZodError")
    return res
      .status(400)
      .json({
        error: "Verifique os campos informados.",
        details: error.issues.map((x) => ({
          campo: x.path.join("."),
          mensagem: x.message,
        })),
      });
  if (error.type === "entity.parse.failed")
    return res.status(400).json({ error: "Formato JSON inválido." });
  if (error instanceof multer.MulterError)
    return res
      .status(400)
      .json({
        error: "Envie um único arquivo de até 10 MB, com título e categoria.",
      });
  if (
    error.code?.startsWith("SQLITE_CONSTRAINT") ||
    String(error.message).includes("UNIQUE constraint failed")
  )
    return res
      .status(409)
      .json({
        error: "CPF/CNPJ, número do processo, e-mail ou contato já cadastrado.",
      });
  const status = error.status || 500;
  if (status >= 500)
    console.error(
      `Falha interna [${req.requestId || "sem-id"}]:`,
      error.code || error.name,
    );
  res
    .status(status)
    .json({
      error:
        status >= 500
          ? "Não foi possível concluir a operação."
          : status === 413
            ? "Dados enviados excedem o limite."
            : error.message,
    });
});
