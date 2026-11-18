const crypto = require("crypto");
const express = require("express");
const rateLimit = require("express-rate-limit");
const path = require("path");

const PORT = Number(process.env.PORT || 28100);
const AUTH_USERNAME = process.env.ST_AUTH_USERNAME || process.env.AUTH_USERNAME || "";
const AUTH_PASSWORD = process.env.ST_AUTH_PASSWORD || process.env.AUTH_PASSWORD || "";
const COOKIE_SECRET = process.env.ST_AUTH_COOKIE_SECRET || process.env.AUTH_COOKIE_SECRET || "";
const COOKIE_NAME = process.env.ST_AUTH_COOKIE_NAME || "pa_session";
const SESSION_TTL_SECONDS = Number(process.env.ST_AUTH_SESSION_TTL_SECONDS || 12 * 60 * 60);
const REMEMBER_TTL_SECONDS = Number(process.env.ST_AUTH_REMEMBER_TTL_SECONDS || 30 * 24 * 60 * 60);

if (!AUTH_USERNAME || !AUTH_PASSWORD || !COOKIE_SECRET) {
  console.error("Missing required envs: ST_AUTH_USERNAME, ST_AUTH_PASSWORD, ST_AUTH_COOKIE_SECRET");
  process.exit(1);
}

function safeEquals(a, b) {
  const left = Buffer.from(String(a), "utf8");
  const right = Buffer.from(String(b), "utf8");
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function sign(payload) {
  return crypto.createHmac("sha256", COOKIE_SECRET).update(payload).digest("base64url");
}

function parseCookies(header) {
  const result = {};
  if (!header) return result;

  for (const part of String(header).split(";")) {
    const sep = part.indexOf("=");
    if (sep < 0) continue;
    const key = part.slice(0, sep).trim();
    const value = part.slice(sep + 1).trim();
    if (!key) continue;
    try {
      result[key] = decodeURIComponent(value);
    } catch {
      result[key] = value;
    }
  }

  return result;
}

function createToken(maxAgeSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(JSON.stringify({
    sub: AUTH_USERNAME,
    iat: now,
    exp: now + maxAgeSeconds,
  }));
  return `${payload}.${sign(payload)}`;
}

function verifyToken(token) {
  if (!token || typeof token !== "string") return false;

  const sep = token.indexOf(".");
  if (sep < 0) return false;

  const payload = token.slice(0, sep);
  const signature = token.slice(sep + 1);
  if (!safeEquals(signature, sign(payload))) return false;

  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);
  return parsed
    && parsed.sub === AUTH_USERNAME
    && Number.isFinite(parsed.exp)
    && parsed.exp > now;
}

function isAuthenticated(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifyToken(cookies[COOKIE_NAME]);
}

function isSafeNext(next) {
  return typeof next === "string"
    && next.startsWith("/")
    && !next.startsWith("//")
    && !next.includes("\r")
    && !next.includes("\n");
}

function normalizeNext(next) {
  return isSafeNext(next) ? next : "/";
}

function htmlEscape(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

function renderLoginPage({ next = "/", error = false } = {}) {
  const safeNext = normalizeNext(next);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Private Access</title>
  <link rel="stylesheet" href="/__pa_assets/style.css">
</head>
<body>
  <main class="card">
    <h1>Private Access</h1>
    <p class="desc">Sign in to continue.</p>
    ${error ? '<p class="notice notice-error">Invalid credentials.</p>' : ""}
    <form method="post" action="/__pa_login" autocomplete="on">
      <input type="hidden" name="next" value="${htmlEscape(safeNext)}">
      <label>
        Username
        <input type="text" name="username" autocomplete="username" autofocus required>
      </label>
      <label>
        Password
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <label class="remember">
        <input type="checkbox" name="remember" value="1">
        Keep me signed in
      </label>
      <button type="submit">Continue</button>
    </form>
  </main>
</body>
</html>`;
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use("/assets", express.static(path.join(__dirname, "public"), {
  immutable: true,
  maxAge: "1h",
}));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

app.get("/__health", (_req, res) => {
  res.status(200).json({ ok: true });
});

app.get("/__auth", (req, res) => {
  const authenticated = isAuthenticated(req);
  const originalUri = String(req.get("x-original-uri") || "");

  if (originalUri.startsWith("/api/backends/chat-completions/generate")) {
    console.log(JSON.stringify({
      event: "auth_check",
      method: String(req.get("x-original-method") || "UNKNOWN"),
      uri: originalUri,
      status: authenticated ? 204 : 401,
    }));
  }

  res.sendStatus(authenticated ? 204 : 401);
});

app.get("/login", (req, res) => {
  if (isAuthenticated(req)) {
    res.redirect(302, normalizeNext(req.query.next));
    return;
  }

  res.status(200).type("html").send(renderLoginPage({ next: req.query.next }));
});

app.post("/login", rateLimit({
  windowMs: 60 * 1000,
  limit: 12,
  standardHeaders: true,
  legacyHeaders: false,
}), (req, res) => {
  const username = req.body?.username || "";
  const password = req.body?.password || "";
  const next = normalizeNext(req.body?.next);

  if (!safeEquals(username, AUTH_USERNAME) || !safeEquals(password, AUTH_PASSWORD)) {
    res.status(401).type("html").send(renderLoginPage({ next, error: true }));
    return;
  }

  const maxAgeSeconds = req.body?.remember === "1" ? REMEMBER_TTL_SECONDS : SESSION_TTL_SECONDS;
  const token = createToken(maxAgeSeconds);
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: maxAgeSeconds * 1000,
  });
  res.redirect(302, next);
});

app.get("/logout", (_req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
  });
  res.redirect(302, "/__pa_login");
});

app.use((_req, res) => {
  res.sendStatus(404);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`auth-gateway listening on ${PORT}`);
});
