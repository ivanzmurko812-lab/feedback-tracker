import express from "express";
import multer from "multer";
import pg from "pg";
import XLSX from "xlsx";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "10mb" }));

const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } });
const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_RENDER_ENV";
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

// limits (защита от нагрузки)
const MAX_PAGE_SIZE = 50;       // /api/records
const MAX_EXPORT_ROWS = 5000;   // /api/records-export
const MAX_LEADERBOARD = 200;    // /api/audit-leaderboard
const MAX_USER_LEADERBOARD = 200; // /api/user-leaderboard

function uuid() {
  return crypto.randomUUID();
}
function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input));
  return buf
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signJWT(payload) {
  const header = { alg: "HS256", typ: "JWT" };
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + TOKEN_TTL_SECONDS;
  const body = { ...payload, iat, exp };

  const h = base64url(JSON.stringify(header));
  const b = base64url(JSON.stringify(body));
  const data = `${h}.${b}`;
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(data).digest();
  return `${data}.${base64url(sig)}`;
}

function verifyJWT(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const data = `${h}.${b}`;
  const expected = base64url(
    crypto.createHmac("sha256", JWT_SECRET).update(data).digest()
  );
  if (expected !== s) return null;

  let payload;
  try {
    payload = JSON.parse(
      Buffer.from(b.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")
    );
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) return null;
  return payload;
}

function authRequired(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  const payload = verifyJWT(token);
  if (!payload) return res.status(401).json({ error: "unauthorized" });
  req.user = payload; // {userId, login, role}
  next();
}

function roleRequired(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "unauthorized" });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "forbidden" });
    next();
  };
}

/** =========================================================
 *  Simple rate limiter (in-memory)
 *  ========================================================= */
function createRateLimiter({ windowMs, max }) {
  const map = new Map(); // key -> {count, resetAt}
  return (key) => {
    const now = Date.now();
    const cur = map.get(key);
    if (!cur || now > cur.resetAt) {
      map.set(key, { count: 1, resetAt: now + windowMs });
      return { ok: true, remaining: max - 1 };
    }
    cur.count += 1;
    if (cur.count > max) return { ok: false, remaining: 0 };
    return { ok: true, remaining: max - cur.count };
  };
}

const apiLimiter = createRateLimiter({ windowMs: 60_000, max: 120 });       // 120 req/min per IP
const loginLimiter = createRateLimiter({ windowMs: 10 * 60_000, max: 12 }); // 12 attempts / 10 min per IP

app.use("/api", (req, res, next) => {
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "ip";
  const r = apiLimiter(ip);
  if (!r.ok) return res.status(429).json({ error: "rate limit" });
  next();
});

/** =========================================================
 *  Excel date/time helpers
 *  ========================================================= */
function excelSerialToJsDate(serial) {
  const d = XLSX.SSF.parse_date_code(serial);
  if (!d || !d.y || !d.m || !d.d) return null;

  const ms = Date.UTC(d.y, d.m - 1, d.d, d.H || 0, d.M || 0, Math.floor(d.S || 0));
  return new Date(ms);
}

function toPgDate(value) {
  if (value === null || value === undefined) return null;

  if (typeof value === "number" && isFinite(value)) {
    const jsd = excelSerialToJsDate(value);
    if (!jsd) return null;
    return jsd.toISOString().slice(0, 10);
  }

  if (value instanceof Date && !isNaN(value)) {
    return value.toISOString().slice(0, 10);
  }

  const s = String(value).trim();
  if (!s) return null;

  const m1 = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m1) return `${m1[1]}-${m1[2]}-${m1[3]}`;

  const m2 = s.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})$/);
  if (m2) {
    const dd = m2[1].padStart(2, "0");
    const mm = m2[2].padStart(2, "0");
    const yy = m2[3];
    return `${yy}-${mm}-${dd}`;
  }

  const t = Date.parse(s);
  if (!isNaN(t)) return new Date(t).toISOString().slice(0, 10);

  return null;
}

function toPgTimestamp(value) {
  if (value === null || value === undefined) return null;

  if (typeof value === "number" && isFinite(value)) {
    const jsd = excelSerialToJsDate(value);
    if (!jsd) return null;
    return jsd.toISOString();
  }

  if (value instanceof Date && !isNaN(value)) {
    return value.toISOString();
  }

  const s = String(value).trim();
  if (!s) return null;

  const t = Date.parse(s);
  if (!isNaN(t)) return new Date(t).toISOString();

  return null;
}

function blacklistWhere(alias = "records") {
  return `NOT EXISTS (SELECT 1 FROM blacklist bl WHERE bl.login = ${alias}.person_login)`;
}

function clampInt(v, min, max, fallback) {
  const n = parseInt(String(v ?? ""), 10);
  if (!isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}


function normalizeDp(value) {
  const s = String(value ?? "").trim().toUpperCase().replace(/\s+/g, "");
  if (!s || s === "ALL") return null;
  if (s === "DP1" || s === "1" || s === "DP01") return "DP1";
  if (s === "DP2" || s === "2" || s === "DP02") return "DP2";
  if (s.startsWith("DP")) {
    const m = s.match(/^DP(\d+)$/);
    if (m) return `DP${m[1]}`;
  }
  return s;
}

function normalizeSide(value) {
  const s = String(value ?? "").trim().toUpperCase().replace(/\s+/g, "");
  if (!s || s === "ALL") return null;
  if (s === "GEEK" || s === "GEEK+") return "GEEK+";
  if (s === "HAI") return "HAI";
  return s;
}

function findHeaderIndexes(header, name) {
  const target = String(name || "").trim().toLowerCase();
  const out = [];
  for (let i = 0; i < header.length; i++) {
    if (String(header[i] || "").trim().toLowerCase() === target) out.push(i);
  }
  return out;
}

function findBlockColumn(header, startIdx, nextStartIdx, names) {
  for (let i = startIdx + 1; i < nextStartIdx; i++) {
    const cur = String(header[i] || "").trim().toLowerCase();
    if (names.includes(cur)) return i;
  }
  return -1;
}

/** =========================================================
 *  DB init
 *  ========================================================= */
async function initDatabase() {
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;

    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      login text UNIQUE NOT NULL,
      pass_hash text NOT NULL,
      role text NOT NULL CHECK (role IN ('admin','manager')),
      created_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS imports (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      creator_login text NOT NULL,
      uploaded_at timestamptz NOT NULL DEFAULT now(),
      rows_count integer NOT NULL DEFAULT 0,
      mime text NOT NULL,
      bytes bytea NOT NULL
    );

    CREATE TABLE IF NOT EXISTS blacklist (
      login text PRIMARY KEY,
      note text,
      created_by text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS records (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      type text NOT NULL CHECK (type IN ('shortpick','audit_pick','audit_pa')),
      date date,
      time timestamptz,
      person_login text,
      task_order text,
      sku text,
      box_number text,
      container text,
      auditor text,
      result text,
      dp text,
      side text,
      import_id uuid REFERENCES imports(id) ON DELETE SET NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    ALTER TABLE records ADD COLUMN IF NOT EXISTS dp text;
    ALTER TABLE records ADD COLUMN IF NOT EXISTS side text;

    CREATE INDEX IF NOT EXISTS idx_records_type_date ON records(type, date);
    CREATE INDEX IF NOT EXISTS idx_records_login_date ON records(person_login, date);
    CREATE INDEX IF NOT EXISTS idx_records_import_id ON records(import_id);
    CREATE INDEX IF NOT EXISTS idx_records_type_result_date ON records(type, lower(result), date);
  `);

  // seed admin: 60078903 / 123456
  const adminLogin = "60078903";
  const adminHash = sha256Hex("123456");

  await pool.query(
    `
    INSERT INTO users (login, pass_hash, role)
    VALUES ($1, $2, 'admin')
    ON CONFLICT (login) DO UPDATE SET role='admin', pass_hash=EXCLUDED.pass_hash;
  `,
    [adminLogin, adminHash]
  );

  console.log("Database initialized");
}

/** =========================================================
 *  API
 *  ========================================================= */
app.get("/api/health", (req, res) => res.json({ ok: true }));

// AUTH
app.post("/api/auth/login", async (req, res) => {
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "ip";

  const rl = loginLimiter(ip);
  if (!rl.ok) return res.status(429).json({ error: "too many login attempts" });

  const { login, password } = req.body || {};
  if (!login || !password) return res.status(400).json({ error: "missing login/password" });

  const q = await pool.query(`SELECT id,login,pass_hash,role FROM users WHERE login=$1`, [
    String(login).trim(),
  ]);
  const u = q.rows[0];
  if (!u) return res.status(401).json({ error: "invalid credentials" });

  if (sha256Hex(password) !== u.pass_hash) return res.status(401).json({ error: "invalid credentials" });

  const token = signJWT({ userId: u.id, login: u.login, role: u.role });
  res.json({ token, user: { id: u.id, login: u.login, role: u.role } });
});

app.post("/api/auth/change-password", authRequired, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "missing fields" });

  const q = await pool.query(`SELECT pass_hash FROM users WHERE id=$1`, [req.user.userId]);
  const u = q.rows[0];
  if (!u) return res.status(404).json({ error: "user not found" });

  if (sha256Hex(currentPassword) !== u.pass_hash) return res.status(401).json({ error: "wrong password" });

  await pool.query(`UPDATE users SET pass_hash=$1 WHERE id=$2`, [
    sha256Hex(newPassword),
    req.user.userId,
  ]);
  res.json({ ok: true });
});

// USERS
app.get("/api/users", authRequired, roleRequired("admin", "manager"), async (req, res) => {
  const q = await pool.query(`SELECT id,login,role,created_at FROM users ORDER BY created_at DESC`);
  res.json({ rows: q.rows });
});

app.post("/api/users", authRequired, roleRequired("admin", "manager"), async (req, res) => {
  const me = req.user;
  const { login, password, role } = req.body || {};
  if (!login || !password) return res.status(400).json({ error: "missing login/password" });

  const r = String(role || "manager");
  if (me.role === "manager" && r === "admin") return res.status(403).json({ error: "manager cannot create admin" });

  try {
    const ins = await pool.query(
      `INSERT INTO users(login,pass_hash,role) VALUES($1,$2,$3) RETURNING id`,
      [String(login).trim(), sha256Hex(password), r]
    );
    res.json({ ok: true, id: ins.rows[0].id });
  } catch (e) {
    if (String(e?.message || "").toLowerCase().includes("unique"))
      return res.status(409).json({ error: "login exists" });
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.put("/api/users/:id", authRequired, roleRequired("admin", "manager"), async (req, res) => {
  const me = req.user;
  const id = req.params.id;
  const { role, password } = req.body || {};

  const q = await pool.query(`SELECT id,role FROM users WHERE id=$1`, [id]);
  const target = q.rows[0];
  if (!target) return res.status(404).json({ error: "not found" });

  if (me.role === "manager" && target.role === "admin")
    return res.status(403).json({ error: "manager cannot edit admin" });
  if (me.role === "manager" && role === "admin")
    return res.status(403).json({ error: "manager cannot set admin" });

  const sets = [];
  const vals = [];
  const add = (sql, v) => {
    vals.push(v);
    sets.push(sql.replace("?", `$${vals.length}`));
  };

  if (role) add(`role = ?`, String(role));
  if (password) add(`pass_hash = ?`, sha256Hex(password));

  if (!sets.length) return res.json({ ok: true });

  vals.push(id);
  await pool.query(`UPDATE users SET ${sets.join(", ")} WHERE id=$${vals.length}`, vals);
  res.json({ ok: true });
});

app.delete("/api/users/:id", authRequired, roleRequired("admin", "manager"), async (req, res) => {
  const me = req.user;
  const id = req.params.id;

  if (String(me.userId) === String(id)) return res.status(400).json({ error: "cannot delete self" });

  const q = await pool.query(`SELECT role FROM users WHERE id=$1`, [id]);
  const target = q.rows[0];
  if (!target) return res.status(404).json({ error: "not found" });

  if (me.role === "manager" && target.role === "admin")
    return res.status(403).json({ error: "manager cannot delete admin" });

  await pool.query(`DELETE FROM users WHERE id=$1`, [id]);
  res.json({ ok: true });
});

// RECORDS (paged)
app.get("/api/records", authRequired, async (req, res) => {
  const { type, login, from, to, result, side, dp, page = "1", pageSize = "25" } = req.query;

  const p = clampInt(page, 1, 1_000_000, 1);
  const ps = clampInt(pageSize, 1, MAX_PAGE_SIZE, 25);
  const offset = (p - 1) * ps;

  const where = [];
  const vals = [];
  const add = (sql, v) => {
    vals.push(v);
    where.push(sql.replace("?", `$${vals.length}`));
  };

  if (type) add(`type = ?`, String(type));
  if (login) add(`person_login = ?`, String(login).trim());
  if (from) add(`date >= ?`, String(from));
  if (to) add(`date <= ?`, String(to));
  if (result && result !== "all") add(`LOWER(result) = ?`, String(result).toLowerCase());
  if (side && side !== "all") add(`side = ?`, normalizeSide(side));
  if (dp && dp !== "all") add(`dp = ?`, normalizeDp(dp));
  where.push(blacklistWhere("records"));

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const total = await pool.query(`SELECT COUNT(*)::int AS c FROM records ${whereSql}`, vals);
  const rows = await pool.query(
    `SELECT * FROM records ${whereSql}
     ORDER BY date DESC NULLS LAST, time DESC NULLS LAST, created_at DESC
     LIMIT ${ps} OFFSET ${offset}`,
    vals
  );

  res.json({ page: p, pageSize: ps, total: total.rows[0].c, rows: rows.rows });
});

// RECORDS EXPORT (limited)
app.get("/api/records-export", authRequired, async (req, res) => {
  const { type, login, from, to, result, side, dp } = req.query;

  const where = [];
  const vals = [];
  const add = (sql, v) => {
    vals.push(v);
    where.push(sql.replace("?", `$${vals.length}`));
  };

  if (type) add(`type = ?`, String(type));
  if (login) add(`person_login = ?`, String(login).trim());
  if (from) add(`date >= ?`, String(from));
  if (to) add(`date <= ?`, String(to));
  if (result && result !== "all") add(`LOWER(result) = ?`, String(result).toLowerCase());
  if (side && side !== "all") add(`side = ?`, normalizeSide(side));
  if (dp && dp !== "all") add(`dp = ?`, normalizeDp(dp));
  where.push(blacklistWhere("records"));

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const rowsQ = await pool.query(
    `SELECT * FROM records ${whereSql}
     ORDER BY date DESC NULLS LAST, time DESC NULLS LAST, created_at DESC
     LIMIT ${MAX_EXPORT_ROWS + 1}`,
    vals
  );

  const truncated = rowsQ.rows.length > MAX_EXPORT_ROWS;
  const rows = truncated ? rowsQ.rows.slice(0, MAX_EXPORT_ROWS) : rowsQ.rows;

  res.json({ rows, truncated, limit: MAX_EXPORT_ROWS });
});

// USER SUMMARY (возвращаем и total и all)
app.get("/api/user-summary", authRequired, async (req, res) => {
  const { login, from, to, side, dp } = req.query;

  const where = [];
  const vals = [];
  const add = (sql, v) => {
    vals.push(v);
    where.push(sql.replace("?", `$${vals.length}`));
  };

  if (login) add(`person_login = ?`, String(login).trim());
  if (from) add(`date >= ?`, String(from));
  if (to) add(`date <= ?`, String(to));
  if (side && side !== "all") add(`side = ?`, normalizeSide(side));
  if (dp && dp !== "all") add(`dp = ?`, normalizeDp(dp));
  where.push(blacklistWhere("records"));
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const grouped = await pool.query(
    `SELECT date, COUNT(*)::int AS count
     FROM records ${whereSql}
     GROUP BY date
     ORDER BY date DESC`,
    vals
  );

  const sp = await pool.query(
    `SELECT COUNT(*)::int AS c FROM records ${whereSql} ${whereSql ? "AND" : "WHERE"} type='shortpick'`,
    vals
  );

  const ap = await pool.query(
    `SELECT
      COUNT(*)::int AS total,
      COUNT(*)::int AS "all",
      SUM(CASE WHEN LOWER(result)='profit' THEN 1 ELSE 0 END)::int AS profit,
      SUM(CASE WHEN LOWER(result)='loss' THEN 1 ELSE 0 END)::int AS loss,
      0::int AS occupied
     FROM records ${whereSql} ${whereSql ? "AND" : "WHERE"} type='audit_pick'`,
    vals
  );

  const pa = await pool.query(
    `SELECT
      COUNT(*)::int AS total,
      COUNT(*)::int AS "all",
      SUM(CASE WHEN LOWER(result)='profit' THEN 1 ELSE 0 END)::int AS profit,
      SUM(CASE WHEN LOWER(result)='loss' THEN 1 ELSE 0 END)::int AS loss,
      SUM(CASE WHEN LOWER(result)='occupied' THEN 1 ELSE 0 END)::int AS occupied
     FROM records ${whereSql} ${whereSql ? "AND" : "WHERE"} type='audit_pa'`,
    vals
  );

  res.json({
    grouped: grouped.rows,
    shortpick: sp.rows[0].c,
    audit_pick: ap.rows[0],
    audit_pa: pa.rows[0],
  });
});

// USER LEADERBOARD (Top by user across all types)
app.get("/api/user-leaderboard", authRequired, async (req, res) => {
  const { login, from, to, side, dp, orderBy="total", orderDir="desc", limit="25" } = req.query;

  const lim = clampInt(limit, 1, MAX_USER_LEADERBOARD, 25);

  const allowedOrder = new Set(["login","shortpick","audit_pick","audit_pa","total"]);
  const ob = allowedOrder.has(String(orderBy)) ? String(orderBy) : "total";
  const od = String(orderDir).toLowerCase() === "asc" ? "asc" : "desc";

  const where = [];
  const vals = [];
  let i = 1;

  if (login) { where.push(`person_login = $${i++}`); vals.push(String(login).trim()); }
  if (from) { where.push(`date >= $${i++}`); vals.push(String(from)); }
  if (to) { where.push(`date <= $${i++}`); vals.push(String(to)); }
  if (side && side !== "all") { where.push(`side = $${i++}`); vals.push(normalizeSide(side)); }
  if (dp && dp !== "all") { where.push(`dp = $${i++}`); vals.push(normalizeDp(dp)); }
  where.push(blacklistWhere("records"));

  const whereSql = where.length ? `WHERE ${where.join(" AND ")} AND COALESCE(person_login,'') <> ''`
                                : `WHERE COALESCE(person_login,'') <> ''`;

  const orderSql = ob === "login" ? `login ${od}, total DESC` : `${ob} ${od}, total DESC`;

  const sql = `
    SELECT
      COALESCE(person_login,'') AS login,
      SUM(CASE WHEN type='shortpick' THEN 1 ELSE 0 END)::int AS shortpick,
      SUM(CASE WHEN type='audit_pick' THEN 1 ELSE 0 END)::int AS audit_pick,
      SUM(CASE WHEN type='audit_pa' THEN 1 ELSE 0 END)::int AS audit_pa,
      COUNT(*)::int AS total
    FROM records
    ${whereSql}
    GROUP BY person_login
    ORDER BY ${orderSql}
    LIMIT ${lim}
  `;

  const q = await pool.query(sql, vals);
  res.json({ rows: q.rows });
});

// LEADERBOARD (возвращаем и total и all, и поддерживаем orderBy=all)
app.get("/api/audit-leaderboard", authRequired, async (req, res) => {
  const {
    type,
    from,
    to,
    result = "all",
    side,
    dp,
    orderBy = "all",
    orderDir = "desc",
    limit = "200",
  } = req.query;

  const t = String(type || "");
  if (!["audit_pick", "audit_pa"].includes(t)) return res.status(400).json({ error: "bad type" });

  const lim = clampInt(limit, 1, MAX_LEADERBOARD, 200);

  // разрешаем all, но сортируем по total (all = total)
  const allowedOrder = new Set(["login", "profit", "loss", "occupied", "total", "all"]);
  const ob = allowedOrder.has(String(orderBy)) ? String(orderBy) : "all";
  const ob2 = ob === "all" ? "total" : ob;
  const od = String(orderDir).toLowerCase() === "asc" ? "asc" : "desc";

  const where = [`type = $1`];
  const vals = [t];
  let i = 2;

  if (from) { where.push(`date >= $${i++}`); vals.push(String(from)); }
  if (to) { where.push(`date <= $${i++}`); vals.push(String(to)); }
  if (result && result !== "all") { where.push(`LOWER(result) = $${i++}`); vals.push(String(result).toLowerCase()); }
  if (side && side !== "all") { where.push(`side = $${i++}`); vals.push(normalizeSide(side)); }
  if (dp && dp !== "all") { where.push(`dp = $${i++}`); vals.push(normalizeDp(dp)); }
  where.push(blacklistWhere("records"));

  const whereSql = `WHERE ${where.join(" AND ")}`;

  const occupiedExpr =
    t === "audit_pa"
      ? `SUM(CASE WHEN LOWER(result)='occupied' THEN 1 ELSE 0 END)::int`
      : `0::int`;

  const orderSql =
    ob2 === "login"
      ? `login ${od}, total DESC`
      : `${ob2} ${od}, total DESC`;

  const sql = `
    SELECT
      COALESCE(person_login,'') AS login,
      COUNT(*)::int AS total,
      COUNT(*)::int AS "all",
      SUM(CASE WHEN LOWER(result)='profit' THEN 1 ELSE 0 END)::int AS profit,
      SUM(CASE WHEN LOWER(result)='loss' THEN 1 ELSE 0 END)::int AS loss,
      ${occupiedExpr} AS occupied
    FROM records
    ${whereSql}
    GROUP BY person_login
    HAVING COALESCE(person_login,'') <> ''
    ORDER BY ${orderSql}
    LIMIT ${lim}
  `;

  const q = await pool.query(sql, vals);
  res.json({ rows: q.rows });
});

// BLACKLIST
app.get("/api/blacklist", authRequired, roleRequired("admin", "manager"), async (req, res) => {
  const q = await pool.query(`SELECT login, note, created_by, created_at FROM blacklist ORDER BY created_at DESC, login ASC`);
  res.json({ rows: q.rows });
});

app.post("/api/blacklist", authRequired, roleRequired("admin", "manager"), async (req, res) => {
  const login = String(req.body?.login || "").trim();
  const note = String(req.body?.note || "").trim();
  if (!login) return res.status(400).json({ error: "missing login" });

  await pool.query(
    `INSERT INTO blacklist(login, note, created_by, created_at)
     VALUES($1,$2,$3,now())
     ON CONFLICT (login) DO UPDATE SET note = EXCLUDED.note, created_by = EXCLUDED.created_by, created_at = now()`,
    [login, note || null, req.user.login]
  );
  res.json({ ok: true });
});

app.delete("/api/blacklist/:login", authRequired, roleRequired("admin", "manager"), async (req, res) => {
  const login = String(req.params.login || "").trim();
  await pool.query(`DELETE FROM blacklist WHERE login=$1`, [login]);
  res.json({ ok: true });
});

// IMPORTS
app.get("/api/imports", authRequired, roleRequired("admin"), async (req, res) => {
  const q = await pool.query(
    `SELECT id,name,creator_login,uploaded_at,rows_count
     FROM imports ORDER BY uploaded_at DESC`
  );
  res.json({ rows: q.rows });
});

app.get("/api/imports/:id/file", authRequired, roleRequired("admin"), async (req, res) => {
  const id = req.params.id;
  const q = await pool.query(`SELECT name,mime,bytes FROM imports WHERE id=$1`, [id]);
  const im = q.rows[0];
  if (!im) return res.status(404).json({ error: "not found" });

  res.setHeader("Content-Type", im.mime || "application/octet-stream");
  res.setHeader("Content-Disposition", `attachment; filename="${im.name || "import.xlsx"}"`);
  res.send(im.bytes);
});

app.delete("/api/imports/:id", authRequired, roleRequired("admin"), async (req, res) => {
  const id = req.params.id;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`DELETE FROM records WHERE import_id=$1`, [id]);
    await client.query(`DELETE FROM imports WHERE id=$1`, [id]);
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    return res.status(500).json({ error: "delete failed" });
  } finally {
    client.release();
  }
  res.json({ ok: true });
});

app.post("/api/import", authRequired, roleRequired("admin"), upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "no file" });

  let data;
  try {
    const wb = XLSX.read(req.file.buffer, { type: "buffer" });
    const ws = wb.Sheets[wb.SheetNames[0]];
    data = XLSX.utils.sheet_to_json(ws, { header: 1, defval: "", raw: true });
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: "bad excel" });
  }

  const header = (data[0] || []).map((x) => String(x || "").trim());

  const colAP = header.indexOf("Audit pick");
  const colSP = header.indexOf("Shortpick");
  const colPA = header.indexOf("Audit PA");

  const blockStarts = [colAP, colSP, colPA].filter((x) => x >= 0).sort((a, b) => a - b);
  const nextBlockStart = (start) => {
    const bigger = blockStarts.find((x) => x > start);
    return bigger >= 0 ? bigger : header.length;
  };

  const apNext = nextBlockStart(colAP);
  const spNext = nextBlockStart(colSP);
  const paNext = nextBlockStart(colPA);

  const apDpCol = colAP >= 0 ? findBlockColumn(header, colAP, apNext, ["dp", "dep."]) : -1;
  const apSideCol = colAP >= 0 ? findBlockColumn(header, colAP, apNext, ["side"]) : -1;

  const spDpCol = colSP >= 0 ? findBlockColumn(header, colSP, spNext, ["dp", "dep."]) : -1;
  const spSideCol = colSP >= 0 ? findBlockColumn(header, colSP, spNext, ["side"]) : -1;

  const paDpCol = colPA >= 0 ? findBlockColumn(header, colPA, paNext, ["dp", "dep."]) : -1;
  const paSideCol = colPA >= 0 ? findBlockColumn(header, colPA, paNext, ["side"]) : -1;

  const importId = uuid();
  const recs = [];

  for (let r = 1; r < data.length; r++) {
    const row = data[r] || [];

    if (colSP >= 0) {
      const DateV = row[colSP + 1];
      const TaskOrder = row[colSP + 2];
      const SKU = row[colSP + 3];
      const BoxNumber = row[colSP + 4];
      const TimeV = row[colSP + 5];
      const Picker = row[colSP + 6];
      const DpV = spDpCol >= 0 ? row[spDpCol] : null;
      const SideV = spSideCol >= 0 ? row[spSideCol] : null;

      const has = [DateV, TaskOrder, SKU, BoxNumber, TimeV, Picker, DpV, SideV].some(
        (v) => String(v || "").trim() !== ""
      );

      if (has) {
        recs.push({
          id: uuid(),
          type: "shortpick",
          date: toPgDate(DateV),
          time: toPgTimestamp(TimeV),
          person_login: String(Picker || "").trim() || null,
          task_order: String(TaskOrder || "") || null,
          sku: String(SKU || "") || null,
          box_number: String(BoxNumber || "") || null,
          container: null,
          auditor: null,
          result: null,
          dp: normalizeDp(DpV),
          side: normalizeSide(SideV),
          import_id: importId,
        });
      }
    }

    if (colAP >= 0) {
      const Audytor = row[colAP + 1];
      const DateV = row[colAP + 2];
      const Container = row[colAP + 3];
      const SKU = row[colAP + 4];
      const Picker = row[colAP + 5];
      const Error = row[colAP + 6];
      const DpV = apDpCol >= 0 ? row[apDpCol] : null;
      const SideV = apSideCol >= 0 ? row[apSideCol] : null;

      const has = [DateV, Container, SKU, Picker, Error, DpV, SideV].some(
        (v) => String(v || "").trim() !== ""
      );

      if (has) {
        recs.push({
          id: uuid(),
          type: "audit_pick",
          date: toPgDate(DateV),
          time: null,
          person_login: String(Picker || "").trim() || null,
          task_order: null,
          sku: String(SKU || "") || null,
          box_number: null,
          container: String(Container || "") || null,
          auditor: String(Audytor || "") || null,
          result: String(Error || "") || null,
          dp: normalizeDp(DpV),
          side: normalizeSide(SideV),
          import_id: importId,
        });
      }
    }

    if (colPA >= 0) {
      const Audytor = row[colPA + 1];
      const DateV = row[colPA + 2];
      const Container = row[colPA + 3];
      const Packer = row[colPA + 4];
      const Eror = row[colPA + 5];
      const SKU = row[colPA + 6];
      const DpV = paDpCol >= 0 ? row[paDpCol] : null;
      const SideV = paSideCol >= 0 ? row[paSideCol] : null;

      const has = [DateV, Container, Packer, Eror, SKU, DpV, SideV].some(
        (v) => String(v || "").trim() !== ""
      );

      if (has) {
        recs.push({
          id: uuid(),
          type: "audit_pa",
          date: toPgDate(DateV),
          time: null,
          person_login: String(Packer || "").trim() || null,
          task_order: null,
          sku: String(SKU || "") || null,
          box_number: null,
          container: String(Container || "") || null,
          auditor: String(Audytor || "") || null,
          result: String(Eror || "") || null,
          dp: normalizeDp(DpV),
          side: normalizeSide(SideV),
          import_id: importId,
        });
      }
    }
  }

  if (recs.length === 0) return res.status(400).json({ error: "no data found in file" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    await client.query(
      `INSERT INTO imports(id,name,creator_login,uploaded_at,rows_count,mime,bytes)
       VALUES($1,$2,$3,now(),$4,$5,$6)`,
      [
        importId,
        req.file.originalname,
        req.user.login,
        recs.length,
        req.file.mimetype || "application/octet-stream",
        req.file.buffer,
      ]
    );

    const values = [];
    const params = [];
    let i = 1;

    for (const x of recs) {
      params.push(
        `($${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++})`
      );
      values.push(
        x.id,
        x.type,
        x.date,
        x.time,
        x.person_login,
        x.task_order,
        x.sku,
        x.box_number,
        x.container,
        x.auditor,
        x.result,
        x.dp,
        x.side,
        x.import_id
      );
    }

    await client.query(
      `INSERT INTO records
        (id,type,date,time,person_login,task_order,sku,box_number,container,auditor,result,dp,side,import_id)
       VALUES ${params.join(",")}`,
      values
    );

    await client.query("COMMIT");
    res.json({ importId, rowsAdded: recs.length });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("IMPORT ERROR:", e);
    return res.status(500).json({ error: "import failed" });
  } finally {
    client.release();
  }
});

/** =========================================================
 *  Serve frontend
 *  ========================================================= */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const port = process.env.PORT || 3000;

(async () => {
  await initDatabase();
  app.listen(port, () => console.log("Listening on", port));
})();




