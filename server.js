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

// IMPORTANT: Render Postgres обычно требует SSL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_RENDER_ENV";
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

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
 *  Excel date/time helpers
 *  ========================================================= */

// Excel serial date/time -> JS Date (UTC-ish)
function excelSerialToJsDate(serial) {
  // XLSX умеет разбирать серийные даты
  const d = XLSX.SSF.parse_date_code(serial);
  if (!d || !d.y || !d.m || !d.d) return null;

  const ms = Date.UTC(
    d.y,
    d.m - 1,
    d.d,
    d.H || 0,
    d.M || 0,
    Math.floor(d.S || 0)
  );
  return new Date(ms);
}

// Любое значение даты из Excel -> 'YYYY-MM-DD' или null
function toPgDate(value) {
  if (value === null || value === undefined) return null;

  // Если это число (как 45811) — это Excel serial date
  if (typeof value === "number" && isFinite(value)) {
    const jsd = excelSerialToJsDate(value);
    if (!jsd) return null;
    return jsd.toISOString().slice(0, 10);
  }

  // Если JS Date (иногда XLSX может дать Date при raw:false)
  if (value instanceof Date && !isNaN(value)) {
    return value.toISOString().slice(0, 10);
  }

  const s = String(value).trim();
  if (!s) return null;

  // Уже ISO 'YYYY-MM-DD...'
  const m1 = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m1) return `${m1[1]}-${m1[2]}-${m1[3]}`;

  // Формат 'DD.MM.YYYY'
  const m2 = s.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})$/);
  if (m2) {
    const dd = m2[1].padStart(2, "0");
    const mm = m2[2].padStart(2, "0");
    const yy = m2[3];
    return `${yy}-${mm}-${dd}`;
  }

  // Пробуем Date.parse
  const t = Date.parse(s);
  if (!isNaN(t)) return new Date(t).toISOString().slice(0, 10);

  return null;
}

// Любое значение времени/даты из Excel -> ISO string для timestamptz или null
function toPgTimestamp(value) {
  if (value === null || value === undefined) return null;

  if (typeof value === "number" && isFinite(value)) {
    // Может быть "дата+время" или просто "время"
    const jsd = excelSerialToJsDate(value);
    if (!jsd) return null;
    return jsd.toISOString();
  }

  if (value instanceof Date && !isNaN(value)) {
    return value.toISOString();
  }

  const s = String(value).trim();
  if (!s) return null;

  // Если уже ISO
  const t = Date.parse(s);
  if (!isNaN(t)) return new Date(t).toISOString();

  return null;
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
      import_id uuid REFERENCES imports(id) ON DELETE SET NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_records_type_date ON records(type, date);
    CREATE INDEX IF NOT EXISTS idx_records_login_date ON records(person_login, date);
    CREATE INDEX IF NOT EXISTS idx_records_import_id ON records(import_id);
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

// RECORDS
app.get("/api/records", authRequired, async (req, res) => {
  const { type, login, from, to, result, page = "1", pageSize = "14" } = req.query;

  const p = Math.max(1, parseInt(page, 10));
  const ps = Math.min(500, Math.max(1, parseInt(pageSize, 10)));
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

app.get("/api/user-summary", authRequired, async (req, res) => {
  const { login, from, to } = req.query;

  const where = [];
  const vals = [];
  const add = (sql, v) => {
    vals.push(v);
    where.push(sql.replace("?", `$${vals.length}`));
  };

  if (login) add(`person_login = ?`, String(login).trim());
  if (from) add(`date >= ?`, String(from));
  if (to) add(`date <= ?`, String(to));
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
      COUNT(*)::int AS all,
      SUM(CASE WHEN LOWER(result)='profit' THEN 1 ELSE 0 END)::int AS profit,
      SUM(CASE WHEN LOWER(result)='loss' THEN 1 ELSE 0 END)::int AS loss,
      0::int AS occupied
     FROM records ${whereSql} ${whereSql ? "AND" : "WHERE"} type='audit_pick'`,
    vals
  );

  const pa = await pool.query(
    `SELECT
      COUNT(*)::int AS all,
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
    // raw:true => получаем числа (45811) — мы их теперь умеем
    data = XLSX.utils.sheet_to_json(ws, { header: 1, defval: "", raw: true });
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: "bad excel" });
  }

  const header = (data[0] || []).map((x) => String(x || "").trim());
  const colAP = header.indexOf("Audit pick");
  const colSP = header.indexOf("Shortpick");
  const colPA = header.indexOf("Audit PA");

  const importId = uuid();
  const recs = [];

  for (let r = 1; r < data.length; r++) {
    const row = data[r] || [];

    // Shortpick
    if (colSP >= 0) {
      const DateV = row[colSP + 1];
      const TaskOrder = row[colSP + 2];
      const SKU = row[colSP + 3];
      const BoxNumber = row[colSP + 4];
      const TimeV = row[colSP + 5];
      const Picker = row[colSP + 6];

      const has = [DateV, TaskOrder, SKU, BoxNumber, TimeV, Picker].some(
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
          import_id: importId,
        });
      }
    }

    // Audit pick
    if (colAP >= 0) {
      const Audytor = row[colAP + 1];
      const DateV = row[colAP + 2];
      const Container = row[colAP + 3];
      const SKU = row[colAP + 4];
      const Picker = row[colAP + 5];
      const Error = row[colAP + 6];

      const has = [DateV, Container, SKU, Picker, Error].some(
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
          import_id: importId,
        });
      }
    }

    // Audit PA
    if (colPA >= 0) {
      const Audytor = row[colPA + 1];
      const DateV = row[colPA + 2];
      const Container = row[colPA + 3];
      const Packer = row[colPA + 4];
      const Eror = row[colPA + 5];
      const SKU = row[colPA + 6];

      const has = [DateV, Container, Packer, Eror, SKU].some(
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
        `($${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++})`
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
        x.import_id
      );
    }

    await client.query(
      `INSERT INTO records
        (id,type,date,time,person_login,task_order,sku,box_number,container,auditor,result,import_id)
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

// чтобы / всегда открывал index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const port = process.env.PORT || 3000;

(async () => {
  await initDatabase();
  app.listen(port, () => console.log("Listening on", port));
})();
