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
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_RENDER_ENV";
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

function nowISO() { return new Date().toISOString(); }
function uuid() { return crypto.randomUUID(); }

function base64url(buf){
  return Buffer.from(buf).toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}
function signJWT(payload){
  const header = { alg:"HS256", typ:"JWT" };
  const iat = Math.floor(Date.now()/1000);
  const exp = iat + TOKEN_TTL_SECONDS;
  const body = { ...payload, iat, exp };

  const h = base64url(JSON.stringify(header));
  const b = base64url(JSON.stringify(body));
  const data = `${h}.${b}`;
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(data).digest();
  return `${data}.${base64url(sig)}`;
}
function verifyJWT(token){
  const parts = String(token||"").split(".");
  if(parts.length !== 3) return null;
  const [h,b,s] = parts;
  const data = `${h}.${b}`;
  const expected = base64url(crypto.createHmac("sha256", JWT_SECRET).update(data).digest());
  if(expected !== s) return null;
  const payload = JSON.parse(Buffer.from(b.replace(/-/g,"+").replace(/_/g,"/"), "base64").toString("utf8"));
  const now = Math.floor(Date.now()/1000);
  if(payload.exp && now > payload.exp) return null;
  return payload;
}

function authRequired(req,res,next){
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  const payload = verifyJWT(token);
  if(!payload) return res.status(401).json({ error:"unauthorized" });
  req.user = payload; // {userId, login, role}
  next();
}
function roleRequired(...roles){
  return (req,res,next)=>{
    if(!req.user) return res.status(401).json({ error:"unauthorized" });
    if(!roles.includes(req.user.role)) return res.status(403).json({ error:"forbidden" });
    next();
  };
}

// ====== DB init ======
await pool.query(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  login TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS imports (
  id TEXT PRIMARY KEY,
  name TEXT,
  creator_login TEXT,
  uploaded_at TEXT,
  rows_count INT,
  mime TEXT,
  bytes BYTEA
);

CREATE TABLE IF NOT EXISTS records (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  date TEXT,
  time TEXT,
  person_login TEXT,
  task_order TEXT,
  sku TEXT,
  box_number TEXT,
  container TEXT,
  auditor TEXT,
  result TEXT,
  import_id TEXT,
  created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_records_type_date ON records(type, date);
CREATE INDEX IF NOT EXISTS idx_records_login_date ON records(person_login, date);
CREATE INDEX IF NOT EXISTS idx_records_import_id ON records(import_id);
`);

// seed admin if empty
const ucount = await pool.query(`SELECT COUNT(*)::int AS c FROM users`);
if(ucount.rows[0].c === 0){
  // ВАЖНО: это demo. После запуска поменяй пароль.
  // login: 60078903 pass: 123456 role: admin
  const demoId = uuid();
  const demoHash = crypto.createHash("sha256").update("123456").digest("hex");
  await pool.query(
    `INSERT INTO users(id,login,pass_hash,role,created_at) VALUES($1,$2,$3,$4,$5)`,
    [demoId, "60078903", demoHash, "admin", nowISO()]
  );
}

// ====== health ======
app.get("/api/health", (req,res)=>res.json({ok:true}));

// ====== AUTH ======
app.post("/api/auth/login", async (req,res)=>{
  const { login, password } = req.body || {};
  if(!login || !password) return res.status(400).json({ error:"missing login/password" });

  const q = await pool.query(`SELECT id,login,pass_hash,role FROM users WHERE login=$1`, [String(login).trim()]);
  const u = q.rows[0];
  if(!u) return res.status(401).json({ error:"invalid credentials" });

  const passHash = crypto.createHash("sha256").update(String(password)).digest("hex");
  if(passHash !== u.pass_hash) return res.status(401).json({ error:"invalid credentials" });

  const token = signJWT({ userId: u.id, login: u.login, role: u.role });
  res.json({ token, user: { id:u.id, login:u.login, role:u.role } });
});

app.post("/api/auth/change-password", authRequired, async (req,res)=>{
  const { currentPassword, newPassword } = req.body || {};
  if(!currentPassword || !newPassword) return res.status(400).json({ error:"missing fields" });

  const q = await pool.query(`SELECT pass_hash FROM users WHERE id=$1`, [req.user.userId]);
  const u = q.rows[0];
  if(!u) return res.status(404).json({ error:"user not found" });

  const curHash = crypto.createHash("sha256").update(String(currentPassword)).digest("hex");
  if(curHash !== u.pass_hash) return res.status(401).json({ error:"wrong password" });

  const newHash = crypto.createHash("sha256").update(String(newPassword)).digest("hex");
  await pool.query(`UPDATE users SET pass_hash=$1 WHERE id=$2`, [newHash, req.user.userId]);
  res.json({ ok:true });
});

// ====== USERS (admin/manager) ======
app.get("/api/users", authRequired, roleRequired("admin","manager"), async (req,res)=>{
  const q = await pool.query(`SELECT id,login,role,created_at FROM users ORDER BY created_at DESC`);
  res.json({ rows: q.rows });
});

app.post("/api/users", authRequired, roleRequired("admin","manager"), async (req,res)=>{
  const me = req.user;
  const { login, password, role } = req.body || {};
  if(!login || !password) return res.status(400).json({ error:"missing login/password" });

  const r = String(role||"manager");
  if(me.role === "manager" && r === "admin") return res.status(403).json({ error:"manager cannot create admin" });

  const id = uuid();
  const pass_hash = crypto.createHash("sha256").update(String(password)).digest("hex");
  try{
    await pool.query(
      `INSERT INTO users(id,login,pass_hash,role,created_at) VALUES($1,$2,$3,$4,$5)`,
      [id, String(login).trim(), pass_hash, r, nowISO()]
    );
  }catch(e){
    if(String(e?.message||"").includes("unique")) return res.status(409).json({ error:"login exists" });
    throw e;
  }
  res.json({ ok:true, id });
});

app.put("/api/users/:id", authRequired, roleRequired("admin","manager"), async (req,res)=>{
  const me = req.user;
  const id = req.params.id;
  const { role, password } = req.body || {};

  const q = await pool.query(`SELECT id,role FROM users WHERE id=$1`, [id]);
  const target = q.rows[0];
  if(!target) return res.status(404).json({ error:"not found" });

  if(me.role === "manager" && target.role === "admin") return res.status(403).json({ error:"manager cannot edit admin" });
  if(me.role === "manager" && role === "admin") return res.status(403).json({ error:"manager cannot set admin" });

  const sets = [];
  const vals = [];
  const add = (sql, v)=>{ vals.push(v); sets.push(sql.replace("?", `$${vals.length}`)); };

  if(role) add(`role=?`, String(role));
  if(password){
    const pass_hash = crypto.createHash("sha256").update(String(password)).digest("hex");
    add(`pass_hash=?`, pass_hash);
  }
  if(!sets.length) return res.json({ ok:true });

  vals.push(id);
  await pool.query(`UPDATE users SET ${sets.join(", ")} WHERE id=$${vals.length}`, vals);
  res.json({ ok:true });
});

app.delete("/api/users/:id", authRequired, roleRequired("admin","manager"), async (req,res)=>{
  const me = req.user;
  const id = req.params.id;

  if(me.userId === id) return res.status(400).json({ error:"cannot delete self" });

  const q = await pool.query(`SELECT role FROM users WHERE id=$1`, [id]);
  const target = q.rows[0];
  if(!target) return res.status(404).json({ error:"not found" });

  if(me.role === "manager" && target.role === "admin") return res.status(403).json({ error:"manager cannot delete admin" });

  await pool.query(`DELETE FROM users WHERE id=$1`, [id]);
  res.json({ ok:true });
});

// ====== RECORDS ======
app.get("/api/records", authRequired, async (req,res)=>{
  const { type, login, from, to, result, page="1", pageSize="14" } = req.query;

  const p = Math.max(1, parseInt(page,10));
  const ps = Math.min(500, Math.max(1, parseInt(pageSize,10)));
  const offset = (p-1)*ps;

  const where = [];
  const vals = [];
  const add = (sql, v)=>{ vals.push(v); where.push(sql.replace("?", `$${vals.length}`)); };

  if(type) add(`type = ?`, String(type));
  if(login) add(`person_login = ?`, String(login).trim());
  if(from) add(`date >= ?`, String(from));
  if(to) add(`date <= ?`, String(to));
  if(result && result !== "all") add(`LOWER(result) = ?`, String(result).toLowerCase());

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const total = await pool.query(`SELECT COUNT(*)::int AS c FROM records ${whereSql}`, vals);
  const rows = await pool.query(
    `SELECT * FROM records ${whereSql}
     ORDER BY date DESC, time DESC NULLS LAST
     LIMIT ${ps} OFFSET ${offset}`,
    vals
  );

  res.json({ page:p, pageSize:ps, total: total.rows[0].c, rows: rows.rows });
});

// summary для вкладки User (группировка по датам + stats)
app.get("/api/user-summary", authRequired, async (req,res)=>{
  const { login, from, to } = req.query;

  const where = [];
  const vals = [];
  const add = (sql, v)=>{ vals.push(v); where.push(sql.replace("?", `$${vals.length}`)); };

  if(login) add(`person_login = ?`, String(login).trim());
  if(from) add(`date >= ?`, String(from));
  if(to) add(`date <= ?`, String(to));
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const grouped = await pool.query(
    `SELECT date, COUNT(*)::int AS count
     FROM records ${whereSql}
     GROUP BY date
     ORDER BY date DESC`,
    vals
  );

  const sp = await pool.query(
    `SELECT COUNT(*)::int AS c FROM records ${whereSql} ${whereSql? "AND":"WHERE"} type='shortpick'`,
    vals
  );

  const ap = await pool.query(
    `SELECT
      COUNT(*)::int AS all,
      SUM(CASE WHEN LOWER(result)='profit' THEN 1 ELSE 0 END)::int AS profit,
      SUM(CASE WHEN LOWER(result)='loss' THEN 1 ELSE 0 END)::int AS loss,
      0::int AS occupied
     FROM records ${whereSql} ${whereSql? "AND":"WHERE"} type='audit_pick'`,
    vals
  );

  const pa = await pool.query(
    `SELECT
      COUNT(*)::int AS all,
      SUM(CASE WHEN LOWER(result)='profit' THEN 1 ELSE 0 END)::int AS profit,
      SUM(CASE WHEN LOWER(result)='loss' THEN 1 ELSE 0 END)::int AS loss,
      SUM(CASE WHEN LOWER(result)='occupied' THEN 1 ELSE 0 END)::int AS occupied
     FROM records ${whereSql} ${whereSql? "AND":"WHERE"} type='audit_pa'`,
    vals
  );

  res.json({
    grouped: grouped.rows,
    shortpick: sp.rows[0].c,
    audit_pick: ap.rows[0],
    audit_pa: pa.rows[0]
  });
});

// ====== IMPORTS (admin only) ======
app.get("/api/imports", authRequired, roleRequired("admin"), async (req,res)=>{
  const q = await pool.query(
    `SELECT id,name,creator_login,uploaded_at,rows_count
     FROM imports ORDER BY uploaded_at DESC`
  );
  res.json({ rows: q.rows });
});

app.get("/api/imports/:id/file", authRequired, roleRequired("admin"), async (req,res)=>{
  const id = req.params.id;
  const q = await pool.query(`SELECT name,mime,bytes FROM imports WHERE id=$1`, [id]);
  const im = q.rows[0];
  if(!im) return res.status(404).json({ error:"not found" });
  res.setHeader("Content-Type", im.mime || "application/octet-stream");
  res.setHeader("Content-Disposition", `attachment; filename="${im.name || "import.xlsx"}"`);
  res.send(im.bytes);
});

app.delete("/api/imports/:id", authRequired, roleRequired("admin"), async (req,res)=>{
  const id = req.params.id;
  const client = await pool.connect();
  try{
    await client.query("BEGIN");
    await client.query(`DELETE FROM records WHERE import_id=$1`, [id]);
    await client.query(`DELETE FROM imports WHERE id=$1`, [id]);
    await client.query("COMMIT");
  }catch(e){
    await client.query("ROLLBACK");
    console.error(e);
    return res.status(500).json({ error:"delete failed" });
  }finally{
    client.release();
  }
  res.json({ ok:true });
});

app.post("/api/import", authRequired, roleRequired("admin"), upload.single("file"), async (req,res)=>{
  if(!req.file) return res.status(400).json({ error:"no file" });

  const importId = uuid();
  const wb = XLSX.read(req.file.buffer, { type:"buffer", cellDates:false });
  const ws = wb.Sheets[wb.SheetNames[0]];
  const data = XLSX.utils.sheet_to_json(ws, { header:1, defval:"", raw:true });

  const header = (data[0]||[]).map(x=>String(x||"").trim());
  const colAP = header.indexOf("Audit pick");
  const colSP = header.indexOf("Shortpick");
  const colPA = header.indexOf("Audit PA");

  const recs = [];
  for(let r=1; r<data.length; r++){
    const row = data[r] || [];

    if(colSP>=0){
      const Date=row[colSP+1], TaskOrder=row[colSP+2], SKU=row[colSP+3], BoxNumber=row[colSP+4], Time=row[colSP+5], Picker=row[colSP+6];
      const has=[Date,TaskOrder,SKU,BoxNumber,Time,Picker].some(v=>String(v||"").trim()!=="");
      if(has) recs.push({
        id: uuid(), type:"shortpick",
        date: String(Date||"").slice(0,10),
        time: String(Time||""),
        person_login: String(Picker||"").trim(),
        task_order: String(TaskOrder||""),
        sku: String(SKU||""),
        box_number: String(BoxNumber||""),
        container:"", auditor:"", result:"",
        import_id: importId, created_at: nowISO()
      });
    }

    if(colAP>=0){
      const Audytor=row[colAP+1], Date=row[colAP+2], Container=row[colAP+3], SKU=row[colAP+4], Picker=row[colAP+5], Error=row[colAP+6];
      const has=[Date,Container,SKU,Picker,Error].some(v=>String(v||"").trim()!=="");
      if(has) recs.push({
        id: uuid(), type:"audit_pick",
        date: String(Date||"").slice(0,10),
        time: String(Date||"").slice(0,10) ? String(Date).slice(0,10)+"T00:00:00" : "",
        person_login: String(Picker||"").trim(),
        task_order:"", sku:String(SKU||""), box_number:"",
        container:String(Container||""), auditor:String(Audytor||""),
        result:String(Error||""), import_id: importId, created_at: nowISO()
      });
    }

    if(colPA>=0){
      const Audytor=row[colPA+1], Date=row[colPA+2], Container=row[colPA+3], Packer=row[colPA+4], Eror=row[colPA+5], SKU=row[colPA+6];
      const has=[Date,Container,Packer,Eror,SKU].some(v=>String(v||"").trim()!=="");
      if(has) recs.push({
        id: uuid(), type:"audit_pa",
        date: String(Date||"").slice(0,10),
        time: String(Date||"").slice(0,10) ? String(Date).slice(0,10)+"T00:00:00" : "",
        person_login: String(Packer||"").trim(),
        task_order:"", sku:String(SKU||""), box_number:"",
        container:String(Container||""), auditor:String(Audytor||""),
        result:String(Eror||""), import_id: importId, created_at: nowISO()
      });
    }
  }

  if(recs.length === 0) return res.status(400).json({ error:"no data found in file" });

  const client = await pool.connect();
  try{
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO imports(id,name,creator_login,uploaded_at,rows_count,mime,bytes)
       VALUES($1,$2,$3,$4,$5,$6,$7)`,
      [importId, req.file.originalname, req.user.login, nowISO(), recs.length, req.file.mimetype, req.file.buffer]
    );

    for(const x of recs){
      await client.query(
        `INSERT INTO records(id,type,date,time,person_login,task_order,sku,box_number,container,auditor,result,import_id,created_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [x.id,x.type,x.date,x.time,x.person_login,x.task_order,x.sku,x.box_number,x.container,x.auditor,x.result,x.import_id,x.created_at]
      );
    }
    await client.query("COMMIT");
  }catch(e){
    await client.query("ROLLBACK");
    console.error(e);
    return res.status(500).json({ error:"import failed" });
  }finally{
    client.release();
  }

  res.json({ importId, rowsAdded: recs.length });
});

// ====== serve frontend ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

const port = process.env.PORT || 3000;
app.listen(port, ()=> console.log("Listening on", port));
