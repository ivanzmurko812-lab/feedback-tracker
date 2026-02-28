import express from "express";
import multer from "multer";
import pg from "pg";
import XLSX from "xlsx";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
app.use(express.json({ limit: "5mb" }));

const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } });

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

await pool.query(`
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

CREATE TABLE IF NOT EXISTS imports (
  id TEXT PRIMARY KEY,
  name TEXT,
  creator_login TEXT,
  uploaded_at TEXT,
  rows_count INT
);
`);

function nowISO(){ return new Date().toISOString(); }
function uuid(){ return crypto.randomUUID(); }

// тест
app.get("/api/health", (req,res)=>res.json({ok:true}));

// получить записи (пока без авторизации)
app.get("/api/records", async (req,res)=>{
  const { type, login, from, to, result, page="1", pageSize="50" } = req.query;

  const p = Math.max(1, parseInt(page,10));
  const ps = Math.min(500, Math.max(1, parseInt(pageSize,10)));
  const offset = (p-1)*ps;

  const where = [];
  const vals = [];
  const add = (sql, v)=>{ vals.push(v); where.push(sql.replace("?", `$${vals.length}`)); };

  if(type) add(`type = ?`, type);
  if(login) add(`person_login = ?`, String(login).trim());
  if(from) add(`date >= ?`, String(from));
  if(to) add(`date <= ?`, String(to));
  if(result && result !== "all") add(`LOWER(result) = ?`, String(result).toLowerCase());

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const total = await pool.query(`SELECT COUNT(*)::int AS c FROM records ${whereSql}`, vals);
  const rows = await pool.query(
    `SELECT * FROM records ${whereSql} ORDER BY date DESC, time DESC NULLS LAST LIMIT ${ps} OFFSET ${offset}`,
    vals
  );

  res.json({ page:p, pageSize:ps, total: total.rows[0].c, rows: rows.rows });
});

// импорт Excel -> в базу
app.post("/api/import", upload.single("file"), async (req,res)=>{
  if(!req.file) return res.status(400).json({error:"no file"});
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

  const client = await pool.connect();
  try{
    await client.query("BEGIN");
    await client.query(
      "INSERT INTO imports(id,name,creator_login,uploaded_at,rows_count) VALUES($1,$2,$3,$4,$5)",
      [importId, req.file.originalname, "admin", nowISO(), recs.length]
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
    return res.status(500).json({error:"import failed"});
  }finally{
    client.release();
  }

  res.json({ importId, rowsAdded: recs.length });
});

// Раздаём статические файлы (index.html)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

const port = process.env.PORT || 3000;
app.listen(port, ()=> console.log("Listening on", port));
