require("dotenv").config();
const express=require("express");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const axios=require("axios");
const Database=require("better-sqlite3");
const path=require("path");
const crypto=require("crypto");

const app=express();
const db=new Database("great_money.db");
const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET||"CHANGE_ME";

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"100kb"}));
app.use(express.urlencoded({extended:false}));
app.use(rateLimit({windowMs:15*60*1000,max:300}));
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 contact TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 referral_code TEXT UNIQUE NOT NULL,
 balance INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 reference TEXT UNIQUE NOT NULL,
 type TEXT NOT NULL,
 amount INTEGER NOT NULL,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function now(){return new Date().toISOString();}
function tokenFor(u){return jwt.sign({id:u.id,contact:u.contact},JWT_SECRET,{expiresIn:"7d"});}
function auth(req,res,next){
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Login required"});
  try{req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}catch(e){res.status(401).json({error:"Invalid or expired session"})}
}
function userById(id){return db.prepare("SELECT id,name,contact,referral_code,balance,created_at FROM users WHERE id=?").get(id)}

app.post("/api/register",async(req,res)=>{
  const {name,contact,password}=req.body;
  if(!name||!contact||!password||password.length<8) return res.status(400).json({error:"Name, contact and an 8+ character password are required"});
  const exists=db.prepare("SELECT id FROM users WHERE contact=?").get(contact.trim().toLowerCase());
  if(exists)return res.status(409).json({error:"An account with this contact already exists"});
  const hash=await bcrypt.hash(password,12);
  const code="GM-"+crypto.randomBytes(4).toString("hex").toUpperCase();
  const info=db.prepare("INSERT INTO users(name,contact,password_hash,referral_code,created_at) VALUES(?,?,?,?,?)")
    .run(name.trim(),contact.trim().toLowerCase(),hash,code,now());
  const u=userById(info.lastInsertRowid);
  res.json({token:tokenFor(u),user:u});
});

app.post("/api/login",async(req,res)=>{
  const {contact,password}=req.body;
  const row=db.prepare("SELECT * FROM users WHERE contact=?").get((contact||"").trim().toLowerCase());
  if(!row||!(await bcrypt.compare(password||"",row.password_hash)))return res.status(401).json({error:"Invalid login details"});
  res.json({token:tokenFor(row),user:userById(row.id)});
});

app.get("/api/me",auth,(req,res)=>{
  const u=userById(req.user.id);
  if(!u)return res.status(404).json({error:"User not found"});
  const transactions=db.prepare("SELECT reference,type,amount,status,created_at FROM transactions WHERE user_id=? ORDER BY id DESC").all(u.id);
  res.json({user:u,transactions});
});

app.post("/api/deposit",auth,async(req,res)=>{
  const amount=Number(req.body.amount);
  if(amount!==1500)return res.status(400).json({error:"The first activation deposit is fixed at ₦1,500"});
  const reference="GM-"+Date.now()+"-"+crypto.randomBytes(3).toString("hex");
  const email=req.user.contact.includes("@")?req.user.contact:`${req.user.id}@greatmoney.local`;
  if(!process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_SECRET_KEY.includes("your_key")){
    db.prepare("INSERT INTO transactions(user_id,reference,type,amount,status,created_at) VALUES(?,?,?,?,?,?)")
      .run(req.user.id,reference,"First Deposit",1500,"Awaiting Payment Setup",now());
    return res.status(503).json({error:"Payment gateway is not configured yet. Set PAYSTACK_SECRET_KEY in .env before accepting real payments.",reference});
  }
  try{
    const r=await axios.post("https://api.paystack.co/transaction/initialize",
      {email,amount:1500000,reference,callback_url:`${process.env.PUBLIC_URL||"http://localhost:"+PORT}/payment-callback.html`},
      {headers:{Authorization:`Bearer ${process.env.PAYSTACK_SECRET_KEY}`}}
    );
    db.prepare("INSERT INTO transactions(user_id,reference,type,amount,status,created_at) VALUES(?,?,?,?,?,?)")
      .run(req.user.id,reference,"First Deposit",1500,"Pending",now());
    res.json({authorization_url:r.data.data.authorization_url,reference});
  }catch(e){res.status(502).json({error:"Payment initialization failed"})}
});

app.get("/api/payment/verify/:reference",auth,async(req,res)=>{
  if(!process.env.PAYSTACK_SECRET_KEY)return res.status(503).json({error:"Payment gateway not configured"});
  try{
    const r=await axios.get(`https://api.paystack.co/transaction/verify/${encodeURIComponent(req.params.reference)}`,
      {headers:{Authorization:`Bearer ${process.env.PAYSTACK_SECRET_KEY}`}});
    const d=r.data.data;
    const tx=db.prepare("SELECT * FROM transactions WHERE reference=? AND user_id=?").get(req.params.reference,req.user.id);
    if(!tx)return res.status(404).json({error:"Transaction not found"});
    if(d.status==="success"){
      db.transaction(()=>{
        db.prepare("UPDATE transactions SET status='Completed' WHERE id=?").run(tx.id);
        db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(1500,req.user.id);
      })();
    }
    res.json({status:d.status});
  }catch(e){res.status(502).json({error:"Could not verify payment"})}
});

app.post("/api/admin/login",async(req,res)=>{
  const {email,password}=req.body;
  if(email!==process.env.ADMIN_EMAIL||password!==process.env.ADMIN_PASSWORD)return res.status(401).json({error:"Invalid admin login"});
  res.json({token:jwt.sign({admin:true},JWT_SECRET,{expiresIn:"4h"})});
});
function admin(req,res,next){
  const h=req.headers.authorization||"";
  try{const p=jwt.verify(h.slice(7),JWT_SECRET);if(!p.admin)throw 0;next()}catch(e){res.status(401).json({error:"Admin access required"})}
}
app.get("/api/admin/overview",admin,(req,res)=>{
  const users=db.prepare("SELECT id,name,contact,balance,created_at FROM users ORDER BY id DESC").all();
  const tx=db.prepare("SELECT t.*,u.name,u.contact FROM transactions t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC").all();
  res.json({users,transactions:tx});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Great Money running on http://localhost:${PORT}`));
