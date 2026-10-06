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
  const amo
