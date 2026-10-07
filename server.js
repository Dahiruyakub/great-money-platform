require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET is missing");
  process.exit(1);
}

if (!process.env.PAYSTACK_SECRET_KEY) {
  console.error("PAYSTACK_SECRET_KEY is missing");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(helmet());

/*
  PAYSTACK WEBHOOK
  This route must receive the RAW request body.
*/
app.post(
  "/api/paystack/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-paystack-signature"];

      if (!signature) {
        return res.status(401).send("Missing signature");
      }

      const hash = crypto
        .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
        .update(req.body)
        .digest("hex");

      if (signature !== hash) {
        return res.status(401).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString());

      if (event.event === "charge.success" && event.data) {
        if (
          Number(event.data.amount) === 150000 &&
          event.data.currency === "NGN"
        ) {
          await completePayment(
            event.data.reference,
            event.data
          );
        }
      }

      return res.sendStatus(200);

    } catch (error) {
      console.error("Webhook error:", error);
      return res.sendStatus(500);
    }
  }
);

/*
  Normal JSON requests
*/
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300
  })
);

app.use(express.static("public"));

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      contact VARCHAR(150) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      referral_code VARCHAR(30) UNIQUE NOT NULL,
      balance NUMERIC(12,2) DEFAULT 0,
      activated BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      reference VARCHAR(120) UNIQUE NOT NULL,
      paystack_transaction_id VARCHAR(120),
      type VARCHAR
