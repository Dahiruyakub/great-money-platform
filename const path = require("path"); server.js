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

app.use(helmet({ contentSecurityPolicy: false }));

function tokenFor(user) {
  return jwt.sign(
    { id: user.id, contact: user.contact },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Login required" });
  }

  try {
    req.user = jwt.verify(
      header.slice(7),
      process.env.JWT_SECRET
    );
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired session"
    });
  }
}

async function userById(id) {
  const result = await pool.query(
    `SELECT id, name, contact, referral_code, balance, activated, created_at
     FROM users WHERE id = $1`,
    [id]
  );

  return result.rows[0] || null;
}

async function completePayment(reference, data) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const txResult = await client.query(
      `SELECT id, user_id, amount, status
       FROM transactions
       WHERE reference = $1
       FOR UPDATE`,
      [reference]
    );

    if (!txResult.rows.length) {
      await client.query("ROLLBACK");
      console.error("Transaction not found:", reference);
      return;
    }

    const tx = txResult.rows[0];

    if (tx.status === "Completed") {
      await client.query("COMMIT");
      return;
    }

    if (Number(tx.amount) !== 1500) {
      await client.query("ROLLBACK");
      console.error("Unexpected transaction amount:", reference);
      return;
    }

    if (
      Number(data.amount) !== 150000 ||
      data.currency !== "NGN"
    ) {
      await client.query("ROLLBACK");
      console.error(
        "Paystack amount/currency mismatch:",
        reference
      );
      return;
    }

    await client.query(
      `UPDATE transactions
       SET status = 'Completed',
           paystack_transaction_id = $1
       WHERE id = $2`,
      [String(data.id || ""), tx.id]
    );

    await client.query(
      `UPDATE users
       SET balance = balance + 1500,
           activated = TRUE
       WHERE id = $1`,
      [tx.user_id]
    );

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("completePayment error:", error);
    throw error;
  } finally {
    client.release();
  }
}

/* Paystack Webhook */
app.post(
  "/api/paystack/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature =
        req.headers["x-paystack-signature"];

      if (!signature) {
        return res.status(401).send("Missing signature");
      }

      const hash = crypto
        .createHmac(
          "sha512",
          process.env.PAYSTACK_SECRET_KEY
        )
        .update(req.body)
        .digest("hex");

      if (signature !== hash) {
        return res.status(401).send("Invalid signature");
      }

      const event = JSON.parse(
        req.body.toString()
      );

      if (
        event.event === "charge.success" &&
        event.data
      ) {
        if (
          Number(event.data.amount) === 150000 &&
          event.data.currency === "NGN" &&
          event.data.status === "success"
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

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300
  })
);

app.use(express.static("public"));

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "great-money-platform"
  });
});

/* REGISTER */
app.post("/api/register", async (req, res) => {
  try {
    const name = String(
      req.body.name || ""
    ).trim();

    const contact = String(
      req.body.contact || ""
    ).trim().toLowerCase();

    const password = String(
      req.body.password || ""
    );

    if (
      !name ||
      !contact ||
      password.length < 8
    ) {
      return res.status(400).json({
        error:
          "Name, contact and an 8+ character password are required"
      });
    }

    const exists = await pool.query(
      "SELECT id FROM users WHERE contact = $1",
      [contact]
    );

    if (exists.rows.length) {
      return res.status(409).json({
        error:
          "An account with this contact already exists"
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const referralCode =
      "GM-" +
      crypto
        .randomBytes(4)
        .toString("hex")
        .toUpperCase();

    const result = await pool.query(
      `INSERT INTO users
       (name, contact, password_hash, referral_code)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, contact, referral_code,
                 balance, activated, created_at`,
      [
        name,
        contact,
        passwordHash,
        referralCode
      ]
    );

    const user = result.rows[0];

    return res.json({
      token: tokenFor(user),
      user
    });
  } catch (error) {
    console.error("Register error:", error);

    return res.status(500).json({
      error: "Registration failed"
    });
  }
});

/* LOGIN */
app.post("/api/login", async (req, res) => {
  try {
    const contact = String(
      req.body.contact || ""
    ).trim().toLowerCase();

    const password = String(
      req.body.password || ""
    );

    const result = await pool.query(
      "SELECT * FROM users WHERE contact = $1",
      [contact]
    );

    const row = result.rows[0];

    if (
      !row ||
      !(await bcrypt.compare(
        password,
        row.password_hash
      ))
    ) {
      return res.status(401).json({
        error: "Invalid login details"
      });
    }

    const user = await userById(row.id);

    return res.json({
      token: tokenFor(user),
      user
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      error: "Login failed"
    });
  }
});

/* CURRENT USER */
app.get("/api/me", auth, async (req, res) => {
  try {
    const user = await userById(
      req.user.id
    );

    if (!user) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    return res.json({ user });
  } catch (error) {
    console.error("Me error:", error);

    return res.status(500).json({
      error: "Could not load account"
    });
  }
});

/* TRANSACTIONS */
app.get(
  "/api/transactions",
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT reference, type, amount, status, created_at
         FROM transactions
         WHERE user_id = $1
         ORDER BY id DESC`,
        [req.user.id]
      );

      return res.json({
        transactions: result.rows
      });
    } catch (error) {
      console.error(
        "Transactions error:",
        error
      );

      return res.status(500).json({
        error: "Could not load transactions"
      });
    }
  }
);

/* PAYSTACK INITIALIZE */
app.post(
  "/api/paystack/initialize",
  auth,
  async (req, res) => {
    try {
      const user = await userById(
        req.user.id
      );

      if (!user) {
        return res.status(404).json({
          error: "User not found"
        });
      }

      const publicUrl =
        process.env.PUBLIC_URL;

      if (!publicUrl) {
        return res.status(500).json({
          error:
            "PUBLIC_URL is not configured on the server"
        });
      }

      if (
        !String(user.contact).includes("@")
      ) {
        return res.status(400).json({
          error:
            "Please register with an email address to make a Paystack payment"
        });
      }

      const reference =
        "GM-" +
        Date.now() +
        "-" +
        crypto
          .randomBytes(4)
          .toString("hex");

      await pool.query(
        `INSERT INTO transactions
         (user_id, reference, type, amount, status)
         VALUES
         ($1, $2, 'Activation', 1500, 'Pending')`,
        [user.id, reference]
      );

      const response = await fetch(
        "https://api.paystack.co/transaction/initialize",
        {
          method: "POST",
          headers: {
            Authorization:
              `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
            "Content-Type":
              "application/json"
          },
          body: JSON.stringify({
            email: user.contact,
            amount: 150000,
            currency: "NGN",
            reference,
            callback_url:
              `${publicUrl.replace(/\/$/, "")}/payment-callback.html`
          })
        }
      );

      const data =
        await response.json();

      if (!response.ok || !data.status) {
        console.error(
          "Paystack initialize error:",
          data
        );

        await pool.query(
          `UPDATE transactions
           SET status = 'Failed'
           WHERE reference = $1`,
          [reference]
        );

        return res.status(400).json({
          error:
            data.message ||
            "Could not initialize payment"
        });
      }

      return res.json({
        authorization_url:
          data.data.authorization_url,
        reference:
          data.data.reference
      });
    } catch (error) {
      console.error(
        "Initialize payment error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not initialize payment"
      });
    }
  }
);

/* PAYSTACK VERIFY */
app.get(
  "/api/paystack/verify/:reference",
  auth,
  async (req, res) => {
    try {
      const reference = String(
        req.params.reference || ""
      );

      const tx = await pool.query(
        `SELECT *
         FROM transactions
         WHERE reference = $1
         AND user_id = $2`,
        [
          reference,
          req.user.id
        ]
      );

      if (!tx.rows.length) {
        return res.status(404).json({
          error:
            "Transaction not found"
        });
      }

      const response = await fetch(
        `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
        {
          headers: {
            Authorization:
              `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
          }
        }
      );

      const data =
        await response.json();

      if (
        response.ok &&
        data.status &&
        data.data &&
        data.data.status === "success" &&
        Number(data.data.amount) === 150000 &&
        data.data.currency === "NGN"
      ) {
        await completePayment(
          reference,
          data.data
        );
      }

      const user =
        await userById(req.user.id);

      return res.json({
        user,
        paystack:
          data.data || null
      });
    } catch (error) {
      console.error(
        "Verify payment error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not verify payment"
      });
    }
  }
);

/* ADMIN LOGIN */
app.post(
  "/api/admin/login",
  async (req, res) => {
    const email = String(
      req.body.email || ""
    ).trim().toLowerCase();

    const password = String(
      req.body.password || ""
    );

    if (
      email !==
        String(
          process.env.ADMIN_EMAIL || ""
        )
          .trim()
          .toLowerCase() ||
      password !==
        String(
          process.env.ADMIN_PASSWORD || ""
        )
    ) {
      return res.status(401).json({
        error: "Invalid admin login"
      });
    }

    return res.json({
      token: jwt.sign(
        {
          admin: true,
          email
        },
        process.env.JWT_SECRET,
        {
          expiresIn: "7d"
        }
      )
    });
  }
);

/* ADMIN AUTH */
function adminAuth(
  req,
  res,
  next
) {
  const header =
    req.headers.authorization || "";

  if (
    !header.startsWith("Bearer ")
  ) {
    return res.status(401).json({
      error:
        "Admin login required"
    });
  }

  try {
    const payload =
      jwt.verify(
        header.slice(7),
        process.env.JWT_SECRET
      );

    if (!payload.admin) {
      throw new Error("Not admin");
    }

    req.admin = payload;
    next();
  } catch (error) {
    return res.status(401).json({
      error:
        "Invalid admin session"
    });
  }
}

/* ADMIN OVERVIEW */
app.get(
  "/api/admin/overview",
  adminAuth,
  async (req, res) => {
    try {
      const users =
        await pool.query(
          "SELECT COUNT(*)::int AS count FROM users"
        );

      const activated =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM users
           WHERE activated = TRUE`
        );

      const completed =
        await pool.query(
          `SELECT COALESCE(SUM(amount),0)::numeric AS total
           FROM transactions
           WHERE status = 'Completed'`
        );

      const pending =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM transactions
           WHERE status = 'Pending'`
        );

      return res.json({
        users:
          users.rows[0].count,
        activated:
          activated.rows[0].count,
        completed_amount:
          completed.rows[0].total,
        pending_transactions:
          pending.rows[0].count
      });
    } catch (error) {
      console.error(
        "Admin overview error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not load admin overview"
      });
    }
  }
);

/* FRONTEND */
app.get(
  "*",
  (req, res) => {
    res.sendFile(
      "index.html",
      {
        root: "public"
      }
    );
  }
);

/* DATABASE */
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
      type VARCHAR(50) NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      status VARCHAR(30) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

initDatabase()
  .then(() => {
    app.listen(
      PORT,
      () => {
        console.log(
          `GREAT MONEY server running on port ${PORT}`
        );
      }
    );
  })
  .catch((error) => {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
