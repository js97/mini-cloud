"use strict";

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const FILES_FILE = path.join(DATA_DIR, "files.json");
const UPLOAD_DIR = path.join(ROOT, "shared_files");

for (const dir of [DATA_DIR, UPLOAD_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}
for (const [file, initial] of [[USERS_FILE, {}], [FILES_FILE, {}]]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(initial, null, 2) + "\n", { mode: 0o600 });
}

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  if (IS_PRODUCTION) {
    console.error("Set SESSION_SECRET to a random secret of at least 32 characters.");
    process.exit(1);
  }
  console.warn("WARNING: Set SESSION_SECRET to a random value of at least 32 characters before deployment.");
}

app.set("view engine", "ejs");
app.set("views", path.join(ROOT, "views"));
app.get("/style.css", (_req, res) => res.sendFile(path.join(ROOT, "public", "style.css")));
app.disable("x-powered-by");
if (IS_PRODUCTION) app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(session({
  name: "mini-cloud.sid",
  secret: SESSION_SECRET || "development-only-secret-change-this-before-deploying",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PRODUCTION,
    maxAge: 8 * 60 * 60 * 1000
  }
}));

// Small synchronizer-token CSRF protection for all state-changing form submissions.
app.use((req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.locals.csrfToken = req.session.csrfToken;
  next();
});
function requireCsrf(req, res, next) {
  const submitted = req.body && req.body._csrf;
  const expected = req.session.csrfToken;
  if (typeof submitted !== "string" || typeof expected !== "string" ||
      submitted.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(submitted), Buffer.from(expected))) {
    return res.status(403).render("error", { title: "Request rejected", message: "The form token was invalid. Please go back, refresh the page, and try again." });
  }
  next();
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    console.error(`Could not read ${path.basename(file)}:`, err.message);
    throw new Error(`Could not read ${path.basename(file)}. Check the file's JSON syntax.`);
  }
}
function writeJsonAtomic(file, value) {
  const temp = file + "." + crypto.randomBytes(6).toString("hex") + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(temp, file);
}
function getUsers() { return readJson(USERS_FILE); }
function getFiles() { return readJson(FILES_FILE); }

function requireVerified(req, res, next) {
  const username = req.session.username;
  if (!username) return res.redirect("/login");
  let user;
  try { user = getUsers()[username]; } catch (err) { return next(err); }
  if (!user || user.verified !== true) {
    req.session.destroy(() => {});
    return res.redirect("/login?notice=verification");
  }
  res.locals.username = username;
  next();
}

function safeOriginalName(name) {
  // Keep only a plain basename and remove control characters.
  return path.basename(name).replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 180);
}
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, _file, cb) => cb(null, crypto.randomUUID())
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (!safeOriginalName(file.originalname)) return cb(new Error("Please choose a file with a valid filename."));
    cb(null, true);
  }
});

app.get("/", requireVerified, (req, res) => res.redirect("/files"));

app.get("/login", (req, res) => {
  if (req.session.username) {
    try {
      const user = getUsers()[req.session.username];
      if (user && user.verified === true) return res.redirect("/files");
    } catch (_) {}
  }
  let notice = "";
  if (req.query.notice === "verification") notice = "Your account is not verified or has been disabled.";
  res.render("login", { error: "", notice });
});

app.post("/login", requireCsrf, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const users = getUsers();
    const user = users[username];

    // Same generic error for missing, unverified, or incorrect credentials.
    if (!user || user.verified !== true || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).render("login", { error: "Invalid credentials or account not verified.", notice: "" });
    }

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.username = username;
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.redirect("/files");
      });
    });
  } catch (err) { next(err); }
});

app.post("/logout", requireVerified, requireCsrf, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie("mini-cloud.sid", { httpOnly: true, sameSite: "lax", secure: IS_PRODUCTION });
    res.redirect("/login");
  });
});

app.get("/files", requireVerified, (req, res, next) => {
  try {
    const files = Object.entries(getFiles()).map(([id, record]) => ({ id, ...record }))
      .sort((a, b) => String(b.uploadedAt).localeCompare(String(a.uploadedAt)));
    res.render("files", { files, message: req.query.message || "" });
  } catch (err) { next(err); }
});

app.post("/upload", requireVerified, (req, res, next) => {
  upload.single("file")(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).redirect("/files?message=" + encodeURIComponent("File is too large. Maximum size is 100 MB."));
      }
      if (err) return res.status(400).redirect("/files?message=" + encodeURIComponent(err.message || "Upload failed."));
      return next(err);
    }
    if (!req.file) return res.redirect("/files?message=" + encodeURIComponent("Please select a file."));

    // Multipart form fields are parsed by Multer, so validate the CSRF token here.
    const submitted = req.body && req.body._csrf;
    const expected = req.session.csrfToken;
    const csrfValid = typeof submitted === "string" && typeof expected === "string" &&
      submitted.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(submitted), Buffer.from(expected));
    if (!csrfValid) {
      fs.rmSync(req.file.path, { force: true });
      return res.status(403).render("error", {
        title: "Request rejected",
        message: "The form token was invalid. Refresh the page and try again."
      });
    }

    try {
      const files = getFiles();
      const id = crypto.randomUUID();
      files[id] = {
        storageName: req.file.filename,
        originalName: safeOriginalName(req.file.originalname) || "download",
        uploadedBy: req.session.username,
        uploadedAt: new Date().toISOString(),
        size: req.file.size
      };
      writeJsonAtomic(FILES_FILE, files);
      res.redirect("/files?message=" + encodeURIComponent("File uploaded and shared."));
    } catch (err2) {
      fs.rmSync(req.file.path, { force: true });
      next(err2);
    }
  });
});

app.get("/download/:id", requireVerified, (req, res, next) => {
  if (!/^[0-9a-f-]{36}$/i.test(req.params.id)) return res.sendStatus(404);
  try {
    const record = getFiles()[req.params.id];
    if (!record || typeof record.storageName !== "string" || path.basename(record.storageName) !== record.storageName) {
      return res.sendStatus(404);
    }
    const diskPath = path.join(UPLOAD_DIR, record.storageName);
    if (!fs.existsSync(diskPath)) return res.status(404).send("File is missing from storage.");
    res.download(diskPath, safeOriginalName(record.originalName) || "download", (err) => {
      if (err && !res.headersSent) next(err);
    });
  } catch (err) { next(err); }
});

app.get("/change-password", requireVerified, (_req, res) => res.render("change-password", { error: "", success: "" }));

app.post("/change-password", requireVerified, requireCsrf, async (req, res, next) => {
  try {
    const current = String(req.body.currentPassword || "");
    const nextPassword = String(req.body.newPassword || "");
    const confirm = String(req.body.confirmPassword || "");
    const users = getUsers();
    const user = users[req.session.username];

    if (!(await bcrypt.compare(current, user.passwordHash))) {
      return res.status(400).render("change-password", { error: "Current password is incorrect.", success: "" });
    }
    if (nextPassword.length < 12) {
      return res.status(400).render("change-password", { error: "Use at least 12 characters for the new password.", success: "" });
    }
    if (nextPassword !== confirm) {
      return res.status(400).render("change-password", { error: "The new passwords do not match.", success: "" });
    }
    if (await bcrypt.compare(nextPassword, user.passwordHash)) {
      return res.status(400).render("change-password", { error: "Choose a different password.", success: "" });
    }

    user.passwordHash = await bcrypt.hash(nextPassword, 12);
    writeJsonAtomic(USERS_FILE, users);

    // Force a fresh login after changing the password.
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie("mini-cloud.sid", { httpOnly: true, sameSite: "lax", secure: IS_PRODUCTION });
      res.redirect("/login?notice=password");
    });
  } catch (err) { next(err); }
});

app.use((err, req, res, _next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(500).render("error", {
    title: "Something went wrong",
    message: "The request could not be completed. Check the server logs for details."
  });
});

// Admin commands: create users as unverified by default, then verify/revoke explicitly.
async function admin() {
  const [command, username] = process.argv.slice(2);
  if (!command || !username) {
    console.log("Usage:");
    console.log("  npm run admin -- create-user USERNAME");
    console.log("  npm run admin -- verify-user USERNAME");
    console.log("  npm run admin -- revoke-user USERNAME");
    process.exitCode = 1;
    return;
  }
  if (username.length > 64 || /[\\/\u0000-\u001f]/.test(username) || username.trim() !== username) {
    throw new Error("Username must be 1–64 characters and cannot contain slashes or control characters.");
  }
  const users = getUsers();
  if (command === "create-user") {
    if (Object.prototype.hasOwnProperty.call(users, username)) throw new Error("That username already exists.");
    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = (question) => new Promise((resolve) => rl.question(question, resolve));
    try {
      const password = await ask("Initial password (input will be visible): ");
      const confirm = await ask("Confirm password: ");
      if (password.length < 12) throw new Error("Use a password of at least 12 characters.");
      if (password !== confirm) throw new Error("Passwords do not match.");
      users[username] = { passwordHash: await bcrypt.hash(password, 12), verified: false, createdAt: new Date().toISOString() };
      writeJsonAtomic(USERS_FILE, users);
      console.log(`Created ${username} as unverified. Run verify-user to grant access.`);
    } finally { rl.close(); }
  } else if (command === "verify-user" || command === "revoke-user") {
    if (!users[username]) throw new Error("User not found.");
    users[username].verified = command === "verify-user";
    writeJsonAtomic(USERS_FILE, users);
    console.log(`${username}: verified=${users[username].verified}`);
  } else {
    throw new Error("Unknown command.");
  }
}

if (require.main === module) {
  if (process.argv.length > 2) {
    admin().catch((err) => { console.error(err.message); process.exitCode = 1; });
  } else {
    app.listen(PORT, "127.0.0.1", () => console.log(`Mini Cloud listening on http://127.0.0.1:${PORT}`));
  }
}
