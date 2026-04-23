const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");
const { nanoid } = require("nanoid");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");

const app = express();

// ---------------- Persistent JSON stores ----------------
const DATA_DIR = path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const USERS_FILE    = path.join(DATA_DIR, "users.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const GROUPS_FILE   = path.join(DATA_DIR, "groups.json");

function loadJson(file, def) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return def; }
}
function saveJson(file, data) {
  fs.writeFileSync(file + ".tmp", JSON.stringify(data, null, 2));
  fs.renameSync(file + ".tmp", file);
}

let users    = loadJson(USERS_FILE, []);
let sessions = new Map(Object.entries(loadJson(SESSIONS_FILE, {})));
function persistUsers()    { saveJson(USERS_FILE, users); }
function persistSessions() { saveJson(SESSIONS_FILE, Object.fromEntries(sessions)); }

const findUserByEmail     = (e) => users.find(u => u.email.toLowerCase() === String(e || "").toLowerCase());
const findUserById        = (id) => users.find(u => u.id === id);
const findUserByGoogleSub = (sub) => users.find(u => u.googleSub === sub);

function makeSession(userId) {
  const sid = crypto.randomBytes(24).toString("hex");
  sessions.set(sid, userId);
  persistSessions();
  return sid;
}
function getUserFromCookie(cookieStr) {
  if (!cookieStr) return null;
  const m = String(cookieStr).match(/cs_session=([^;]+)/);
  if (!m) return null;
  const uid = sessions.get(decodeURIComponent(m[1]));
  return uid ? findUserById(uid) : null;
}
function getUserFromReq(req) { return getUserFromCookie(req.headers.cookie); }
function publicUser(u) {
  if (!u) return null;
  return { id: u.id, email: u.email, name: u.name, plan: u.plan || "free" };
}

const PLAN_RANK = { free: 0, unlimited: 1, super: 2 };
const hasPlan = (u, min) => u && PLAN_RANK[u.plan || "free"] >= PLAN_RANK[min];

// ---------------- Uploads ----------------
const UPLOAD_DIR = path.join(__dirname, "public", "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename:    (_req, file, cb) => cb(null, nanoid(16) + (path.extname(file.originalname).toLowerCase().slice(0, 8) || "")),
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => /^(image|video)\//.test(file.mimetype) ? cb(null, true) : cb(new Error("Only image/video allowed")),
});

// ---------------- Middleware ----------------
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  next();
});
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
// Static (no implicit /index.html so we control the home page)
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// Page-level auth helper
function requireAuth(planMin) {
  return (req, res, next) => {
    const u = getUserFromReq(req);
    if (!u) return res.redirect("/auth?next=" + encodeURIComponent(req.originalUrl));
    if (planMin && !hasPlan(u, planMin)) return res.redirect("/subscribe?need=" + planMin);
    req.user = u;
    next();
  };
}

// ---------------- Page routes ----------------
app.get("/",          (req, res) => res.sendFile(path.join(__dirname, "public", "home.html")));
app.get("/auth",      (req, res) => res.sendFile(path.join(__dirname, "public", "auth.html")));
app.get("/subscribe", requireAuth(),            (req, res) => res.sendFile(path.join(__dirname, "public", "subscribe.html")));
app.get("/play",      requireAuth(),            (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/openings",  requireAuth(),            (req, res) => res.sendFile(path.join(__dirname, "public", "openings.html")));
app.get("/classroom", requireAuth(),            (req, res) => res.sendFile(path.join(__dirname, "public", "classroom.html")));
app.get("/groups",    requireAuth(),            (req, res) => res.sendFile(path.join(__dirname, "public", "groups.html")));
app.get("/review",    requireAuth("unlimited"), (req, res) => res.sendFile(path.join(__dirname, "public", "review.html")));
app.get("/ai",        requireAuth("super"),     (req, res) => res.sendFile(path.join(__dirname, "public", "ai.html")));

// ---------------- Auth API ----------------
app.post("/api/signup", async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
  if (String(password).length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
  if (findUserByEmail(email))      return res.status(409).json({ error: "An account with this email already exists" });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: nanoid(12),
    email: String(email).toLowerCase().trim(),
    name: String(name || email.split("@")[0]).slice(0, 40),
    passwordHash,
    plan: "free",
    createdAt: Date.now(),
  };
  users.push(user); persistUsers();
  const sid = makeSession(user.id);
  res.cookie("cs_session", sid, { httpOnly: true, sameSite: "lax", maxAge: 30 * 24 * 3600 * 1000 });
  res.json({ user: publicUser(user) });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  const u = findUserByEmail(email);
  if (!u || !u.passwordHash) return res.status(401).json({ error: "Invalid email or password" });
  const ok = await bcrypt.compare(String(password || ""), u.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid email or password" });
  const sid = makeSession(u.id);
  res.cookie("cs_session", sid, { httpOnly: true, sameSite: "lax", maxAge: 30 * 24 * 3600 * 1000 });
  res.json({ user: publicUser(u) });
});

app.post("/api/logout", (req, res) => {
  const m = (req.headers.cookie || "").match(/cs_session=([^;]+)/);
  if (m) { sessions.delete(decodeURIComponent(m[1])); persistSessions(); }
  res.clearCookie("cs_session");
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  res.json({
    user: publicUser(getUserFromReq(req)),
    googleClientId: process.env.GOOGLE_CLIENT_ID || null,
    aiEnabled: true,
  });
});

app.post("/api/google-auth", async (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID) return res.status(400).json({ error: "Google sign-in is not configured on this server" });
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: "Missing credential" });
  try {
    const { OAuth2Client } = require("google-auth-library");
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const p = ticket.getPayload();
    let u = findUserByGoogleSub(p.sub) || findUserByEmail(p.email);
    if (!u) {
      u = {
        id: nanoid(12),
        email: String(p.email).toLowerCase(),
        name: p.name || p.email.split("@")[0],
        googleSub: p.sub,
        plan: "free",
        createdAt: Date.now(),
      };
      users.push(u);
    } else if (!u.googleSub) {
      u.googleSub = p.sub; // link existing account
    }
    persistUsers();
    const sid = makeSession(u.id);
    res.cookie("cs_session", sid, { httpOnly: true, sameSite: "lax", maxAge: 30 * 24 * 3600 * 1000 });
    res.json({ user: publicUser(u) });
  } catch (e) {
    console.error("Google auth failed:", e.message);
    res.status(401).json({ error: "Could not verify Google sign-in" });
  }
});

app.post("/api/subscribe", (req, res) => {
  const u = getUserFromReq(req);
  if (!u) return res.status(401).json({ error: "Not signed in" });
  const { plan, code } = req.body || {};
  if (!["free", "unlimited", "super"].includes(plan)) return res.status(400).json({ error: "Invalid plan" });
  if (plan === "free") { u.plan = "free"; persistUsers(); return res.json({ user: publicUser(u) }); }
  if (String(code || "").trim() === "2014") {
    u.plan = plan; persistUsers();
    return res.json({ user: publicUser(u), unlocked: true });
  }
  return res.status(402).json({ error: "Payments are not enabled yet. Use the secret access code to unlock." });
});

// ---------------- Upload API ----------------
app.post("/api/upload", (req, res, next) => {
  if (!getUserFromReq(req)) return res.status(401).json({ error: "Not signed in" });
  next();
}, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  res.json({ url: "/uploads/" + req.file.filename, type: req.file.mimetype, name: req.file.originalname, size: req.file.size });
});

// ---------------- AI Chat (Super Unlimited) ----------------
// Uses Pollinations.ai — a free, no-API-key text endpoint that exposes an
// OpenAI-compatible chat-completions API. https://text.pollinations.ai/
app.post("/api/ai/chat", async (req, res) => {
  const u = getUserFromReq(req);
  if (!hasPlan(u, "super")) return res.status(403).json({ error: "Super Unlimited plan required" });
  const { messages, fen } = req.body || {};
  const userMsgs = Array.isArray(messages)
    ? messages.slice(-12).map(m => ({ role: m.role === "assistant" ? "assistant" : "user", content: String(m.content || "").slice(0, 4000) }))
    : [];
  const sys = "You are Chesstudy AI, an expert chess coach. Be concise and concrete. Use standard chess notation (SAN). When the user gives a position (FEN) or move list, analyse it briefly: name the opening if known, state the imbalances, suggest a plan, and recommend a candidate move with a one-line reason." + (fen ? "\nCurrent position FEN: " + fen : "");

  try {
    const r = await fetch("https://text.pollinations.ai/openai", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "openai",
        messages: [{ role: "system", content: sys }, ...userMsgs],
        temperature: 0.5,
        private: true,
      }),
    });
    if (!r.ok) {
      const errText = await r.text().catch(() => "");
      console.error("Pollinations error:", r.status, errText.slice(0, 200));
      return res.status(502).json({ error: "AI service is busy — please try again in a moment." });
    }
    const ct = r.headers.get("content-type") || "";
    let reply = "";
    if (ct.includes("application/json")) {
      const data = await r.json();
      reply = data.choices?.[0]?.message?.content || data.reply || "";
    } else {
      reply = await r.text();
    }
    reply = (reply || "").trim() || "(no response)";
    res.json({ reply });
  } catch (e) {
    console.error("AI chat failed:", e.message);
    res.status(500).json({ error: "AI service unavailable: " + e.message });
  }
});

// ---------------- HTTP server + WS routing ----------------
const server = http.createServer(app);
const wss  = new WebSocketServer({ noServer: true }); // /ws  - classroom
const gwss = new WebSocketServer({ noServer: true }); // /ws-groups

server.on("upgrade", (req, socket, head) => {
  const url = req.url || "";
  if (url.startsWith("/ws-groups")) {
    const user = getUserFromCookie(req.headers.cookie);
    if (!user) { socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n"); socket.destroy(); return; }
    gwss.handleUpgrade(req, socket, head, (ws) => { ws._user = user; gwss.emit("connection", ws, req); });
  } else if (url.startsWith("/ws")) {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
  } else {
    socket.destroy();
  }
});

/* =========================================================================
   CLASSROOM (unchanged from previous version)
   ========================================================================= */
const rooms = new Map();
function send(ws, obj) { if (ws.readyState === 1) ws.send(JSON.stringify(obj)); }
function broadcast(room, obj, exceptId) {
  for (const [id, c] of room.clients) if (id !== exceptId) send(c.ws, obj);
}
function roomSummary(room) {
  const participants = [];
  for (const [id, c] of room.clients) {
    participants.push({ id, name: c.name, muted: !!c.muted, videoOn: !!c.videoOn, isHost: id === room.hostId });
  }
  return { hostId: room.hostId, participants, fen: room.fen, chat: room.chat.slice(-100), moves: room.moves };
}
wss.on("connection", (ws) => {
  let clientId = null, roomId = null;
  ws.on("message", (data) => {
    let msg; try { msg = JSON.parse(data); } catch { return; }
    if (msg.type === "create") {
      roomId = nanoid(6).toUpperCase(); clientId = nanoid(10);
      const room = { hostId: clientId, clients: new Map(), fen: "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", chat: [], moves: [] };
      room.clients.set(clientId, { ws, name: msg.name || "Host", muted: false, videoOn: false });
      rooms.set(roomId, room);
      send(ws, { type: "joined", roomId, clientId, state: roomSummary(room) });
      return;
    }
    if (msg.type === "join") {
      const room = rooms.get(msg.roomId);
      if (!room) return send(ws, { type: "error", message: "Room not found" });
      roomId = msg.roomId; clientId = nanoid(10);
      room.clients.set(clientId, { ws, name: msg.name || "Guest", muted: false, videoOn: false });
      send(ws, { type: "joined", roomId, clientId, state: roomSummary(room) });
      broadcast(room, { type: "participant-joined", clientId, name: msg.name, isHost: false }, clientId);
      return;
    }
    if (!roomId || !rooms.has(roomId)) return;
    const room = rooms.get(roomId);
    if (msg.type === "move" && clientId === room.hostId) {
      room.fen = msg.fen; room.moves = msg.moves || room.moves;
      broadcast(room, { type: "board-update", fen: msg.fen, moves: room.moves, lastMove: msg.lastMove }, clientId);
    } else if (msg.type === "reset-board" && clientId === room.hostId) {
      room.fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"; room.moves = [];
      broadcast(room, { type: "board-update", fen: room.fen, moves: [], lastMove: null });
    } else if (msg.type === "chat") {
      const entry = { id: nanoid(8), clientId, name: room.clients.get(clientId)?.name || "?", text: String(msg.text || "").slice(0, 500), ts: Date.now() };
      room.chat.push(entry);
      if (room.chat.length > 500) room.chat.shift();
      broadcast(room, { type: "chat", entry });
    } else if (msg.type === "mute") {
      const c = room.clients.get(clientId); if (c) c.muted = !!msg.muted;
      broadcast(room, { type: "status-update", clientId, muted: !!msg.muted });
    } else if (msg.type === "video") {
      const c = room.clients.get(clientId); if (c) c.videoOn = !!msg.videoOn;
      broadcast(room, { type: "status-update", clientId, videoOn: !!msg.videoOn });
    } else if (msg.type === "rename") {
      const c = room.clients.get(clientId); if (!c) return;
      const newName = String(msg.name || "").trim().slice(0, 40) || (clientId === room.hostId ? "Host" : "Guest");
      const oldName = c.name;
      c.name = newName;
      broadcast(room, { type: "status-update", clientId, name: newName });
      if (oldName !== newName) {
        const sysEntry = { id: nanoid(8), clientId: null, name: "system", text: `${oldName} is now known as ${newName}`, ts: Date.now(), system: true };
        room.chat.push(sysEntry);
        broadcast(room, { type: "chat", entry: sysEntry });
      }
    } else if (msg.type === "rtc-offer" || msg.type === "rtc-answer" || msg.type === "rtc-ice") {
      const target = room.clients.get(msg.target);
      if (target) send(target.ws, { ...msg, from: clientId });
    }
  });
  ws.on("close", () => {
    if (!roomId || !clientId) return;
    const room = rooms.get(roomId); if (!room) return;
    room.clients.delete(clientId);
    if (room.clients.size === 0) { rooms.delete(roomId); return; }
    if (room.hostId === clientId) {
      const next = room.clients.keys().next().value;
      room.hostId = next;
      broadcast(room, { type: "host-changed", hostId: next });
    }
    broadcast(room, { type: "participant-left", clientId });
  });
});

/* =========================================================================
   GROUPS — persistent across restarts; do not delete empty groups
   ========================================================================= */
const groups = new Map();
const gconns = new Map(); // ws -> { userId, name, code }

function persistGroups() {
  const out = {};
  for (const [code, g] of groups) {
    const members = {};
    for (const [uid, m] of g.members) members[uid] = { name: m.name };
    out[code] = {
      code: g.code, name: g.name, isPrivate: g.isPrivate,
      hostUserId: g.hostUserId, members, posts: g.posts, createdAt: g.createdAt,
    };
  }
  saveJson(GROUPS_FILE, out);
}
function loadGroupsFromDisk() {
  const raw = loadJson(GROUPS_FILE, {});
  for (const [code, g] of Object.entries(raw)) {
    const members = new Map();
    for (const [uid, m] of Object.entries(g.members || {})) members.set(uid, { name: m.name, sockets: new Set() });
    groups.set(code, {
      code: g.code || code, name: g.name || "Group", isPrivate: !!g.isPrivate,
      hostUserId: g.hostUserId, members, posts: Array.isArray(g.posts) ? g.posts : [],
      createdAt: g.createdAt || Date.now(),
    });
  }
}
loadGroupsFromDisk();

function gsend(ws, obj) { if (ws.readyState === 1) ws.send(JSON.stringify(obj)); }
function gbroadcast(group, obj) {
  for (const m of group.members.values()) for (const s of m.sockets) gsend(s, obj);
}
function groupSnapshot(group) {
  const members = [];
  for (const [uid, m] of group.members) {
    members.push({ userId: uid, name: m.name, online: m.sockets.size > 0, isHost: uid === group.hostUserId });
  }
  return { code: group.code, name: group.name, isPrivate: group.isPrivate, hostUserId: group.hostUserId, members, posts: group.posts.slice(-200) };
}
function genCode() {
  let code; do { code = nanoid(6).toUpperCase(); } while (groups.has(code));
  return code;
}

function leaveCurrentGroup(ws) {
  const conn = gconns.get(ws);
  if (!conn || !conn.code) return;
  const group = groups.get(conn.code);
  conn.code = null;
  if (!group) return;
  const m = group.members.get(conn.userId);
  if (m) {
    m.sockets.delete(ws);
    // Always keep memberships persisted; only update presence.
    gbroadcast(group, { type: "presence", userId: conn.userId, online: m.sockets.size > 0 });
  }
  // Note: we intentionally do NOT delete empty groups — host can return later.
}

gwss.on("connection", (ws) => {
  // Authed user from upgrade handshake
  const authedUser = ws._user;
  gconns.set(ws, { userId: authedUser.id, name: authedUser.name, code: null });

  // Auto-hello so the client doesn't need to send identity
  gsend(ws, { type: "hello-ok", userId: authedUser.id, name: authedUser.name });
  // Send a list of groups this user is a member of
  const myGroups = [];
  for (const g of groups.values()) {
    if (g.members.has(authedUser.id)) {
      myGroups.push({ code: g.code, name: g.name, isPrivate: g.isPrivate, isHost: g.hostUserId === authedUser.id, memberCount: g.members.size });
    }
  }
  gsend(ws, { type: "my-groups", groups: myGroups });

  ws.on("message", (data) => {
    let msg; try { msg = JSON.parse(data); } catch { return; }
    const conn = gconns.get(ws);
    if (!conn) return;

    if (msg.type === "create") {
      leaveCurrentGroup(ws);
      const code = genCode();
      const group = {
        code, name: String(msg.groupName || "New Group").slice(0, 60),
        isPrivate: !!msg.isPrivate, hostUserId: conn.userId,
        members: new Map(), posts: [], createdAt: Date.now(),
      };
      group.members.set(conn.userId, { name: conn.name, sockets: new Set([ws]) });
      groups.set(code, group);
      conn.code = code;
      persistGroups();
      gsend(ws, { type: "joined", group: groupSnapshot(group) });
      return;
    }

    if (msg.type === "join") {
      const code = String(msg.code || "").toUpperCase();
      const group = groups.get(code);
      if (!group) return gsend(ws, { type: "error", message: "Group not found" });
      leaveCurrentGroup(ws);
      let m = group.members.get(conn.userId);
      if (!m) {
        m = { name: conn.name, sockets: new Set([ws]) };
        group.members.set(conn.userId, m);
        conn.code = code;
        persistGroups();
        gsend(ws, { type: "joined", group: groupSnapshot(group) });
        gbroadcast(group, { type: "member-joined", member: { userId: conn.userId, name: conn.name, online: true, isHost: false } });
      } else {
        m.name = conn.name;
        m.sockets.add(ws);
        conn.code = code;
        gsend(ws, { type: "joined", group: groupSnapshot(group) });
        gbroadcast(group, { type: "presence", userId: conn.userId, online: true });
      }
      return;
    }

    if (msg.type === "leave") { leaveCurrentGroup(ws); return; }

    if (!conn.code) return;
    const group = groups.get(conn.code);
    if (!group) return;

    if (msg.type === "post") {
      const text = String(msg.text || "").slice(0, 2000);
      const media = Array.isArray(msg.media) ? msg.media.slice(0, 6).map(x => ({
        url:  String(x.url  || "").slice(0, 300),
        type: String(x.type || "").slice(0, 60),
        name: String(x.name || "").slice(0, 200),
      })).filter(x => x.url) : [];
      if (!text && !media.length) return;
      const post = { id: nanoid(10), authorId: conn.userId, authorName: group.members.get(conn.userId)?.name || conn.name, text, media, ts: Date.now() };
      group.posts.push(post);
      if (group.posts.length > 1000) group.posts.shift();
      persistGroups();
      gbroadcast(group, { type: "new-post", post });
      return;
    }

    if (msg.type === "delete-post") {
      const idx = group.posts.findIndex(p => p.id === msg.id);
      if (idx < 0) return;
      const p = group.posts[idx];
      if (p.authorId !== conn.userId && conn.userId !== group.hostUserId) return;
      group.posts.splice(idx, 1);
      persistGroups();
      gbroadcast(group, { type: "post-deleted", id: msg.id });
      return;
    }

    if (msg.type === "kick") {
      if (conn.userId !== group.hostUserId) return;
      const targetId = String(msg.targetUserId || "");
      if (!targetId || targetId === group.hostUserId) return;
      const target = group.members.get(targetId);
      if (!target) return;
      for (const s of target.sockets) {
        gsend(s, { type: "kicked", code: group.code });
        const tc = gconns.get(s); if (tc) tc.code = null;
      }
      group.members.delete(targetId);
      persistGroups();
      gbroadcast(group, { type: "member-left", userId: targetId, kicked: true });
      return;
    }

    if (msg.type === "update-settings") {
      if (conn.userId !== group.hostUserId) return;
      if (typeof msg.isPrivate === "boolean") group.isPrivate = msg.isPrivate;
      if (typeof msg.groupName === "string")  group.name = msg.groupName.slice(0, 60) || group.name;
      persistGroups();
      gbroadcast(group, { type: "settings", name: group.name, isPrivate: group.isPrivate });
      return;
    }

    if (msg.type === "rename-self") {
      const newName = String(msg.name || "").slice(0, 40).trim();
      if (!newName) return;
      conn.name = newName;
      const m = group.members.get(conn.userId);
      if (m) m.name = newName;
      persistGroups();
      gbroadcast(group, { type: "member-renamed", userId: conn.userId, name: newName });
      return;
    }

    if (msg.type === "leave-membership") {
      // Permanently leave the group
      const isHost = conn.userId === group.hostUserId;
      group.members.delete(conn.userId);
      conn.code = null;
      persistGroups();
      if (isHost && group.members.size > 0) {
        // promote arbitrary member to host
        const newHost = group.members.keys().next().value;
        group.hostUserId = newHost;
        persistGroups();
        gbroadcast(group, { type: "host-changed", hostUserId: newHost });
      }
      gbroadcast(group, { type: "member-left", userId: conn.userId });
      return;
    }
  });

  ws.on("close", () => {
    leaveCurrentGroup(ws);
    gconns.delete(ws);
  });
});

const PORT = 5000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Chesstudy server on :${PORT}`);
});
