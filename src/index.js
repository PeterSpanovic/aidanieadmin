/**
 * DanieAI Admin Panel – Cloudflare Worker
 * Routes:  /          → login page
 *          /admin     → admin panel HTML shell
 *          /api/*     → proxied Supabase queries (server-side, uses service_role key)
 */

const ADMIN_PASSWORD_HASH_ENV = "ADMIN_PASSWORD_HASH"; // bcrypt hash stored in secret
const SESSION_COOKIE = "danieai_admin_session";
const SESSION_SECRET_ENV = "SESSION_SECRET";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ── Static assets ────────────────────────────────────────────────
    if (url.pathname === "/" || url.pathname === "/login") {
      return loginPage();
    }

    // ── Auth endpoint ────────────────────────────────────────────────
    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      return handleLogin(request, env);
    }
    if (url.pathname === "/api/auth/logout") {
      return handleLogout();
    }

    // ── Protected routes ─────────────────────────────────────────────
    const session = await verifySession(request, env);
    if (!session) {
      return Response.redirect(new URL("/", request.url).toString(), 302);
    }

    if (url.pathname === "/admin") {
      return adminShell();
    }

    // ── API proxy ────────────────────────────────────────────────────
    if (url.pathname.startsWith("/api/data/")) {
      return handleDataApi(url.pathname, url.searchParams, env);
    }

    return new Response("Not Found", { status: 404 });
  },
};

// ────────────────────────────────────────────────────────────────────
// Auth helpers
// ────────────────────────────────────────────────────────────────────

async function verifySession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = parseCookie(cookie, SESSION_COOKIE);
  if (!token) return null;
  try {
    const [data, sig] = token.split(".");
    const expected = await hmac(env[SESSION_SECRET_ENV] || "fallback-secret", data);
    if (expected !== sig) return null;
    const payload = JSON.parse(atob(data));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const { password } = body;

  const adminPass = env["ADMIN_PASSWORD"] || "admin";
  if (password !== adminPass) {
    return json({ error: "Invalid password" }, 401);
  }

  const payload = { admin: true, exp: Date.now() + 8 * 60 * 60 * 1000 };
  const data = btoa(JSON.stringify(payload));
  const sig = await hmac(env[SESSION_SECRET_ENV] || "fallback-secret", data);
  const token = `${data}.${sig}`;

  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
    },
  });
}

function handleLogout() {
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
    },
  });
}

async function hmac(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function parseCookie(header, name) {
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

// ────────────────────────────────────────────────────────────────────
// Data API handlers (service_role → bypasses RLS)
// ────────────────────────────────────────────────────────────────────

async function handleDataApi(pathname, params, env) {
  const supabaseUrl = env["SUPABASE_URL"] || "https://mhifcmwoqxuvodqlwddj.supabase.co";
  const serviceKey = env["SUPABASE_SERVICE_KEY"];

  const sb = (path, opts = {}) =>
    fetch(`${supabaseUrl}/rest/v1/${path}`, {
      headers: {
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        "Content-Type": "application/json",
        Prefer: "return=representation",
        ...opts.headers,
      },
      ...opts,
    }).then((r) => r.json());

  const route = pathname.replace("/api/data/", "");

  try {
    if (route === "stats") {
      const [clients, subs, convs, msgs] = await Promise.all([
        sb("clients?select=id"),
        sb("subscriptions?select=status"),
        sb("conversations?select=id"),
        sb("messages?select=id"),
      ]);
      const subStats = subs.reduce((acc, s) => {
        acc[s.status] = (acc[s.status] || 0) + 1;
        return acc;
      }, {});
      return json({
        totalClients: clients.length,
        totalConversations: convs.length,
        totalMessages: msgs.length,
        subStats,
      });
    }

    if (route === "users") {
      const page = parseInt(params.get("page") || "0");
      const limit = 25;
      const offset = page * limit;
      const search = params.get("search") || "";
      const statusFilter = params.get("status") || "";

      let clientQuery = `clients?select=id,name,email,phone,platform,lang,country,is_blocked,age_verified,created_at,subscriptions(id,status,plan,billing_cycle,trial_end,current_period_end,messages_used_today,trial_messages_used)&order=created_at.desc&limit=${limit}&offset=${offset}`;

      if (search) {
        clientQuery += `&or=(name.ilike.*${encodeURIComponent(search)}*,email.ilike.*${encodeURIComponent(search)}*,phone.ilike.*${encodeURIComponent(search)}*)`;
      }

      const clients = await sb(clientQuery);

      if (statusFilter && Array.isArray(clients)) {
        const filtered = clients.filter(
          (c) => c.subscriptions?.[0]?.status === statusFilter
        );
        return json(filtered);
      }

      return json(clients);
    }

    if (route === "conversations") {
      const clientId = params.get("client_id");
      const page = parseInt(params.get("page") || "0");
      const limit = 20;
      const offset = page * limit;

      let query = `conversations?select=id,title,started_at,last_message_at,ended_at,client_id,clients(name,email,phone)&order=last_message_at.desc&limit=${limit}&offset=${offset}`;
      if (clientId) query += `&client_id=eq.${clientId}`;

      const convs = await sb(query);
      return json(convs);
    }

    if (route === "messages") {
      const convId = params.get("conversation_id");
      if (!convId) return json({ error: "conversation_id required" }, 400);

      const msgs = await sb(
        `messages?select=id,role,content,message_type,tokens_used,created_at&conversation_id=eq.${convId}&order=created_at.asc`
      );
      return json(msgs);
    }

    if (route === "client") {
      const id = params.get("id");
      if (!id) return json({ error: "id required" }, 400);
      const client = await sb(
        `clients?select=*,subscriptions(*),conversations(id,title,started_at,last_message_at)&id=eq.${id}`
      );
      return json(Array.isArray(client) ? client[0] : client);
    }

    return json({ error: "Unknown route" }, 404);
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ────────────────────────────────────────────────────────────────────
// HTML pages
// ────────────────────────────────────────────────────────────────────

function loginPage() {
  return new Response(LOGIN_HTML, {
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

function adminShell() {
  return new Response(ADMIN_HTML, {
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

// ────────────────────────────────────────────────────────────────────
// Inline HTML – Login
// ────────────────────────────────────────────────────────────────────
const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DanieAI Admin</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Mono:wght@400;500&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0a0a0f;--surface:#111118;--border:#1e1e2e;
    --accent:#c8a96e;--accent2:#7c6fcd;
    --text:#e8e6f0;--muted:#6b6880;
  }
  body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;
    min-height:100vh;display:flex;align-items:center;justify-content:center;
    overflow:hidden;position:relative}
  .bg-grid{position:fixed;inset:0;background-image:
    linear-gradient(var(--border) 1px,transparent 1px),
    linear-gradient(90deg,var(--border) 1px,transparent 1px);
    background-size:48px 48px;opacity:.4;pointer-events:none}
  .glow{position:fixed;width:600px;height:600px;border-radius:50%;
    background:radial-gradient(circle,rgba(124,111,205,.12) 0%,transparent 70%);
    top:50%;left:50%;transform:translate(-50%,-50%);pointer-events:none}
  .card{background:var(--surface);border:1px solid var(--border);
    border-radius:2px;padding:48px 44px;width:380px;
    box-shadow:0 0 0 1px rgba(200,169,110,.06),0 32px 64px rgba(0,0,0,.5);
    position:relative;animation:slideUp .5s ease forwards}
  @keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
  .logo{font-family:'DM Serif Display',serif;font-size:22px;color:var(--accent);
    letter-spacing:.02em;margin-bottom:6px}
  .logo span{font-style:italic;color:var(--accent2)}
  .sub{font-size:11px;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;margin-bottom:40px}
  label{display:block;font-size:10px;letter-spacing:.12em;text-transform:uppercase;
    color:var(--muted);margin-bottom:8px}
  input{width:100%;background:#0d0d14;border:1px solid var(--border);color:var(--text);
    font-family:'DM Mono',monospace;font-size:14px;padding:12px 14px;
    border-radius:2px;outline:none;transition:border-color .2s}
  input:focus{border-color:var(--accent2)}
  .btn{width:100%;margin-top:24px;padding:13px;background:var(--accent);
    color:#0a0a0f;font-family:'DM Mono',monospace;font-size:12px;
    letter-spacing:.1em;text-transform:uppercase;font-weight:500;
    border:none;cursor:pointer;border-radius:2px;transition:all .2s}
  .btn:hover{background:#d4b87a;transform:translateY(-1px)}
  .btn:active{transform:none}
  .err{margin-top:14px;font-size:12px;color:#e05c5c;text-align:center;min-height:18px}
  .corner{position:absolute;width:8px;height:8px;border-color:var(--accent);border-style:solid}
  .tl{top:-1px;left:-1px;border-width:1px 0 0 1px}
  .tr{top:-1px;right:-1px;border-width:1px 1px 0 0}
  .bl{bottom:-1px;left:-1px;border-width:0 0 1px 1px}
  .br{bottom:-1px;right:-1px;border-width:0 1px 1px 0}
</style>
</head>
<body>
<div class="bg-grid"></div><div class="glow"></div>
<div class="card">
  <div class="corner tl"></div><div class="corner tr"></div>
  <div class="corner bl"></div><div class="corner br"></div>
  <div class="logo">Danie<span>AI</span></div>
  <div class="sub">Admin Panel</div>
  <label for="pw">Password</label>
  <input type="password" id="pw" placeholder="Enter admin password" autofocus>
  <button class="btn" id="loginBtn">Access Panel</button>
  <div class="err" id="err"></div>
</div>
<script>
  document.getElementById('loginBtn').addEventListener('click', login);
  document.getElementById('pw').addEventListener('keydown', e => e.key==='Enter' && login());
  async function login(){
    const pw = document.getElementById('pw').value;
    const err = document.getElementById('err');
    const btn = document.getElementById('loginBtn');
    btn.textContent = 'Verifying...'; btn.disabled = true;
    try{
      const r = await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
      const d = await r.json();
      if(d.ok){ window.location.href='/admin'; }
      else{ err.textContent = d.error || 'Invalid credentials'; }
    }catch(e){ err.textContent = 'Connection error'; }
    finally{ btn.textContent='Access Panel'; btn.disabled=false; }
  }
</script>
</body>
</html>`;

// ────────────────────────────────────────────────────────────────────
// Inline HTML – Admin Panel
// ────────────────────────────────────────────────────────────────────
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DanieAI — Admin</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Mono:wght@300;400;500&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#07070e;--surface:#0e0e18;--surface2:#13131f;--border:#1a1a2c;
    --accent:#c8a96e;--accent2:#7c6fcd;--accent3:#5bbf8f;
    --text:#e8e6f0;--muted:#5c5a70;--muted2:#888699;
    --red:#e05c5c;--yellow:#d4a849;--green:#5bbf8f;
  }
  body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;
    min-height:100vh;display:flex;flex-direction:column}

  /* ── TOP NAV ── */
  nav{background:var(--surface);border-bottom:1px solid var(--border);
    padding:0 32px;height:56px;display:flex;align-items:center;gap:24px;
    position:sticky;top:0;z-index:100}
  .logo{font-family:'DM Serif Display',serif;font-size:18px;color:var(--accent);letter-spacing:.02em;margin-right:auto}
  .logo em{font-style:italic;color:var(--accent2)}
  .nav-tab{font-size:11px;letter-spacing:.1em;text-transform:uppercase;
    color:var(--muted2);cursor:pointer;padding:6px 0;border-bottom:2px solid transparent;
    transition:all .2s;white-space:nowrap}
  .nav-tab.active,.nav-tab:hover{color:var(--text);border-bottom-color:var(--accent)}
  .logout{font-size:10px;letter-spacing:.12em;text-transform:uppercase;
    color:var(--muted);cursor:pointer;padding:6px 10px;border:1px solid var(--border);
    border-radius:2px;transition:all .2s;background:none}
  .logout:hover{color:var(--red);border-color:var(--red)}

  /* ── LAYOUT ── */
  .main{display:flex;flex:1;overflow:hidden}
  .content{flex:1;overflow-y:auto;padding:28px 32px}

  /* ── STATS ROW ── */
  .stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:16px;margin-bottom:28px}
  .stat-card{background:var(--surface);border:1px solid var(--border);padding:20px 22px;border-radius:2px;position:relative;overflow:hidden}
  .stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:.6}
  .stat-label{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted2);margin-bottom:8px}
  .stat-val{font-size:28px;font-family:'DM Serif Display',serif;color:var(--accent)}
  .stat-sub{font-size:10px;color:var(--muted);margin-top:4px}

  /* ── TABLE ── */
  .table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:2px;overflow:hidden}
  .table-head{display:flex;align-items:center;gap:12px;padding:16px 20px;border-bottom:1px solid var(--border)}
  .table-head h2{font-family:'DM Serif Display',serif;font-size:17px;color:var(--text);font-weight:400;margin-right:auto}
  .search{background:var(--bg);border:1px solid var(--border);color:var(--text);
    font-family:'DM Mono',monospace;font-size:12px;padding:8px 12px;
    border-radius:2px;outline:none;width:220px;transition:border-color .2s}
  .search:focus{border-color:var(--accent2)}
  select.filter{background:var(--bg);border:1px solid var(--border);color:var(--text);
    font-family:'DM Mono',monospace;font-size:11px;padding:8px 10px;border-radius:2px;outline:none}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{text-align:left;font-size:10px;letter-spacing:.1em;text-transform:uppercase;
    color:var(--muted);padding:12px 16px;border-bottom:1px solid var(--border);
    font-weight:400;white-space:nowrap}
  td{padding:11px 16px;border-bottom:1px solid rgba(255,255,255,.03);vertical-align:middle;
    color:var(--muted2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
  tr:hover td{background:rgba(255,255,255,.02);color:var(--text)}
  tr.clickable{cursor:pointer}
  .badge{display:inline-flex;align-items:center;gap:4px;font-size:10px;
    padding:3px 8px;border-radius:2px;letter-spacing:.06em;text-transform:uppercase;font-weight:500}
  .badge.active{background:rgba(91,191,143,.12);color:var(--green)}
  .badge.trial{background:rgba(200,169,110,.1);color:var(--accent)}
  .badge.cancelled{background:rgba(224,92,92,.1);color:var(--red)}
  .badge.inactive{background:rgba(92,90,112,.15);color:var(--muted2)}
  .badge.past_due{background:rgba(212,168,73,.1);color:var(--yellow)}
  .badge.overlimit{background:rgba(224,92,92,.1);color:var(--red)}
  .badge.blocked{background:rgba(224,92,92,.15);color:var(--red)}
  .badge.vip{background:linear-gradient(135deg,rgba(200,169,110,.2),rgba(124,111,205,.2));color:var(--accent)}
  .badge.plus{background:rgba(124,111,205,.12);color:var(--accent2)}
  .badge.basic{background:rgba(91,191,143,.08);color:var(--green)}
  .dot{width:6px;height:6px;border-radius:50%;background:currentColor}

  /* ── PAGINATION ── */
  .pagination{display:flex;align-items:center;gap:8px;padding:14px 20px;border-top:1px solid var(--border);font-size:11px;color:var(--muted)}
  .page-btn{background:none;border:1px solid var(--border);color:var(--muted2);
    font-family:'DM Mono',monospace;font-size:11px;padding:5px 12px;cursor:pointer;
    border-radius:2px;transition:all .2s}
  .page-btn:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
  .page-btn:disabled{opacity:.3;cursor:default}

  /* ── DETAIL DRAWER ── */
  .drawer-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:200;
    opacity:0;pointer-events:none;transition:opacity .25s;backdrop-filter:blur(4px)}
  .drawer-overlay.open{opacity:1;pointer-events:all}
  .drawer{position:fixed;right:0;top:0;bottom:0;width:520px;
    background:var(--surface);border-left:1px solid var(--border);
    z-index:201;overflow-y:auto;transform:translateX(100%);transition:transform .3s cubic-bezier(.4,0,.2,1)}
  .drawer.open{transform:none}
  .drawer-header{padding:24px 28px 20px;border-bottom:1px solid var(--border);
    display:flex;align-items:flex-start;gap:12px}
  .drawer-header h3{font-family:'DM Serif Display',serif;font-size:20px;font-weight:400;flex:1}
  .drawer-close{background:none;border:none;color:var(--muted);cursor:pointer;
    font-size:20px;line-height:1;padding:4px;transition:color .2s}
  .drawer-close:hover{color:var(--text)}
  .drawer-section{padding:20px 28px;border-bottom:1px solid var(--border)}
  .drawer-section h4{font-size:10px;letter-spacing:.12em;text-transform:uppercase;
    color:var(--muted);margin-bottom:14px}
  .kv-grid{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:12px}
  .kv-key{color:var(--muted2)}
  .kv-val{color:var(--text);word-break:break-all}

  /* ── CONVERSATION LIST in drawer ── */
  .conv-item{padding:10px 0;border-bottom:1px solid rgba(255,255,255,.04);cursor:pointer;
    transition:all .2s}
  .conv-item:hover .conv-title{color:var(--accent)}
  .conv-title{font-size:13px;color:var(--text);margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .conv-meta{font-size:10px;color:var(--muted)}

  /* ── MESSAGE THREAD ── */
  .thread{display:flex;flex-direction:column;gap:10px;padding:16px 28px}
  .msg{padding:10px 14px;border-radius:2px;font-size:12px;line-height:1.6;max-width:90%}
  .msg.user{background:rgba(124,111,205,.1);border-left:2px solid var(--accent2);align-self:flex-end;text-align:right}
  .msg.assistant{background:rgba(200,169,110,.07);border-left:2px solid var(--accent);align-self:flex-start}
  .msg-meta{font-size:10px;color:var(--muted);margin-top:4px}

  /* ── LOADING / EMPTY ── */
  .loading{text-align:center;padding:48px;color:var(--muted);font-size:12px;letter-spacing:.08em}
  .loading::after{content:'';display:inline-block;width:14px;height:14px;
    border:2px solid var(--border);border-top-color:var(--accent);
    border-radius:50%;animation:spin .7s linear infinite;margin-left:10px;vertical-align:middle}
  @keyframes spin{to{transform:rotate(360deg)}}
  .empty{text-align:center;padding:48px;color:var(--muted);font-size:12px}
  .section-hidden{display:none}
  a.plain{color:inherit;text-decoration:none}
</style>
</head>
<body>
<nav>
  <div class="logo">Danie<em>AI</em></div>
  <div class="nav-tab active" data-tab="users">Users</div>
  <div class="nav-tab" data-tab="conversations">Conversations</div>
  <button class="logout" id="logoutBtn">Logout</button>
</nav>
<div class="main">
  <div class="content">

    <!-- Stats -->
    <div class="stats" id="statsRow">
      <div class="stat-card"><div class="stat-label">Total Clients</div><div class="stat-val" id="s-clients">—</div></div>
      <div class="stat-card"><div class="stat-label">Conversations</div><div class="stat-val" id="s-convs">—</div></div>
      <div class="stat-card"><div class="stat-label">Messages</div><div class="stat-val" id="s-msgs">—</div></div>
      <div class="stat-card"><div class="stat-label">Active Subs</div><div class="stat-val" id="s-active" style="color:var(--green)">—</div><div class="stat-sub" id="s-trial-info"></div></div>
    </div>

    <!-- Users tab -->
    <div id="tab-users">
      <div class="table-wrap">
        <div class="table-head">
          <h2>Users</h2>
          <input class="search" type="text" id="userSearch" placeholder="Search name, email, phone…">
          <select class="filter" id="statusFilter">
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="trial">Trial</option>
            <option value="cancelled">Cancelled</option>
            <option value="inactive">Inactive</option>
            <option value="past_due">Past Due</option>
            <option value="overlimit">Over Limit</option>
          </select>
        </div>
        <div id="usersBody"></div>
        <div class="pagination">
          <button class="page-btn" id="userPrev" disabled>← Prev</button>
          <span id="userPageLabel">Page 1</span>
          <button class="page-btn" id="userNext">Next →</button>
        </div>
      </div>
    </div>

    <!-- Conversations tab -->
    <div id="tab-conversations" class="section-hidden">
      <div class="table-wrap">
        <div class="table-head">
          <h2>Conversations</h2>
        </div>
        <div id="convsBody"></div>
        <div class="pagination">
          <button class="page-btn" id="convPrev" disabled>← Prev</button>
          <span id="convPageLabel">Page 1</span>
          <button class="page-btn" id="convNext">Next →</button>
        </div>
      </div>
    </div>

  </div>
</div>

<!-- Detail Drawer -->
<div class="drawer-overlay" id="drawerOverlay"></div>
<div class="drawer" id="drawer">
  <div class="drawer-header">
    <div style="flex:1">
      <h3 id="drawerTitle">—</h3>
      <div id="drawerSub" style="font-size:11px;color:var(--muted);margin-top:4px"></div>
    </div>
    <button class="drawer-close" id="drawerClose">✕</button>
  </div>
  <div id="drawerContent"></div>
</div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

// ── State ──
let userPage = 0, convPage = 0, userSearch = '', statusFilter = '', activeTab = 'users';

// ── Tabs ──
$$('.nav-tab').forEach(t => t.addEventListener('click', () => {
  $$('.nav-tab').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  activeTab = t.dataset.tab;
  $('#tab-users').style.display = activeTab === 'users' ? '' : 'none';
  $('#tab-conversations').style.display = activeTab === 'conversations' ? '' : 'none';
  if (activeTab === 'conversations') loadConvs();
}));

// ── Logout ──
$('#logoutBtn').addEventListener('click', async () => {
  await fetch('/api/auth/logout');
  window.location.href = '/';
});

// ── Stats ──
async function loadStats() {
  const d = await api('/api/data/stats');
  if (!d) return;
  $('#s-clients').textContent = d.totalClients ?? '—';
  $('#s-convs').textContent = d.totalConversations ?? '—';
  $('#s-msgs').textContent = d.totalMessages ?? '—';
  $('#s-active').textContent = d.subStats?.active ?? 0;
  const trial = d.subStats?.trial ?? 0;
  $('#s-trial-info').textContent = trial ? trial + ' on trial' : '';
}

// ── Users ──
async function loadUsers() {
  const el = $('#usersBody');
  el.innerHTML = '<div class="loading">Loading users</div>';
  const params = new URLSearchParams({ page: userPage });
  if (userSearch) params.set('search', userSearch);
  if (statusFilter) params.set('status', statusFilter);
  const data = await api('/api/data/users?' + params);
  if (!data || data.error) { el.innerHTML = '<div class="empty">Failed to load</div>'; return; }
  if (!data.length) { el.innerHTML = '<div class="empty">No users found</div>'; return; }

  el.innerHTML = \`
  <table>
    <thead><tr>
      <th>Name</th><th>Email / Phone</th><th>Platform</th>
      <th>Plan</th><th>Status</th><th>Msgs Today</th><th>Joined</th>
    </tr></thead>
    <tbody>
    \${data.map(u => {
      const sub = u.subscriptions?.[0] || {};
      return \`<tr class="clickable" onclick="openUser('\${u.id}')">
        <td style="color:var(--text)">\${esc(u.name || '—')}\${u.is_blocked ? ' <span class="badge blocked">blocked</span>' : ''}</td>
        <td>\${esc(u.email || u.phone || '—')}</td>
        <td>\${u.platform ? \`<span class="badge \${u.platform}">\${u.platform}</span>\` : '—'}</td>
        <td>\${sub.plan ? \`<span class="badge \${sub.plan}">\${sub.plan}</span>\` : '—'}</td>
        <td>\${sub.status ? \`<span class="badge \${sub.status}"><span class="dot"></span>\${sub.status}</span>\` : '—'}</td>
        <td>\${sub.messages_used_today ?? '—'}</td>
        <td>\${fmtDate(u.created_at)}</td>
      </tr>\`;
    }).join('')}
    </tbody>
  </table>\`;

  $('#userPrev').disabled = userPage === 0;
  $('#userNext').disabled = data.length < 25;
  $('#userPageLabel').textContent = 'Page ' + (userPage + 1);
}

// search debounce
let searchTimer;
$('#userSearch').addEventListener('input', e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { userPage = 0; userSearch = e.target.value; loadUsers(); }, 350);
});
$('#statusFilter').addEventListener('change', e => { statusFilter = e.target.value; userPage = 0; loadUsers(); });
$('#userPrev').addEventListener('click', () => { userPage--; loadUsers(); });
$('#userNext').addEventListener('click', () => { userPage++; loadUsers(); });

// ── Conversations ──
async function loadConvs() {
  const el = $('#convsBody');
  el.innerHTML = '<div class="loading">Loading conversations</div>';
  const data = await api('/api/data/conversations?page=' + convPage);
  if (!data || data.error) { el.innerHTML = '<div class="empty">Failed to load</div>'; return; }
  if (!data.length) { el.innerHTML = '<div class="empty">No conversations</div>'; return; }

  el.innerHTML = \`
  <table>
    <thead><tr>
      <th>Title</th><th>Client</th><th>Started</th><th>Last Message</th><th>Status</th>
    </tr></thead>
    <tbody>
    \${data.map(c => \`<tr class="clickable" onclick="openConv('\${c.id}',\${JSON.stringify(esc(c.title||'Untitled'))})">
      <td style="color:var(--text)">\${esc(c.title || 'Untitled conversation')}</td>
      <td>\${esc(c.clients?.name || c.clients?.email || '—')}</td>
      <td>\${fmtDate(c.started_at)}</td>
      <td>\${fmtDate(c.last_message_at)}</td>
      <td>\${c.ended_at ? '<span class="badge inactive">ended</span>' : '<span class="badge active"><span class="dot"></span>active</span>'}</td>
    </tr>\`).join('')}
    </tbody>
  </table>\`;

  $('#convPrev').disabled = convPage === 0;
  $('#convNext').disabled = data.length < 20;
  $('#convPageLabel').textContent = 'Page ' + (convPage + 1);
}

$('#convPrev').addEventListener('click', () => { convPage--; loadConvs(); });
$('#convNext').addEventListener('click', () => { convPage++; loadConvs(); });

// ── User detail drawer ──
async function openUser(id) {
  showDrawer('Loading…', '');
  const u = await api('/api/data/client?id=' + id);
  if (!u || u.error) { $('#drawerContent').innerHTML = '<div class="empty">Failed to load</div>'; return; }
  const sub = u.subscriptions?.[0] || {};
  const convs = u.conversations || [];

  $('#drawerTitle').textContent = u.name || 'Unknown';
  $('#drawerSub').textContent = u.email || u.phone || '';

  $('#drawerContent').innerHTML = \`
    <div class="drawer-section">
      <h4>Profile</h4>
      <div class="kv-grid">
        <span class="kv-key">ID</span><span class="kv-val" style="font-size:10px;color:var(--muted)">\${u.id}</span>
        <span class="kv-key">Email</span><span class="kv-val">\${esc(u.email||'—')}</span>
        <span class="kv-key">Phone</span><span class="kv-val">\${esc(u.phone||'—')}</span>
        <span class="kv-key">Platform</span><span class="kv-val">\${u.platform||'—'}</span>
        <span class="kv-key">Country</span><span class="kv-val">\${u.country||'—'}</span>
        <span class="kv-key">Language</span><span class="kv-val">\${u.lang||'—'}</span>
        <span class="kv-key">Age Verified</span><span class="kv-val">\${u.age_verified?'✓ Yes':'No'}</span>
        <span class="kv-key">Blocked</span><span class="kv-val">\${u.is_blocked?'<span class="badge blocked">Yes</span>':'No'}</span>
        <span class="kv-key">Joined</span><span class="kv-val">\${fmtFull(u.created_at)}</span>
      </div>
    </div>
    <div class="drawer-section">
      <h4>Subscription</h4>
      <div class="kv-grid">
        <span class="kv-key">Status</span><span class="kv-val">\${sub.status?'<span class="badge '+sub.status+'"><span class="dot"></span>'+sub.status+'</span>':'—'}</span>
        <span class="kv-key">Plan</span><span class="kv-val">\${sub.plan?'<span class="badge '+sub.plan+'">'+sub.plan+'</span>':'—'}</span>
        <span class="kv-key">Billing</span><span class="kv-val">\${sub.billing_cycle||'—'}</span>
        <span class="kv-key">Period End</span><span class="kv-val">\${fmtDate(sub.current_period_end)}</span>
        <span class="kv-key">Trial End</span><span class="kv-val">\${fmtDate(sub.trial_end)}</span>
        <span class="kv-key">Msgs Today</span><span class="kv-val">\${sub.messages_used_today??'—'}</span>
        <span class="kv-key">Trial Msgs Used</span><span class="kv-val">\${sub.trial_messages_used??'—'}</span>
        <span class="kv-key">Voice Sent</span><span class="kv-val">\${sub.voice_sent_today??'—'}</span>
        <span class="kv-key">Voice Recv</span><span class="kv-val">\${sub.voice_received_today??'—'}</span>
      </div>
    </div>
    <div class="drawer-section">
      <h4>Conversations (\${convs.length})</h4>
      \${convs.length ? convs.map(c=>\`
        <div class="conv-item" onclick="openConv('\${c.id}',\${JSON.stringify(esc(c.title||'Untitled'))})">
          <div class="conv-title">\${esc(c.title||'Untitled conversation')}</div>
          <div class="conv-meta">\${fmtDate(c.started_at)} · last msg \${fmtDate(c.last_message_at)}</div>
        </div>\`).join('') : '<div style="font-size:12px;color:var(--muted)">No conversations yet</div>'}
    </div>
  \`;
}

// ── Conversation detail drawer ──
async function openConv(id, title) {
  showDrawer(title || 'Conversation', 'Loading messages…');
  const msgs = await api('/api/data/messages?conversation_id=' + id);
  if (!msgs || msgs.error) { $('#drawerContent').innerHTML = '<div class="empty">Failed to load</div>'; return; }
  $('#drawerSub').textContent = msgs.length + ' messages';

  if (!msgs.length) {
    $('#drawerContent').innerHTML = '<div class="empty">No messages</div>';
    return;
  }

  $('#drawerContent').innerHTML = \`<div class="thread">\${msgs.map(m=>\`
    <div class="msg \${m.role}">
      <div>\${esc(m.content)}</div>
      <div class="msg-meta">\${m.role} · \${fmtFull(m.created_at)}\${m.tokens_used?' · '+m.tokens_used+' tokens':''}</div>
    </div>\`).join('')}</div>\`;
}

// ── Drawer helpers ──
function showDrawer(title, sub) {
  $('#drawerTitle').textContent = title;
  $('#drawerSub').textContent = sub;
  $('#drawerContent').innerHTML = '<div class="loading">Loading</div>';
  $('#drawer').classList.add('open');
  $('#drawerOverlay').classList.add('open');
}
$('#drawerClose').addEventListener('click', closeDrawer);
$('#drawerOverlay').addEventListener('click', closeDrawer);
function closeDrawer() {
  $('#drawer').classList.remove('open');
  $('#drawerOverlay').classList.remove('open');
}

// ── Helpers ──
async function api(url) {
  try { const r = await fetch(url); return r.json(); }
  catch { return null; }
}
function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtDate(s) {
  if (!s) return '—';
  return new Date(s).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
}
function fmtFull(s) {
  if (!s) return '—';
  return new Date(s).toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
}

// ── Boot ──
loadStats();
loadUsers();
</script>
</body>
</html>`;
