# DanieAI Admin Panel

A secure, single-file Cloudflare Worker admin panel for the DanieAI Supabase database.

## Features

- 🔐 Password-protected login with signed session cookies
- 👥 Users table — name, email, platform, plan, subscription status, messages used
- 💬 Conversations table — with clickable message thread viewer
- 🔗 Client detail drawer — full profile + subscription + conversation history
- 🔍 Search & filter by subscription status
- 📊 Live stats bar (clients, conversations, messages, active subs)
- All data fetched server-side using `service_role` key (bypasses RLS)

---

## Project Structure

\`\`\`
danieai-admin/
├── src/
│   └── index.js          # Single Worker file (all routes + HTML inlined)
├── .github/
│   └── workflows/
│       └── deploy.yml    # Auto-deploy on push to main
├── wrangler.toml         # Cloudflare Worker config
├── package.json
├── .gitignore
└── .dev.vars.example     # Template for local secrets
\`\`\`

---

## Setup

### 1. Clone & install

\`\`\`bash
git clone https://github.com/YOUR_USERNAME/danieai-admin.git
cd danieai-admin
npm install
\`\`\`

### 2. Configure local secrets

\`\`\`bash
cp .dev.vars.example .dev.vars
\`\`\`

Edit `.dev.vars`:

\`\`\`
ADMIN_PASSWORD=your-secure-password
SESSION_SECRET=random-string-32-chars-minimum
SUPABASE_SERVICE_KEY=eyJh...your-service-role-key
\`\`\`

> **Where to find the Supabase service role key:**  
> Supabase Dashboard → Project Settings → API → `service_role` (secret key)

### 3. Run locally

\`\`\`bash
npm run dev
# Opens at http://localhost:8787
\`\`\`

---

## Deployment

### One-time: set Cloudflare secrets

\`\`\`bash
wrangler secret put ADMIN_PASSWORD
wrangler secret put SESSION_SECRET
wrangler secret put SUPABASE_SERVICE_KEY
\`\`\`

### Manual deploy

\`\`\`bash
npm run deploy
\`\`\`

### Auto-deploy via GitHub Actions

Add these secrets to your GitHub repository  
(**Settings → Secrets and variables → Actions**):

| Secret | Where to get it |
|--------|----------------|
| `CF_API_TOKEN` | Cloudflare Dashboard → My Profile → API Tokens → Create Token (use *Edit Cloudflare Workers* template) |
| `CF_ACCOUNT_ID` | Cloudflare Dashboard → right sidebar of Workers page |

Push to `main` → GitHub Action deploys automatically.

---

## Custom Domain (optional)

Uncomment the `[[routes]]` block in `wrangler.toml` and set your domain:

\`\`\`toml
[[routes]]
pattern = "admin.yourdomain.com/*"
zone_name = "yourdomain.com"
\`\`\`

---

## Security Notes

- The `SUPABASE_SERVICE_KEY` **never** leaves the Worker — it's used only for server-side Supabase queries.
- The anon key is **not used** in this panel; all queries use the service role.
- Session tokens are HMAC-SHA256 signed and expire after 8 hours.
- Add IP allowlisting via a Cloudflare Access rule for extra protection.
