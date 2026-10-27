# VaultX

A lightweight, self-hosted, zero-knowledge password manager built with TypeScript, Node.js, and SQLite / Turso.

Plaintext credentials and master passwords never leave your browser. All encryption and key derivation happens locally on the client using the native Web Crypto API.

---

## Features

- **Zero-Knowledge Architecture:** Master password and vault items are never transmitted to or stored on the server in plaintext.
- **Client-Side Derivation (PBKDF2):** Derives a 256-bit authentication hash (`authHash`) and an independent 256-bit AES-GCM vault encryption key (`vaultKey`) over 300,000 rounds.
- **Full Field Encryption:** Encrypts complete credential records (name, username, password, URL, notes) into a single AES-256-GCM blob. No metadata is leaked into separate columns.
- **Breach Detection ($k$-Anonymity):** Checks passwords against HaveIBeenPwned's API using 5-character SHA-1 prefixes without exposing the password.
- **Secure Send:** End-to-end encrypted, self-destructing secret sharing with view limits, expiration timers, and optional PIN derivation.
- **Two-Factor Authentication:** TOTP (RFC 6238) with QR code setup compatible with Google Authenticator and Authy.
- **Import & Export:** JSON vault backups and CSV import/export compatible with Bitwarden and Google Chrome.
- **Database Flexibility:** Runs on local SQLite (`vault.db`) in development or **Turso Cloud** (`@libsql/client`) for free 24/7 cloud persistence.

---

## How It Works

```text
[Browser / Client]
  |
  +-- Master Password + Salt
  |     \--> PBKDF2 (300,000 rounds)
  |            +--> AuthKey (SHA-256) ---> POST /api/auth/login ---> Server hashes with bcrypt
  |            \--> VaultKey (AES-256-GCM) ---> Encrypts/Decrypts vault items locally in browser RAM
  |
[Server / Database]
  |
  \-- Stores only user bcrypt hashes, encrypted vault blobs, and random IVs.
```

---

## Getting Started

### Prerequisites
- Node.js 20+ or 22+
- npm 10+

### Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/ShubhamAg01/VaultX.git
cd VaultX

# 2. Install dependencies
npm install

# 3. Set environment variables
cp .env.example .env

# 4. Start the development server
npm run dev
```

Visit `http://localhost:3000`. The first account registered automatically receives administrator privileges. Subsequent registrations require an invite link generated from the admin panel.

---

## Testing & Build

```bash
# Run unit and integration tests
npm test

# Type-check TypeScript codebase
npm run typecheck

# Production build
npm run build
```

---

## Deployment (Render + Turso)

1. **Database:** Create a free database at [Turso](https://turso.tech) and get your database URL (`libsql://...`) and auth token.
2. **Web Service:** Deploy to [Render](https://render.com) as a Node web service:
   - **Build Command:** `npm install && npm run build`
   - **Start Command:** `npm start`
   - **Environment Variables:**
     - `NODE_ENV=production`
     - `JWT_SECRET=<your-random-secret>`
     - `TURSO_DATABASE_URL=<your-turso-url>`
     - `TURSO_AUTH_TOKEN=<your-turso-token>`
     - `KEEP_ALIVE_URL=https://<your-app>.onrender.com` *(optional: prevents free-tier sleep)*

---

## License

MIT
