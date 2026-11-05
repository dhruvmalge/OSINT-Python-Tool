# Consent-based Link Analytics

A small Flask application for campaign links, consent-first redirect tracking,
a protected dashboard, CSV export and QR codes.

## Important hosting/data note

Do **not** use SQLite on Render Free for production data: the free web service has
an ephemeral filesystem, so local database files can disappear on restart/redeploy.
Render's free Postgres currently expires after 30 days. Use a durable PostgreSQL
provider/paid database for data you need to keep, or use this project for a
non-critical demo and expect data loss. Render documents these free-tier limits:
https://render.com/docs/free

## Local run

1. Python 3.11+ recommended.
2. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   # Windows: .venv\Scripts\activate
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Create environment variables. Copy `.env.example` values into your shell or
   use a local `.env` loader of your choice. Generate secrets:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('choose-a-strong-password'))"
   ```

   Set `SECRET_KEY`, `ADMIN_USER`, `ADMIN_PASSWORD_HASH`, and
   `PUBLIC_BASE_URL=http://127.0.0.1:5000`. For local HTTP testing set
   `COOKIE_SECURE=0` and `TRUST_PROXY=0`.

4. Run:

   ```bash
   python app.py
   ```

5. Open `http://127.0.0.1:5000/login`, sign in, create a link, and test it in
   a private/incognito browser window.

## Cloud deployment (Render + durable PostgreSQL)

1. Push this folder to a private GitHub repository.
2. Create a durable PostgreSQL database with a provider of your choice. Copy its
   connection URL. Ensure it uses SSL if the provider requires it.
3. In Render, choose **New → Web Service**, connect the repository, and set:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
   - Health check path: `/health`
4. Add environment variables in Render:
   - `SECRET_KEY`: long random value (do not commit it).
   - `ADMIN_USER`: your admin username.
   - `ADMIN_PASSWORD_HASH`: output of the hash command above.
   - `DATABASE_URL`: PostgreSQL connection URL.
   - `PUBLIC_BASE_URL`: `https://YOUR-SERVICE.onrender.com` (no trailing slash).
   - `TRUST_PROXY=1`, `COOKIE_SECURE=1`, `GEO_LOOKUP=1`,
     `RETENTION_DAYS=90`.
5. Deploy. Visit `/login` and create your first link.

Render free web services sleep after inactivity and have an ephemeral filesystem.
Use an external durable PostgreSQL database if you need persistent analytics.
A free database tier may have its own storage, compute, expiry and backup limits;
check the provider's current terms before relying on it.

Render Flask deployment instructions: https://render.com/docs/deploy-flask
Render free service limits: https://render.com/docs/free

## Privacy and security checklist

- The visitor is shown a notice and chooses whether to enable analytics.
- Declining consent redirects without recording a visit.
- Raw IP addresses are not stored in the app database. If enrichment is enabled,
  the IP is sent to ipwho.is after consent for approximate location/ISP and
  proxy/VPN/Tor signals. Review that provider's current privacy policy and terms.
- Set `GEO_LOOKUP=0` to disable third-party IP enrichment.
- Set `RETENTION_DAYS` to the shortest period that meets your needs. Old records
  are pruned when the dashboard is opened; for strict scheduled deletion, add a
  database maintenance job.
- Keep the admin password hash and `SECRET_KEY` private. Use a strong unique
  admin password. Do not share CSV exports publicly.
- The app uses secure, HTTP-only, SameSite=Lax session cookies. HTTPS is required
  in cloud deployment.
- Configure trusted proxy handling only when deployed behind a trusted proxy.
- Before public/production use, add rate limiting, backups, monitoring, and a
  documented data-request/deletion process. CSRF protection is enabled. The
  current app is a functional starter, not a security-audited SaaS product.
- Follow applicable privacy and data-protection laws and provide a contact
  method in the notice appropriate to your deployment.

## Routes

- `/login` administrator login
- `/dashboard` dashboard (protected)
- `/r/<slug>` consent screen and redirect
- `/privacy` privacy notice
- `/export.csv` protected CSV export
- `/health` health check
