# Deploy CLEARANCE on Hostinger

## Requirements

- PHP **8.1+** (set in hPanel → Advanced → PHP Configuration)
- MySQL database created in hPanel
- SSH/SFTP enabled for the hosting account

## Document root

This app can run with the **project root** as the web root (recommended on shared hosting):

- `index.php` and `.htaccess` at the site root bootstrap `public/index.php`
- `storage/`, `src/`, and `vendor/` stay above direct URL access (blocked by `.htaccess`)

Do **not** point the domain only at `public/` unless you also copy or symlink root `index.php` and root `.htaccess`.

## Database

1. In hPanel → **Databases**, create MySQL DB and user (Hostinger names look like `u899628465_clearance`).
2. Assign the user to the database with **All privileges**.
3. Import via **phpMyAdmin** (if SSH import is unavailable):
   - `database/schema.sql`
   - `database/seed.sql` (development demo data only; skip or replace passwords for production)

On Hostinger, `DB_HOST` is usually `127.0.0.1`.

## Environment (`.env`)

Create `.env` in the site root (same folder as `index.php`). Copy from `.env.example` and set:

| Variable | Production value |
|----------|------------------|
| `DB_HOST` | `127.0.0.1` |
| `DB_NAME` | your Hostinger DB name |
| `DB_USER` | your Hostinger DB user |
| `DB_PASSWORD` | DB password from hPanel |
| `APP_ENV` | `production` |
| `APP_DEBUG` | `0` |
| `APP_BASE_URL` | `https://your-domain.com` (no trailing slash) |

`APP_ENCRYPTION_KEY` is optional; the app will create `storage/app.key` on first request if unset.

## Automated deploy (from your PC)

```powershell
cd c:\xampp\htdocs\CLEARANCE
$env:DEPLOY_SSH_PASSWORD = "your-ssh-password"
$env:DB_PASSWORD = "your-mysql-password"
# optional: $env:DEPLOY_SITE_DOMAIN = "clearancesas.online"
# optional: $env:APP_BASE_URL = "https://clearancesas.online"
python tools/deploy_hostinger.py
```

Add `--import-db` only for a fresh database (runs `schema.sql` and `seed.sql`).

SSH defaults: host `109.106.254.155`, port `65002`, user `u899628465` (override with `DEPLOY_SSH_*`). Deploy targets `clearancesas.online` unless `DEPLOY_SITE_DOMAIN` or `DEPLOY_REMOTE_DIR` is set.

If SSH login fails, reset the SSH password in hPanel → **Advanced → SSH Access** and confirm SSH is **Enabled**.

## Manual deploy (File Manager)

```powershell
python tools/deploy_hostinger.py --pack-only
```

Upload `clearance-hostinger-deploy.zip` to `public_html`, extract, add `.env`, set folder permissions on `storage/` to writable (775).

## Verify

- `GET https://your-domain.com/health` should return JSON OK
- Log in with production accounts (not dev seed passwords if you skipped seed)

## Security

- Never commit `.env` or SSH passwords to git.
- Rotate any credentials that were shared in chat or tickets.
- For production, avoid importing `seed.sql` or change all demo passwords immediately.
