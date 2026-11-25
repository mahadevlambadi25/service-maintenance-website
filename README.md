# Service Maintenance Website & Operations Platform (PRD v2.0)

Full-stack commercial property services website, authenticated staff CMS dashboard, protected recruiting/applicant workspace, seasonal campaign scheduler, completed-project before/after media pipeline, and durable Freshsales CRM integration built to the November 24, 2026 PRD v2.0 specification.

## Quick Start (Node.js >= 24.0.0)

```bash
npm start
# Public website: http://127.0.0.1:3000/
# Staff dashboard: http://127.0.0.1:3000/admin/login
```

Run the full unit and PRD P0 acceptance test suite:

```bash
npm test
```

## Architecture & Module Map

- **Database (`src/db/database.js`, `src/db/seed.js`)**: Native `node:sqlite` (WAL mode) with isolated schemas for:
  1. CMS & Content (`business_settings`, `pages`, `page_revisions`, `testimonials_claims`, `articles`, `redirects`, `audit_log`)
  2. Commercial Leads & Operations (`accounts`, `contacts`, `properties`, `inquiries`, `inquiry_attachments`, `crm_delivery_queue`, `notification_queue`)
  3. Protected Recruiting (`jobs`, `applicants`, `applications`, `application_attachments`, `application_notes`)
  4. Seasonal Campaigns (`campaigns`, `scheduler_health`)
  5. Projects & Media (`media_assets`, `projects`, `project_before_after_pairs`, `project_gallery_items`)
  6. PII-Scrubbed Analytics (`analytics_events`)
- **Security & RBAC (`src/services/auth.js`, `src/lib/crypto.js`, `src/server.js`)**:
  - Per-request CSP nonces, `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, Fetch Metadata filtering, CSRF tokens, scrypt password hashing, and RFC 6238 TOTP MFA.
  - 7 server-enforced RBAC roles (`Platform Administrator`, `Content Editor`, `Approver and Publisher`, `Hiring Owner`, `Hiring Reviewer`, `Project Contributor`, `Analyst`).
- **Media & Document Pipeline (`src/lib/media-processor.js`)**:
  - Magic-byte file signature verification (never trusts browser MIME types).
  - Strips JPEG EXIF/GPS/XMP/IPTC/COM, PNG `eXIf`/`tEXt`/`iTXt`, and WebP `EXIF`/`XMP` metadata.
  - Enforces 20 files/batch, 20 MB/image, 64 MP limits, and separates private originals (`storage/private/originals`) from approved public derivatives (`storage/public/media`).
  - Rejects macro-enabled Word documents (`.docm`) and active PDF scripts on resume uploads (`storage/private/resumes`).
- **Environment Variables (Production)**:
  - `NODE_ENV=production`
  - `PORT`, `HOST`, `BASE_URL`
  - `SESSION_SECRET` (strong random 32+ char secret)
  - `FRESHSALES_DOMAIN`, `FRESHSALES_API_KEY` (when omitted, CRM adapter runs in local sandbox mode)
  - `APP_ENV=staging` (enforces `noindex, nofollow` & `Disallow: /` in `robots.txt`)
