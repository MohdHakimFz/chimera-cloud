# Production Hardening

## Operational modes

**NORMAL / SAFE MODE** is the default: `VULNERABILITY_LAB_ENABLED=false`. The secure application, telemetry, threat assessment, static/adaptive deception, and analytics remain enabled; every `/lab/*` route returns a safe 404.

**AUTHORIZED LAB MODE** requires the operator to set `VULNERABILITY_LAB_ENABLED=true`. It exposes only the synthetic, gated `/lab/*` modules. Real authentication, RBAC, ownership, CSRF, uploads, APIs, telemetry, scoring, and analytics remain unchanged. LAB telemetry stays outside operational scoring. A production readiness check reports a prominent warning; it never toggles the value.

## Configuration and deployment gate

`ProductionSecurityValidator` emits only PASS, WARNING, or FAIL plus non-secret remediation text. It checks environment/debug mode, canonical HTTPS URL, HTTPS enforcement, session cookies, telemetry hashing, database configuration/non-root identity, private storage, upload bounds, writable runtime directories, schema connectivity, `.env` location, and lab mode.

- PASS: required condition is satisfied.
- WARNING: intentional lab mode or hosting-dependent condition needs operator review.
- FAIL: critical missing/unsafe configuration blocks readiness.

Possible gates are `NORMAL_MODE_READY`, `NORMAL_MODE_READY_WITH_WARNING`, `AUTHORIZED_LAB_MODE_READY_WITH_WARNING`, and `BLOCKED`. The gate is informational and cannot deploy. Security Admin sees it at `/security/deployment-readiness`; CLI operators can run `php scripts/check-deployment-readiness.php`.

## Errors, transport, headers, and caching

Production suppresses display errors even if `APP_DEBUG` is accidentally true. Dispatcher and bootstrap failures return generic HTML or JSON and log only server-side. The router emits 405 with `Allow`; explicit safe views exist for 400, 401, 403, 404, 405, 419, 422, 429, and 500 behavior.

HTTPS detection trusts only direct server `HTTPS` or `REQUEST_SCHEME=https`. `X-Forwarded-*` is ignored because no trusted-proxy allowlist exists. `HTTPS_ENFORCE=true` redirects to the configured HTTPS `APP_URL`; operators must enable it only after validating hosting TLS to avoid loops. HSTS (`max-age=31536000`) is emitted only in production when direct HTTPS is detected; subdomains are deliberately not asserted without deployment evidence. Local HTTP receives no HSTS.

Dynamic front-controller responses use CSP with `frame-ancestors 'none'`, X-Frame-Options DENY, nosniff, strict-origin referrer policy, restricted permissions, and private no-store caching. Static assets bypass the front controller and retain normal server caching.

## Sessions and CSRF

Production configuration requires Secure cookies, HttpOnly is hardcoded, SameSite accepts only Lax or Strict, PHP strict/cookie-only session modes are enabled, login/registration regenerate the identifier, and logout deletes the cookie and destroys server state. Every state-changing route is POST plus CSRF; GET analytics/exports are read-only.

## Files, storage, and downloads

Uploads retain size, extension, detected MIME, HTTP-upload, random-name, private-storage, checksum, and ownership controls. Phase 9 additionally rejects executable double extensions and Windows reserved filenames. Control characters and traversal segments are normalized. Internal filenames remain constrained; symlinks, size mismatch, and checksum mismatch fail safely.

Document, quarantine, session, and log directories remain outside application `public/`. In the InfinityFree `/htdocs` topology they are classified `PROTECTED_IN_WEBROOT`, restricted to the exact storage tree, and protected by root plus storage-level Apache denial. Readiness remains blocked with `PENDING LIVE VERIFICATION` until direct HTTP checks have returned 403/404 and the operator records `WEBROOT_DENIAL_VERIFIED=true`. Executable upload extensions remain denied. Recommended permissions are owner/group writable only where supported (commonly 0750/0770 according to hosting ownership; files 0640), never blanket 0777.

## Logging, telemetry, deception, and analytics

Logs must remain outside the web root, access-restricted, rotated by the host or operator, and retained only as long as required for the academic evaluation. Application code does not record passwords, cookies, Authorization/CSRF values, DB passwords, document contents, or honeytoken plaintext.

Telemetry keeps direct-peer attribution and safe hashing; no new fingerprinting was added. Deception remains synthetic/non-functional and cannot authenticate or reach real documents/Admin actions. LAB data remains synthetic and zero-score. Analytics stays Security Admin-only, prepared, bounded, read-only, minimized, and CSV-formula safe.

## Known production limitations

Application-level rate limiting is not implemented because it could alter the verified pentest semantics and shared hosting provides no guaranteed persistent store. Configure hosting/web-server throttling where available and document exclusions for an explicitly authorized lab exercise. Trusted reverse proxies, HSTS support, PHP handler behavior, writable ownership, and log rotation are HOSTING-DEPENDENT and must be verified after upload in Phase 10.

Phase 10's local compatibility implementation does not resolve hosting-dependent items. `php scripts/phase10-hosting-preflight.php` reports them explicitly and combines the result with the production readiness gate without exposing secret values. The repository is ready for a separately authorized NORMAL_SAFE upload, but this is not evidence that live deployment validation has passed.
