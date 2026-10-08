# Shared-hosting Deployment

> General/historical shared-hosting guidance. For the active InfinityFree `/htdocs` target, use `INFINITYFREE_DEPLOYMENT_PLAN.md` and `INFINITYFREE_DEPLOYMENT_MANIFEST.md`; their verified provider constraints supersede the Hostinger/private-root assumptions below.

## Constraints

CHIMERA assumes no root access, containers, background daemons, Redis, custom ports, firewall changes, or kernel controls. All deception remains in HTTP application routes. Scheduled cleanup, if added, must use the host's cron facility or an authenticated maintenance action.

## Hostinger-compatible layout

Prefer mapping the domain or subdomain document root directly to `public/`. If the control panel forces `public_html`, keep `app`, `config`, `database`, `resources`, `storage`, and `.env` above it. Copy public files into `public_html` and adjust `public_html/index.php` to require the actual bootstrap path.

Set `APP_DEBUG=false`, `SESSION_SECURE=true`, and the canonical HTTPS `APP_URL`. Confirm `mod_rewrite` or use a hosting-supported front-controller rule. Make only `storage/logs` and `storage/uploads` writable. Disable directory listings and block dotfiles.

The Phase 1 Tailwind CDN eases initial deployment but requires an external script allowed by CSP. Before a strict production release, generate a fixed local CSS build and remove the CDN allowances.

Import schema and seed through phpMyAdmin or the hosting database console. Change seeded passwords immediately and use a least-privilege database account.
