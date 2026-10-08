<?php
$currentUser = user();
$success = \App\Core\Session::pullFlash('success');
$flashError = \App\Core\Session::pullFlash('error');
$pageTitle = isset($title) ? e($title) . ' | CHIMERA CLOUD' : 'CHIMERA CLOUD';
$requestPath = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/');
$isSecurityArea = str_starts_with($requestPath, '/security');
$isActive = static function (string $path, bool $prefix = false) use ($requestPath): bool {
    return $prefix ? $requestPath === $path || str_starts_with($requestPath, $path . '/') : $requestPath === $path;
};
$roleLabel = $currentUser ? ucwords(str_replace('_', ' ', (string) $currentUser['role'])) : null;
$assetRevision = '20261008-pdv-f01';
?>
<!doctype html>
<html lang="en" class="h-full" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <meta name="description" content="CHIMERA CLOUD adaptive cyber-deception, security monitoring, and protected document operations.">
    <meta name="theme-color" content="#070b12">
    <link rel="icon" href="<?= e(asset('images/chimera-mark.svg') . '?v=' . $assetRevision) ?>" type="image/svg+xml">
    <link rel="preload" href="<?= e(asset('fonts/space-grotesk-latin-variable.woff2') . '?v=' . $assetRevision) ?>" as="font" type="font/woff2" crossorigin>
    <link rel="preload" href="<?= e(asset('fonts/manrope-latin-variable.woff2') . '?v=' . $assetRevision) ?>" as="font" type="font/woff2" crossorigin>
    <title><?= $pageTitle ?></title>
    <script>
        (() => {
            const root = document.documentElement;
            let theme = 'dark';
            try {
                const saved = localStorage.getItem('chimera-theme');
                theme = saved === 'light' || saved === 'dark'
                    ? saved
                    : (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
            } catch (_) {
                theme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
            }
            root.dataset.theme = theme;
        })();
    </script>
    <link rel="stylesheet" href="<?= e(asset('css/tailwind.css') . '?v=' . $assetRevision) ?>">
    <link rel="stylesheet" href="<?= e(asset('css/app.css') . '?v=' . $assetRevision) ?>">
</head>
<body class="min-h-[100dvh] antialiased">
    <a class="skip-link" href="#main-content">Skip to content</a>
    <div class="ambient-grid" aria-hidden="true"></div>

    <header class="site-header">
        <nav class="nav-island" aria-label="Primary navigation">
            <a href="<?= e(url($currentUser ? '/dashboard' : '/')) ?>" class="brand-lockup" aria-label="CHIMERA CLOUD home">
                <span class="brand-mark" aria-hidden="true">
                    <svg class="brand-symbol" viewBox="0 0 48 48" focusable="false">
                        <path class="brand-ring" d="M24 3.5C12.7 3.5 3.5 12.7 3.5 24S12.7 44.5 24 44.5c7.8 0 14.6-4.3 18.1-10.7h-8.3A13.7 13.7 0 0 1 24 37.7 13.7 13.7 0 0 1 10.3 24 13.7 13.7 0 0 1 24 10.3c3.8 0 7.2 1.5 9.8 3.9h8.3A20.5 20.5 0 0 0 24 3.5Z"/>
                        <path class="brand-core-cut" d="m24 14.8 9.2 9.2-9.2 9.2-9.2-9.2 9.2-9.2Z"/>
                        <path class="brand-core" d="m24 19.5 4.5 4.5-4.5 4.5-4.5-4.5 4.5-4.5Z"/>
                    </svg>
                </span>
                <span class="brand-name"><strong>CHIMERA</strong><em>CLOUD</em></span>
            </a>
            <button type="button" class="nav-toggle" aria-controls="primary-menu" aria-expanded="false" aria-label="Open navigation"><span></span><span></span></button>
            <div id="primary-menu" class="nav-menu">
                <?php if ($currentUser): ?>
                    <div class="nav-links">
                        <a href="<?= e(url('/dashboard')) ?>" class="nav-link" <?= $isActive('/dashboard') ? 'aria-current="page"' : '' ?>>Workspace</a>
                        <a href="<?= e(url('/documents')) ?>" class="nav-link" <?= $isActive('/documents', true) ? 'aria-current="page"' : '' ?>>Documents</a>
                        <a href="<?= e(url('/activity')) ?>" class="nav-link" <?= $isActive('/activity') ? 'aria-current="page"' : '' ?>>Activity</a>
                        <?php if ($currentUser['role'] === 'admin'): ?><a href="<?= e(url('/admin')) ?>" class="nav-link" <?= $isActive('/admin', true) ? 'aria-current="page"' : '' ?>>Administration</a><?php endif; ?>
                        <?php if ($currentUser['role'] === 'security_admin'): ?><a href="<?= e(url('/security')) ?>" class="nav-link" <?= $isSecurityArea ? 'aria-current="page"' : '' ?>>Security operations</a><?php endif; ?>
                    </div>
                    <div class="nav-account">
                        <a class="account-chip" href="<?= e(url('/profile')) ?>" <?= $isActive('/profile') ? 'aria-current="page"' : '' ?>>
                            <span class="account-avatar" aria-hidden="true"><?= e(strtoupper(substr((string) $currentUser['name'], 0, 1))) ?></span>
                            <span><strong><?= e($currentUser['name']) ?></strong><small><?= e($roleLabel) ?></small></span>
                        </a>
                        <form action="<?= e(url('/logout')) ?>" method="post" class="logout-form">
                            <?= csrf_field() ?>
                            <button class="icon-button" type="submit" aria-label="Sign out" title="Sign out"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h7a2 2 0 0 0 2-2v-3M10 12h11m-3-3 3 3-3 3"/></svg></button>
                        </form>
                    </div>
                <?php else: ?>
                    <div class="nav-links nav-links-public">
                        <a href="<?= e(url('/')) ?>" class="nav-link" <?= $isActive('/') ? 'aria-current="page"' : '' ?>>Platform</a>
                        <a href="<?= e(url('/about')) ?>" class="nav-link" <?= $isActive('/about') ? 'aria-current="page"' : '' ?>>Architecture</a>
                        <a href="<?= e(url('/login')) ?>" class="nav-link" <?= $isActive('/login') ? 'aria-current="page"' : '' ?>>Sign in</a>
                        <a href="<?= e(url('/register')) ?>" class="button button-primary button-compact">Create account <span class="button-glyph" aria-hidden="true">↗</span></a>
                    </div>
                <?php endif; ?>
                <button type="button" class="theme-switch" data-theme-toggle aria-label="Switch colour theme">
                    <span class="theme-switch-track" aria-hidden="true"><span></span></span>
                    <span data-theme-label>Dark</span>
                </button>
            </div>
        </nav>
        <?php if ($currentUser && $currentUser['role'] === 'security_admin' && $isSecurityArea): ?>
            <nav class="security-rail" aria-label="Security operations">
                <a href="<?= e(url('/security')) ?>" <?= $isActive('/security') || str_starts_with($requestPath, '/security/events/') ? 'aria-current="page"' : '' ?>>Overview</a>
                <a href="<?= e(url('/security/threats')) ?>" <?= $isActive('/security/threats', true) ? 'aria-current="page"' : '' ?>>Assessments</a>
                <a href="<?= e(url('/security/deception')) ?>" <?= $isActive('/security/deception') ? 'aria-current="page"' : '' ?>>Deception</a>
                <a href="<?= e(url('/security/adaptive')) ?>" <?= $isActive('/security/adaptive', true) ? 'aria-current="page"' : '' ?>>Adaptive</a>
                <a href="<?= e(url('/security/analytics')) ?>" <?= $isActive('/security/analytics', true) ? 'aria-current="page"' : '' ?>>Analytics</a>
                <a href="<?= e(url('/security/lab')) ?>" <?= $isActive('/security/lab') ? 'aria-current="page"' : '' ?>>Controlled lab</a>
                <a href="<?= e(url('/security/deployment-readiness')) ?>" <?= $isActive('/security/deployment-readiness') ? 'aria-current="page"' : '' ?>>Readiness</a>
            </nav>
        <?php endif; ?>
    </header>

    <?php if ($success || $flashError): ?>
        <div class="flash-wrap" <?= $flashError ? 'role="alert"' : 'role="status"' ?>><div class="alert <?= $flashError ? 'alert-error' : 'alert-success' ?>"><span class="alert-dot" aria-hidden="true"></span><?= e($flashError ?: $success) ?></div></div>
    <?php endif; ?>

    <main id="main-content"><?= $content ?></main>
    <footer class="site-footer"><div><span class="footer-mark">CHIMERA CLOUD</span><span>Adaptive deception and protected operations.</span></div><p>Controlled academic environment <span aria-hidden="true">/</span> Authorized use only</p></footer>
    <script src="<?= e(asset('js/app.js') . '?v=' . $assetRevision) ?>" defer></script>
</body>
</html>
