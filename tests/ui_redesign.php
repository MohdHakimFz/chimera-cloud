<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$passed = 0;
$failed = 0;
$check = static function (bool $condition, string $label) use (&$passed, &$failed): void {
    echo ($condition ? '[PASS] ' : '[FAIL] ') . $label . PHP_EOL;
    $condition ? $passed++ : $failed++;
};
$read = static fn (string $path): string => (string) file_get_contents($root . '/' . $path);

$layout = $read('resources/views/layouts/app.php');
$routes = $read('routes/web.php');
$javascript = $read('public/assets/js/app.js');
$css = $read('public/assets/css/app.css');
$tailwind = $read('public/assets/css/tailwind.css');
$headers = $read('app/Security/SecurityHeaders.php');
$manifest = json_decode($read('deployment/infinityfree-manifest.json'), true, 32, JSON_THROW_ON_ERROR);

$requiredAssets = [
    'public/assets/css/app.css',
    'public/assets/css/tailwind.css',
    'public/assets/js/app.js',
    'public/assets/images/chimera-mark.svg',
    'public/assets/fonts/space-grotesk-latin-variable.woff2',
    'public/assets/fonts/manrope-latin-variable.woff2',
    'public/assets/fonts/ibm-plex-mono-latin-500.woff2',
];
foreach ($requiredAssets as $asset) {
    $check(is_file($root . '/' . $asset) && filesize($root . '/' . $asset) > 0, "Redesign asset exists and is non-empty: {$asset}");
}

$check(!str_contains($tailwind, '@tailwind'), 'Production Tailwind asset is compiled rather than shipping source directives');
$check(str_contains($layout, "asset('css/tailwind.css')") && str_contains($layout, "asset('css/app.css')") && str_contains($layout, "asset('js/app.js')"), 'Shared layout references both production stylesheets and the application script');
$check(str_contains($layout, '?v=') && str_contains($layout, '$assetRevision'), 'Shared assets use one deterministic cache revision');
$check(!str_contains($layout . $headers, 'cdn.tailwindcss.com'), 'Runtime presentation has no Tailwind CDN dependency');
$check(str_contains($headers, "script-src 'self' 'unsafe-inline'") && str_contains($headers, "style-src 'self' 'unsafe-inline'"), 'CSP keeps redesigned runtime assets same-origin');
$check(str_contains($layout, 'class="skip-link"') && str_contains($layout, 'id="main-content"'), 'Shared shell provides a keyboard skip target');
$check(str_contains($layout, 'aria-controls="primary-menu"') && str_contains($layout, 'aria-expanded="false"'), 'Mobile navigation has explicit accessible state');
$check(str_contains($layout, 'data-theme-toggle') && str_contains($javascript, "localStorage.setItem('chimera-theme'"), 'Theme control is local presentation state only');
$check(str_contains($css, '@media (prefers-reduced-motion:reduce)') && str_contains($css, 'focus-visible'), 'Styles preserve reduced-motion and visible keyboard-focus behavior');
$check(str_contains($css, '@media (max-width:1100px)') && str_contains($css, '@media (max-width:767px)') && str_contains($css, '@media (max-width:480px)'), 'Styles define desktop, tablet, and mobile adaptations');
$mobileNavigation = explode('@media (max-width:1100px)', $css, 2)[1] ?? '';
$mobileNavigation = explode('@media (max-width:1023px)', $mobileNavigation, 2)[0];
$check(str_contains($mobileNavigation, '.nav-island { backdrop-filter:none; }') && str_contains($mobileNavigation, 'position:fixed; inset:.65rem') && str_contains($mobileNavigation, 'overflow-y:auto'), 'Mobile navigation escapes the filtered header containing block and contains scrollable content');
$check(str_contains($mobileNavigation, 'grid-template-columns:minmax(0,1fr)') && str_contains($mobileNavigation, 'justify-content:stretch') && !str_contains($css, '.account-chip span:last-child { display:none; }'), 'Mobile navigation spans the panel and retains the account identity');
$check(str_contains($mobileNavigation, 'visibility:hidden') && str_contains($mobileNavigation, '.nav-menu.mobile-open { opacity:1; visibility:visible;'), 'Closed mobile navigation is hidden from keyboard focus and opens visibly');

$forms = [
    ['resources/views/auth/login.php', '/login'],
    ['resources/views/auth/register.php', '/register'],
    ['resources/views/layouts/app.php', '/logout'],
    ['resources/views/profile/show.php', '/profile'],
    ['resources/views/documents/index.php', '/documents'],
    ['resources/views/documents/show.php', '/delete'],
    ['resources/views/security/lab.php', '/state'],
];
foreach ($forms as [$path, $actionFragment]) {
    $view = $read($path);
    $check(str_contains(strtolower($view), 'method="post"') && str_contains($view, $actionFragment) && str_contains($view, 'csrf_field()'), "State-changing form remains POST + CSRF: {$path}");
}

preg_match_all('/\$router->post\(/', $routes, $postMatches);
$check(count($postMatches[0]) === 7, 'Route inventory still contains exactly seven business-state POST routes');
foreach (['/login', '/register', '/logout', '/profile', '/documents', '/documents/{id}/delete', '/security/lab/modules/{id}/state'] as $path) {
    $pattern = '/\$router->post\(\'' . preg_quote($path, '/') . '\'.*VerifyCsrf::class/';
    $check(preg_match($pattern, $routes) === 1, "Server-side CSRF middleware remains attached to {$path}");
}
$check(!preg_match('/\$router->get\([^\n]*(?:delete|logout|state)/i', $routes), 'No destructive or session-ending action became GET');
$check(str_contains($routes, "new RequireRole(['admin'])") && str_contains($routes, "new RequireRole(['security_admin'])"), 'Exact Admin and Security Admin route guards remain present');
$check(str_contains($layout, "\$currentUser['role'] === 'admin'") && str_contains($layout, "\$currentUser['role'] === 'security_admin'"), 'Role-aware navigation remains conditional presentation rather than a shared capability');

$presentation = implode("\n", array_map($read, [
    'resources/views/layouts/app.php',
    'resources/views/dashboard/index.php',
    'resources/views/documents/index.php',
    'resources/views/documents/show.php',
    'resources/views/profile/show.php',
    'resources/views/security/index.php',
    'resources/views/security/threats.php',
    'resources/views/security/deception.php',
    'resources/views/security/adaptive.php',
    'resources/views/security/analytics.php',
]));
$check(!preg_match('/\b(source_ip|source_hash|source_safe_identifier|source_identifier|storage_name|token_hash|password_hash)\b/i', $presentation), 'Redesigned presentation contains no protected source, storage, token-hash, or password-hash fields');
$check(!preg_match('#(?:href|src)=["\'][^"\']*/storage/#i', $presentation), 'Redesigned presentation emits no direct private-storage URL');
$check(str_contains($read('resources/views/documents/index.php'), "e(\$document['original_name'])") && str_contains($read('resources/views/documents/show.php'), "e(\$document['original_name'])"), 'Document names remain escaped in list and detail views');
$check(str_contains($layout, "e(\$currentUser['name'])") && str_contains($read('resources/views/admin/index.php'), "e(\$account['email'])"), 'User-controlled identity fields remain escaped');
$check(str_contains($read('resources/views/security/show.php'), "e(json_encode(\$event['metadata']"), 'Sanitized event metadata remains HTML-escaped before rendering');

$check(!str_contains($javascript, 'fetch(') && !str_contains($javascript, 'XMLHttpRequest') && !str_contains($javascript, 'setInterval('), 'Presentation JavaScript performs no API mutation or polling');
$innerHtmlIsStatic = preg_match('/dialog\.innerHTML\s*=\s*`(?<template>.*?)`;/s', $javascript, $dialogMatch) === 1
    && !str_contains($dialogMatch['template'], '${');
$check(substr_count($javascript, 'innerHTML') === 1 && $innerHtmlIsStatic, 'The sole innerHTML use is a static confirmation-dialog template');
$check(str_contains($javascript, "querySelector('[data-confirm-message]').textContent = message"), 'Dynamic confirmation text uses textContent rather than HTML injection');
$check(str_contains($javascript, "event.key === 'Escape'") && str_contains($javascript, "aria-expanded"), 'Mobile navigation supports keyboard dismissal and synchronized ARIA state');

$threatView = $read('resources/views/security/threats.php');
$scoring = $read('app/Services/ThreatScoringService.php');
$check(str_contains($threatView, 'foreach($rules as $type=>$rule)') && !preg_match('/ACCESS_DENIED\s*=\s*\d+/', $threatView), 'Threat UI consumes server scoring policy rather than defining competing weights');
foreach (['ACCESS_DENIED'=>3, 'LOGIN_FAILURE'=>5, 'DOCUMENT_UPLOAD_REJECTED'=>5, 'ROLE_ACCESS_DENIED'=>10, 'SECURITY_RELEVANT_APPLICATION_ERROR'=>10, 'OWNERSHIP_ACCESS_DENIED'=>12, 'CSRF_REJECTED'=>12, 'DOCUMENT_INTEGRITY_FAILURE'=>20, 'DECOY_ACCESSED'=>20, 'HONEYTOKEN_TRIGGERED'=>35] as $event => $weight) {
    $check(str_contains($scoring, "'{$event}' => [{$weight},"), "Locked scoring weight remains {$event}={$weight}");
}
$check(str_contains($scoring, "\$score >= 75 ? 'CRITICAL'") && str_contains($scoring, "\$score >= 45 ? 'HIGH'") && str_contains($scoring, "\$score >= 20 ? 'MEDIUM'") && str_contains($scoring, ": 'LOW'"), 'Locked LOW/MEDIUM/HIGH/CRITICAL thresholds remain unchanged');

$analytics = $read('resources/views/security/analytics.php');
$check(!str_contains($analytics . $javascript, 'Chart(') && !str_contains($analytics . $javascript, 'chart.js'), 'Analytics UI has no undeclared Chart.js runtime dependency');
$check(str_contains($analytics, '$exportUrls[$t]') && str_contains($analytics, '$a[\'filters\']'), 'Analytics view consumes controller-provided safe filters and export contracts');
$lab = $read('resources/views/security/lab.php');
$check(str_contains($lab, 'LAB STATUS:') && str_contains($lab, '$module[\'is_active\']') && str_contains($lab, 'csrf_field()'), 'Controlled LAB UI shows authoritative status and gates CSRF-protected controls');

$check(in_array('public/assets/', $manifest['upload'] ?? [], true), 'Deployment manifest includes redesigned production assets');
$check(in_array('node_modules/', $manifest['do_not_upload'] ?? [], true) && in_array('package.json', $manifest['do_not_upload'] ?? [], true) && in_array('tailwind.config.js', $manifest['do_not_upload'] ?? [], true), 'Deployment manifest excludes local UI build tooling');
$rootPolicy = $read('.htaccess');
$check(str_contains($rootPolicy, 'RewriteRule ^$ public/index.php [QSA,L]') && str_contains($rootPolicy, 'RewriteRule ^assets/fonts/'), 'InfinityFree routing covers the origin root and allowlisted local fonts');

echo PHP_EOL . "{$passed} post-redesign UI checks passed, {$failed} failed, 0 skipped." . PHP_EOL;
exit($failed === 0 ? 0 : 1);
