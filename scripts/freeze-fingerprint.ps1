param(
    [switch] $Verify
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestPath = Join-Path $projectRoot 'evidence/pre_pentest_target_baseline_2026-10-08.sha256.tsv'
$runtimeRoots = @('app', 'bootstrap', 'config', 'public', 'resources', 'routes')
$standaloneFiles = @('.htaccess', 'storage/.htaccess', 'storage/uploads/.htaccess')
$relativePaths = [System.Collections.Generic.List[string]]::new()

foreach ($runtimeRoot in $runtimeRoots) {
    $directory = Join-Path $projectRoot $runtimeRoot
    if (-not [System.IO.Directory]::Exists($directory)) {
        throw "Missing runtime directory: $runtimeRoot"
    }
    foreach ($file in Get-ChildItem -LiteralPath $directory -Recurse -File -Force) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A runtime file is a reparse point; review it before freezing.'
        }
        if (-not $file.FullName.StartsWith($projectRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'A runtime file resolves outside the project root.'
        }
        $relative = $file.FullName.Substring($projectRoot.Length + 1).Replace('\', '/')
        $allowed = $relative -match '^(app|bootstrap|config|routes)/[^\r\n]+\.php$' -or
            $relative -match '^resources/[^\r\n]+\.php$' -or
            $relative -eq 'resources/css/tailwind.css' -or
            $relative -eq 'public/index.php' -or
            $relative -eq 'public/.htaccess' -or
            $relative -match '^public/assets/css/[^/]+\.css$' -or
            $relative -match '^public/assets/js/[^/]+\.js$' -or
            $relative -match '^public/assets/fonts/[^/]+\.woff2$' -or
            $relative -eq 'public/assets/fonts/ATTRIBUTION.md' -or
            $relative -match '^public/assets/images/[^/]+\.(svg|webp)$'
        if (-not $allowed) {
            throw "Unexpected file in runtime scope: $relative"
        }
        $relativePaths.Add($relative)
    }
}

foreach ($relative in $standaloneFiles) {
    $path = Join-Path $projectRoot $relative
    if (-not [System.IO.File]::Exists($path)) {
        throw "Missing runtime policy file: $relative"
    }
    $relativePaths.Add($relative)
}

$paths = $relativePaths.ToArray()
[System.Array]::Sort($paths, [System.StringComparer]::Ordinal)
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("relative_path`tsha256")
foreach ($relative in $paths) {
    $path = Join-Path $projectRoot $relative
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $lines.Add("$relative`t$hash")
}
$expected = [string]::Join("`n", $lines) + "`n"

if ($Verify) {
    if (-not [System.IO.File]::Exists($manifestPath)) {
        throw 'Freeze manifest does not exist.'
    }
    $actual = [System.IO.File]::ReadAllText($manifestPath, [System.Text.Encoding]::UTF8)
    if (-not [string]::Equals($actual, $expected, [System.StringComparison]::Ordinal)) {
        throw 'Freeze manifest differs from current runtime files.'
    }
    Write-Output "FINGERPRINT_VERIFY=PASS FILES=$($paths.Length)"
    exit 0
}

$manifestDirectory = [System.IO.Path]::GetDirectoryName($manifestPath)
if (-not [System.IO.Directory]::Exists($manifestDirectory)) {
    [System.IO.Directory]::CreateDirectory($manifestDirectory) | Out-Null
}
[System.IO.File]::WriteAllText($manifestPath, $expected, [System.Text.UTF8Encoding]::new($false))
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "FINGERPRINT_CREATED=PASS FILES=$($paths.Length) MANIFEST_SHA256=$manifestHash"
