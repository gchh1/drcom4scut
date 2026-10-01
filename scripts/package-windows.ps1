param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifest = Get-Content -LiteralPath (Join-Path $repoRoot 'Cargo.toml') -Raw
$versionMatch = [regex]::Match($manifest, '(?m)^version\s*=\s*"([^"]+)"')
if (-not $versionMatch.Success) { throw 'Cannot read package version from Cargo.toml.' }
$version = $versionMatch.Groups[1].Value
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    $localCargo = Join-Path $repoRoot 'target\tooling\cargo\bin\cargo.exe'
    if (-not (Test-Path -LiteralPath $localCargo)) { throw 'Cargo not found. Install Rust before packaging.' }
    $cargo = $localCargo
    $env:RUSTUP_HOME = Join-Path $repoRoot 'target\tooling\rustup'
    $env:CARGO_HOME = Join-Path $repoRoot 'target\tooling\cargo'
}

Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        & $cargo build --release --locked
        if ($LASTEXITCODE -ne 0) { throw "Release build failed with exit code $LASTEXITCODE." }
    }
    $binDir = Join-Path $repoRoot 'target\release'
    $releaseName = "drcom4scut-v$version-windows-x64"
    $distDir = Join-Path $repoRoot 'dist'
    $stageDir = Join-Path $distDir $releaseName
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
    foreach ($name in @('drcom4scut.exe', 'drcom4scut-worker.exe')) {
        $source = Join-Path $binDir $name
        if (-not (Test-Path -LiteralPath $source)) { throw "Missing $source. Build both binaries first." }
        Copy-Item -LiteralPath $source -Destination (Join-Path $stageDir $name) -Force
    }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') -Destination $stageDir -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination $stageDir -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot 'src\default_config.yml') -Destination (Join-Path $stageDir 'config.example.yml') -Force
    $archive = Join-Path $distDir "$releaseName.zip"
    Compress-Archive -LiteralPath $stageDir -DestinationPath $archive -Force
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$archive.sha256", "$hash  $releaseName.zip`n")
    Write-Output "Package: $archive"
    Write-Output "SHA-256: $hash"
} finally {
    Pop-Location
}
