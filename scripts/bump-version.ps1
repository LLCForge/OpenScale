# Bir sonraki OpenScale sürümünü hesaplar ve VERSION dosyasına yazar
# (ADR-0193). Ara sürüm 0-9 arasında döner (x.9 -> (x+1).0).
#
#   powershell -File scripts\bump-version.ps1 minor|patch|beta|release [-DryRun]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('minor', 'patch', 'beta', 'release')]
    [string]$Kind,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $old = (Get-Content -Raw VERSION).Trim()
    $goArgs = @('run', './cmd/bumpversion', '-file', 'VERSION')
    if (-not $DryRun) { $goArgs += '-w' }
    $goArgs += $Kind
    $new = (& go @goArgs).Trim()
    if ($LASTEXITCODE -ne 0) { throw "bumpversion başarısız" }
    if ($DryRun) { "VERSION (yazılmadı): $old -> $new" } else { "VERSION: $old -> $new" }
}
finally {
    Pop-Location
}
