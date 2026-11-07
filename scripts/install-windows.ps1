#Requires -Version 5.1
<#
.SYNOPSIS
    OpenScale'i Windows'a kurar veya günceller; önce sürümü doğrular (F-170, ADR-0022).

.DESCRIPTION
    1. openscale-windows-amd64.exe geçici, yalnızca bu kullanıcıya ait bir klasöre kopyalanır;
       bundan sonra yalnızca bu kopya kullanılır (doğrulama ile çalıştırma arasında dosya değiştirilemez).
    2. Kopya, imzalı sürüm manifestosuyla (openscale-<sürüm>.release.json) openscale-release-verify
       ile doğrulanır: kök anahtar -> imzalama sertifikası -> manifesto -> dosyanın SHA-256'sı ve boyutu.
       Kurulu sürümden eski bir sürüm reddedilir (geri alma koruması; bilerek dönmek için -AllowDowngrade).
    3. Authenticode imzası varsa denetlenir; bozuksa kurulum durur.
    4. Doğrulanan kopya 'openscale.exe app' ile başlatılır: program yönetici onayı (UAC) ister, kendini
       %ProgramFiles%\OpenScale altına kurar, servisi kurar/günceller ve tepsi simgesini açar.

    Ağdan hiçbir şey indirilmez. İlk kurulumda güvenilir doğrulayıcıyı nasıl edineceğiniz için
    docs/surum-dogrulama.md dosyasındaki 'İlk kurulum' bölümüne bakın.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Verifier C:\Araclar\openscale-release-verify.exe

.EXAMPLE
    # İmzasız bir sürüm (yalnızca SHA256SUMS ile bütünlük denetimi; özgünlük KANITLANMAZ):
    .\install-windows.ps1 -Sha256Only
#>
[CmdletBinding()]
param(
    [string]$Exe = (Join-Path $PSScriptRoot 'openscale-windows-amd64.exe'),
    [string]$Manifest,
    [string]$Verifier,
    [string]$RootKey,
    [string]$RootFingerprint,
    [switch]$AllowDowngrade,
    [switch]$Sha256Only,
    [switch]$NoVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ReleaseExeName = 'openscale-windows-amd64.exe'
$InstallDir = Join-Path $env:ProgramFiles 'OpenScale'
$InstalledExe = Join-Path $InstallDir 'openscale.exe'
$InstalledVerifier = Join-Path $InstallDir 'openscale-release-verify.exe'

function Test-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InstalledVersion {
    if (-not (Test-Path -LiteralPath $InstalledExe -PathType Leaf)) { return $null }
    try {
        $out = & $InstalledExe version 2>$null | Select-Object -First 1
        if ($out -match '^openscale\s+(\S+)') { return $Matches[1] }
    } catch {
        Write-Warning "Kurulu sürüm okunamadı: $($_.Exception.Message)"
    }
    return $null
}

function Find-Manifest([string]$Dir) {
    $found = @(Get-ChildItem -LiteralPath $Dir -Filter 'openscale-*.release.json' -File -ErrorAction SilentlyContinue)
    if ($found.Count -eq 1) { return $found[0].FullName }
    if ($found.Count -gt 1) { throw "Birden fazla imzalı sürüm dosyası var; -Manifest ile seçin." }
    return $null
}

function Find-Verifier {
    if ($Verifier) { return (Resolve-Path -LiteralPath $Verifier).ProviderPath }
    if (Test-Path -LiteralPath $InstalledVerifier -PathType Leaf) { return $InstalledVerifier }
    $cmd = Get-Command 'openscale-release-verify' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

$source = (Resolve-Path -LiteralPath $Exe).ProviderPath
if ((Split-Path -Leaf $source) -ne $ReleaseExeName) {
    throw "Dosya adı '$ReleaseExeName' olmalı (manifestoda bu adla kayıtlı): $source"
}
$sourceDir = Split-Path -Parent $source

# 1. Private working copy.
$work = Join-Path ([IO.Path]::GetTempPath()) ('openscale-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$acl = Get-Acl -LiteralPath $work
$acl.SetAccessRuleProtection($true, $false)
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
# The elevated copy may run as another administrator account (UAC prompt
# with credentials), so administrators and SYSTEM may read and execute.
foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
    $id = New-Object Security.Principal.SecurityIdentifier($sid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $work -AclObject $acl
$exeCopy = Join-Path $work $ReleaseExeName
Copy-Item -LiteralPath $source -Destination $exeCopy
$verifierCopy = $null

# 2. Release verification.
if ($NoVerify) {
    Write-Warning '-NoVerify: program DOĞRULANMADI.'
} elseif ($Sha256Only) {
    $sums = Join-Path $sourceDir 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $sums -PathType Leaf)) { throw "SHA256SUMS bulunamadı: $sums" }
    $line = Get-Content -LiteralPath $sums | Where-Object { $_ -match "^([0-9a-f]{64})  $([regex]::Escape($ReleaseExeName))$" } | Select-Object -First 1
    if (-not $line) { throw "SHA256SUMS içinde $ReleaseExeName yok." }
    $want = ($line -split '\s+')[0]
    $got = (Get-FileHash -LiteralPath $exeCopy -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $want) { throw "SHA-256 eşleşmiyor: beklenen $want, bulunan $got" }
    Write-Warning 'Yalnızca SHA256SUMS denetlendi: dosya bozulmamış, ancak kimin yayımladığı KANITLANMADI.'
} else {
    if (-not $Manifest) { $Manifest = Find-Manifest $sourceDir }
    if (-not $Manifest) { throw "İmzalı sürüm dosyası (openscale-*.release.json) bulunamadı; -Manifest ile verin. İmzasız sürüm için -Sha256Only." }
    $Manifest = (Resolve-Path -LiteralPath $Manifest).ProviderPath
    $v = Find-Verifier
    if (-not $v) {
        throw "openscale-release-verify bulunamadı. Güvenilir bir kopyasını -Verifier ile verin (docs/surum-dogrulama.md, 'İlk kurulum')."
    }
    if ((Split-Path -Parent $v) -eq $sourceDir) {
        Write-Warning 'Doğrulayıcı, doğrulanan sürümle aynı klasörden geliyor. Bu yalnızca tutarlılığı gösterir; ilk kurulumda doğrulayıcının SHA-256 değerini ayrı bir kanaldan karşılaştırın ve -RootFingerprint verin.'
    }
    $vargs = @('-manifest', $Manifest, '-dir', $work)
    if ($RootKey) { $vargs += @('-root-key', $RootKey) }
    if ($RootFingerprint) { $vargs += @('-root-fingerprint', $RootFingerprint) }
    $installed = Get-InstalledVersion
    if ($installed) { $vargs += @('-installed', $installed) }
    if ($AllowDowngrade) { $vargs += '-allow-downgrade' }
    $vargs += $exeCopy
    $newVerifier = Join-Path $sourceDir 'openscale-release-verify-windows-amd64.exe'
    if (Test-Path -LiteralPath $newVerifier -PathType Leaf) {
        $verifierCopy = Join-Path $work 'openscale-release-verify-windows-amd64.exe'
        Copy-Item -LiteralPath $newVerifier -Destination $verifierCopy
        $vargs += $verifierCopy
    }
    & $v @vargs
    if ($LASTEXITCODE -ne 0) { throw "Sürüm doğrulanamadı (çıkış kodu $LASTEXITCODE). Kurulum yapılmadı." }
}

# 3. Authenticode (optional; OpenScale releases may be unsigned).
$sig = Get-AuthenticodeSignature -LiteralPath $exeCopy
switch ($sig.Status) {
    'Valid' { Write-Host "Authenticode imzası geçerli: $($sig.SignerCertificate.Subject)" }
    'NotSigned' { Write-Host 'Authenticode imzası yok (SmartScreen uyarı verebilir); bütünlük yukarıda doğrulandı.' }
    default { throw "Authenticode imzası geçersiz ($($sig.Status)): $($sig.StatusMessage)" }
}

# Keep the verified verifier for later updates (needs administrator rights).
if ((-not $NoVerify) -and (-not $Sha256Only) -and $verifierCopy) {
    if (Test-Admin) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Copy-Item -LiteralPath $verifierCopy -Destination $InstalledVerifier -Force
        Write-Host "Doğrulayıcı kuruldu: $InstalledVerifier"
    } else {
        Write-Host 'Doğrulayıcı kurulmadı (yönetici değil); sonraki güncellemede -Verifier verin.'
    }
}

# 4. The program installs itself (UAC prompt).
Write-Host 'OpenScale başlatılıyor; yönetici onayı istenecek.'
Start-Process -FilePath $exeCopy -ArgumentList 'app' -WorkingDirectory $work
Write-Host "Geçici kopya: $work (kurulumdan sonra silebilirsiniz)."
