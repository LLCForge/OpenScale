#Requires -Version 5.1
<#
.SYNOPSIS
    OpenScale'i Windows'tan kaldırır (F-170).

.DESCRIPTION
    'openscale.exe service uninstall' ile servis, kalıcı kill switch filtreleri ve güvenlik duvarı
    kuralları kaldırılır; tepsi simgesi kapatılır ve %ProgramFiles%\OpenScale silinir.

    Anahtarlar ve ağ verisi (%ProgramData%\OpenScale) varsayılan olarak KORUNUR: cihaz anahtarı
    kaybolursa cihaz ağa yeniden katılmak zorunda kalır; kök anahtar varsa ağın kendisi kaybolur.
    Bunları da silmek için -RemoveData verin; ayrıca onay istenir. Kök anahtarın yedeği yoksa silmeyin.

    Yönetici olarak çalıştırılmalıdır.

.EXAMPLE
    .\uninstall-windows.ps1
.EXAMPLE
    .\uninstall-windows.ps1 -RemoveData
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$RemoveData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InstallDir = Join-Path $env:ProgramFiles 'OpenScale'
$InstalledExe = Join-Path $InstallDir 'openscale.exe'
$DataDir = Join-Path $env:ProgramData 'OpenScale'

$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Yönetici olarak çalıştırın (PowerShell > Yönetici olarak çalıştır).'
}

if (Test-Path -LiteralPath $InstalledExe -PathType Leaf) {
    & $InstalledExe service uninstall
    if ($LASTEXITCODE -ne 0) {
        throw "Servis kaldırılamadı (çıkış kodu $LASTEXITCODE). Dosyalar silinmedi; kill switch açık kalmış olabilir: '$InstalledExe killswitch off'."
    }
} else {
    Write-Warning "$InstalledExe yok; servis kaldırma adımı atlandı."
}

# Sign-in entries (ADR-0194): "service uninstall" removes them too; this
# also covers a program that is already gone. Only the "OpenScale" value is
# removed, and only when it runs a program from the install directory.
foreach ($runKey in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) {
    $value = (Get-ItemProperty -LiteralPath $runKey -Name 'OpenScale' -ErrorAction SilentlyContinue).OpenScale
    if ($value -and $value.StartsWith('"' + $InstallDir, [StringComparison]::OrdinalIgnoreCase)) {
        if ($PSCmdlet.ShouldProcess("$runKey\OpenScale", 'Oturum açılışı kaydını sil')) {
            Remove-ItemProperty -LiteralPath $runKey -Name 'OpenScale'
            Write-Host "Silindi: $runKey\OpenScale"
        }
    }
}

# Tray icons still running from the install directory hold the file open.
Get-Process -Name 'openscale' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) } |
    ForEach-Object {
        Write-Host "Kapatılıyor: $($_.Path) (PID $($_.Id))"
        Stop-Process -Id $_.Id -Force
        $_.WaitForExit(10000) | Out-Null
    }

if ((Test-Path -LiteralPath $InstallDir) -and -not $WhatIfPreference) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "Silindi: $InstallDir"
}

if ($RemoveData) {
    if ((Test-Path -LiteralPath $DataDir) -and $PSCmdlet.ShouldProcess($DataDir, 'Anahtarları ve ağ verisini KALICI olarak sil')) {
        Remove-Item -LiteralPath $DataDir -Recurse -Force
        Write-Host "Silindi: $DataDir"
    }
} else {
    Write-Host "Anahtarlar ve ağ verisi korundu: $DataDir"
}
Write-Host 'OpenScale kaldırıldı.'
