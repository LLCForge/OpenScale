#Requires -Version 5.1
# OpenScale PowerShell module (#859). Thin wrappers around the openscale CLI
# and its --json output; the CLI does every check and talks only to the
# local service. Arguments are passed to the program as separate argv
# entries (never through Invoke-Expression or a command string), and every
# value is validated before it is passed.
#
#   Import-Module "$env:ProgramFiles\OpenScale\OpenScale.psd1"
#   Get-OSStatus
#   Get-OSDevice -Online
#   Send-OSFile -Path .\rapor.pdf -Device nas
#   Set-OSExitNode -Name ev-sunucu      # Set-OSExitNode -Clear
#
# The program is found in this order: -CliPath, $env:OPENSCALE_CLI, the
# folder of this module, "$env:ProgramFiles\OpenScale", then PATH.

Set-StrictMode -Version 3.0

# Device names as the signed document allows them (DNS labels), MagicDNS
# names and tunnel IP addresses.
$script:DeviceNamePattern = '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){0,8}$'

function Resolve-OSCli {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$CliPath)

    $candidates = @()
    if ($CliPath) { $candidates += $CliPath }
    if ($env:OPENSCALE_CLI) { $candidates += $env:OPENSCALE_CLI }
    $candidates += (Join-Path -Path $PSScriptRoot -ChildPath 'openscale.exe')
    if ($env:ProgramFiles) { $candidates += (Join-Path -Path $env:ProgramFiles -ChildPath 'OpenScale\openscale.exe') }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $c).ProviderPath
        }
    }
    $cmd = Get-Command -Name 'openscale.exe', 'openscale' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    throw [System.IO.FileNotFoundException]::new('openscale programı bulunamadı; -CliPath verin veya OPENSCALE_CLI ortam değişkenini ayarlayın.')
}

function Test-OSArgument {
    # Refuses control characters and values the CLI would read as a flag.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value, [Parameter(Mandatory)][string]$What)
    # A double quote is refused too: Windows PowerShell 5.1 passes it to
    # native programs without escaping.
    if ($Value -match '[\x00-\x1f\x7f"]') { throw [System.ArgumentException]::new("$What denetim karakteri veya çift tırnak içeremez.") }
    if ($Value.StartsWith('-')) { throw [System.ArgumentException]::new("$What '-' ile başlayamaz.") }
}

function ConvertTo-OSArgument {
    # Quotes one argv entry by the CommandLineToArgvW rules, so the program
    # receives exactly $Value as one argument (no shell is involved).
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($Value -ne '' -and $Value -notmatch '[\s"]') { return $Value }
    $b = [System.Text.StringBuilder]::new('"')
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') { $slashes++; continue }
        if ($ch -eq '"') { [void]$b.Append([char]'\', 2 * $slashes + 1) }
        elseif ($slashes -gt 0) { [void]$b.Append([char]'\', $slashes) }
        $slashes = 0
        [void]$b.Append($ch)
    }
    [void]$b.Append([char]'\', 2 * $slashes)
    [void]$b.Append('"')
    $b.ToString()
}

function Invoke-OSCli {
    # Runs openscale with argv entries and returns standard output. A
    # non-zero exit code becomes an error with the CLI's message. The CLI
    # writes UTF-8; it is read as UTF-8 whatever the console code page is.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$CliPath,
        [switch]$Json
    )
    $exe = Resolve-OSCli -CliPath $CliPath
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.Arguments = (($Arguments | ForEach-Object { ConvertTo-OSArgument -Value $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        $errTask = $p.StandardError.ReadToEndAsync()
        $text = $p.StandardOutput.ReadToEnd().Trim()
        $p.WaitForExit()
        $stderr = $errTask.GetAwaiter().GetResult().Trim()
        $code = $p.ExitCode
    }
    finally {
        $p.Dispose()
    }
    if ($code -ne 0) {
        $msg = if ($stderr) { $stderr } else { $text }
        throw [System.InvalidOperationException]::new("openscale $($Arguments[0]) başarısız (çıkış kodu $code): $msg")
    }
    if ($Json) {
        if (-not $text) { return $null }
        return ($text | ConvertFrom-Json)
    }
    return $text
}

function Get-OSStatus {
    <#
    .SYNOPSIS
    Bu cihazın ve eşlerin durumunu döndürür ("openscale status --json").
    .PARAMETER StateDir
    Ön planda 'openscale up' ile açılan tünelin durum klasörü.
    #>
    [CmdletBinding()]
    param(
        [ValidateLength(1, 1024)][string]$StateDir,
        [string]$CliPath
    )
    $a = @('status', '--json')
    if ($StateDir) {
        Test-OSArgument -Value $StateDir -What 'Durum klasörü'
        $a += @('--state-dir', $StateDir)
    }
    Invoke-OSCli -Arguments $a -CliPath $CliPath -Json
}

function Get-OSDevice {
    <#
    .SYNOPSIS
    Ağdaki diğer cihazları döndürür (status --json içindeki eşler).
    .PARAMETER Name
    Yalnızca bu adlı cihaz (joker karakter kullanılabilir, ör. "nas*").
    .PARAMETER Online
    Yalnızca çevrimiçi cihazlar.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][ValidateLength(1, 253)][string]$Name,
        [switch]$Online,
        [ValidateLength(1, 1024)][string]$StateDir,
        [string]$CliPath
    )
    $p = @{ CliPath = $CliPath }
    if ($StateDir) { $p.StateDir = $StateDir }
    $st = Get-OSStatus @p
    if ($null -eq $st -or -not ($st.PSObject.Properties.Name -contains 'peers')) { return }
    $peers = @($st.peers)
    if ($Name) { $peers = @($peers | Where-Object { $_.name -like $Name }) }
    if ($Online) { $peers = @($peers | Where-Object { $_.online }) }
    $peers
}

function Send-OSFile {
    <#
    .SYNOPSIS
    Bir cihaza dosya gönderir ("openscale send").
    .PARAMETER Path
    Gönderilecek dosya.
    .PARAMETER Device
    Alıcı cihazın adı, MagicDNS adı veya tünel adresi.
    .PARAMETER Wait
    Alıcı çevrimdışıysa çevrimiçi olana kadar bekle.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][Alias('FullName')][string]$Path,
        [Parameter(Mandatory, Position = 1)][ValidateLength(1, 253)][string]$Device,
        [ValidateLength(1, 255)][string]$RemoteName,
        [ValidateSet('location', 'all')][string]$StripMetadata,
        [switch]$Wait,
        [string]$CliPath
    )
    process {
        $file = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $file.ProviderPath -PathType Leaf)) {
            throw [System.ArgumentException]::new("Dosya değil: $Path")
        }
        $ip = $null
        if (-not ($Device -match $script:DeviceNamePattern) -and -not [System.Net.IPAddress]::TryParse($Device, [ref]$ip)) {
            throw [System.ArgumentException]::new("Geçersiz cihaz: $Device")
        }
        $a = @('send')
        if ($RemoteName) {
            Test-OSArgument -Value $RemoteName -What 'Dosya adı'
            if ($RemoteName -match '[\\/]') { throw [System.ArgumentException]::new('Dosya adı klasör içeremez.') }
            $a += @('--name', $RemoteName)
        }
        if ($StripMetadata) { $a += @('--strip-metadata', $StripMetadata) }
        if ($Wait) { $a += '--wait' }
        # "--" ends the flags: the path and device are never read as one.
        $a += @('--', $file.ProviderPath, $Device)
        if ($PSCmdlet.ShouldProcess($Device, "Dosya gönder: $($file.ProviderPath)")) {
            $text = Invoke-OSCli -Arguments $a -CliPath $CliPath
            [pscustomobject]@{ Device = $Device; Path = $file.ProviderPath; Output = $text }
        }
    }
}

function Set-OSExitNode {
    <#
    .SYNOPSIS
    İnternet trafiğinin çıkacağı çıkış düğümünü seçer veya kaldırır ("openscale set exit-node=...").
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Set')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Set')][ValidateLength(1, 253)][string]$Name,
        [Parameter(Mandatory, ParameterSetName = 'Clear')][switch]$Clear,
        [ValidateLength(1, 1024)][string]$StateDir,
        [string]$CliPath
    )
    $value = ''
    if ($PSCmdlet.ParameterSetName -eq 'Set') {
        if (-not ($Name -match $script:DeviceNamePattern)) { throw [System.ArgumentException]::new("Geçersiz cihaz: $Name") }
        $value = $Name
    }
    $a = @('set', '--json')
    if ($StateDir) {
        Test-OSArgument -Value $StateDir -What 'Durum klasörü'
        $a += @('--state-dir', $StateDir)
    }
    $a += "exit-node=$value"
    $target = if ($value) { $value } else { 'yok' }
    if ($PSCmdlet.ShouldProcess($target, 'Çıkış düğümünü ayarla')) {
        Invoke-OSCli -Arguments $a -CliPath $CliPath -Json
    }
}

Export-ModuleMember -Function Get-OSStatus, Get-OSDevice, Send-OSFile, Set-OSExitNode
