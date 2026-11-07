@{
    RootModule        = 'OpenScale.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '33a35730-4d93-4590-9184-0e8e36630240'
    Author            = 'OpenScale'
    Description       = 'OpenScale komut satırı aracının --json çıktısını saran PowerShell komutları (#859).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-OSStatus', 'Get-OSDevice', 'Send-OSFile', 'Set-OSExitNode')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Prerelease = 'beta2' } }
}
