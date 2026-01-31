@{
    RootModule        = 'ADSecurityHealthCheck.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '0fd7e4b4-1303-4b5b-a9e0-92c3b8de1111'
    Author            = 'DambergC'
    CompanyName       = 'YourOrg'
    Copyright         = '(c) 2026 YourOrg'
    Description       = 'Active Directory security health check module.'
    PowerShellVersion = '5.1'
    RequiredModules   = @(
        'ActiveDirectory',
        'GroupPolicy'
    )
    FunctionsToExport = @(
        'Get-ADSecurityHealthCheck',
        'Get-ADAccountSecurityCheck',
        'Get-ADPrivilegedGroupCheck',
        'Get-ADDomainControllerCheck',
        'Get-ADGPOCheck',
        'Get-ADTrustCheck',
        'Get-ADADCSCheck',
        'Get-ADSchemaConfigCheck',
        'Get-ADDelegationCheck',
        'Get-ADOSInventoryCheck',
        'Get-ADDNSCheck',
        'Get-ADSiteCheck',
        'Get-ADLoginScriptCheck',
        'Get-ADBackupRecoveryCheck',
        'Get-ADKrbtgtAdminCheck'
    )
    PrivateData = @{
        PSData = @{
            Tags        = @('ActiveDirectory','Security','Audit','HealthCheck')
            ProjectUri  = ''
            LicenseUri  = ''
            ReleaseNotes = 'Initial version with broad coverage and extensible stubs.'
        }
    }
}