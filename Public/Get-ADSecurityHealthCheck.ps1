function Get-ADSecurityHealthCheck {
    [CmdletBinding()]
    param(
        [string] $Domain,
        [int]    $InactiveDays = 90,
        [switch] $IncludeGPO,
        [switch] $IncludeADCS,
        [switch] $IncludeDNS,
        [switch] $IncludeSites,
        [switch] $IncludeOSInventory,
        [switch] $IncludeDelegations,
        [switch] $IncludeBackupRecovery
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory','GroupPolicy'

    $results = @()

    $results += Get-ADAccountSecurityCheck      -Domain $Domain -InactiveDays $InactiveDays
    $results += Get-ADPrivilegedGroupCheck      -Domain $Domain
    $results += Get-ADDomainControllerCheck     -Domain $Domain
    $results += Get-ADTrustCheck                -Domain $Domain
    $results += Get-ADSchemaConfigCheck         -Domain $Domain
    $results += Get-ADKrbtgtAdminCheck          -Domain $Domain

    if ($IncludeGPO)            { $results += Get-ADGPOCheck            -Domain $Domain }
    if ($IncludeADCS)           { $results += Get-ADADCSCheck           -Domain $Domain }
    if ($IncludeDNS)            { $results += Get-ADDNSCheck            -Domain $Domain }
    if ($IncludeSites)          { $results += Get-ADSiteCheck           -Domain $Domain }
    if ($IncludeOSInventory)    { $results += Get-ADOSInventoryCheck    -Domain $Domain }
    if ($IncludeDelegations)    { $results += Get-ADDelegationCheck     -Domain $Domain }
    if ($IncludeBackupRecovery) { $results += Get-ADBackupRecoveryCheck -Domain $Domain }

    return $results
}