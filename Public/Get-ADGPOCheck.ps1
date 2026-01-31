function Get-ADGPOCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'GroupPolicy','ActiveDirectory'

    $params = @{}
    if ($Domain) { $params['Server'] = $Domain }

    $results = @()
    $results += Get-ADSHCGPPPasswords
    $results += Get-ADSHCGPPFiles
    $results += Get-ADSHCGPPFirewall
    $results += Get-ADSHCGPPTerminalServices
    $results += Get-ADSHCGPPFolderOptions
    $results += Get-ADSHCGPPLoginScripts

    $results += Get-ADSHCGPOPasswordPolicies
    $results += Get-ADSHCGPOAuditPolicies
    $results += Get-ADSHCGPOUserRights
    $results += Get-ADSHCGPOWSUSConfig
    $results += Get-ADSHCGPODefenderASR
    $results += Get-ADSHCGPOEventForwarding

    $results += Get-ADSHCGPODelegations
    $results += Get-ADSHCGPOInformation

    return $results
}