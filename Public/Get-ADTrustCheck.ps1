function Get-ADTrustCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $params = @{}
    if ($Domain) { $params['Server'] = $Domain }

    $results = @()
    $results += Get-ADSHCTrusts @params
    $results += Get-ADSHCTrustSIDFiltering @params
    $results += Get-ADSHCTrustSelectiveAuth @params
    $results += Get-ADSHCTrustTransitivity @params

    return $results
}