function Get-ADDomainControllerCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $params = @{}
    if ($Domain) { $params['Server'] = $Domain }

    $results = @()
    $results += Get-ADSHCDCInventory    @params
    $results += Get-ADSHCDCSecurity     @params
    $results += Get-ADSHCDCConfiguration @params
    $results += Get-ADSHCSysvolDfsrHealth @params
    $results += Get-ADSHCTimeSync         @params
    $results += Get-ADSHCSecureChannel    @params
    $results += Get-ADSHCUnsupportedDCOS  @params

    return $results
}