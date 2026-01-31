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

    return $results
}