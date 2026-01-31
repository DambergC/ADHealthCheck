function Get-ADKrbtgtAdminCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $params = @{}
    if ($Domain) { $params['Server'] = $Domain }

    $results = @()
    $results += Get-ADSHCKrbtgtInfo @params
    $results += Get-ADSHCAdminGuestInfo @params

    return $results
}