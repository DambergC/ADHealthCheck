function Get-ADOSInventoryCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $params = @{}
    if ($Domain) { $params['Server'] = $Domain }

    $results = @()
    $results += Get-ADSHCOSInventory @params

    return $results
}