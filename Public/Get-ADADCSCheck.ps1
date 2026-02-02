function Get-ADADCSCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $params = @{}
    if ($Domain) { $params['Server'] = $Domain }

    $results = @()
    $results += Get-ADSHCADCSTemplates @params
    $results += Get-ADSHCADCSCAs @params

    return $results
}
