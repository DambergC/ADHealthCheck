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
    $results += Get-ADSHCADCSESC1 @params
    $results += Get-ADSHCADCSESC2 @params
    $results += Get-ADSHCADCSESC3 @params
    $results += Get-ADSHCADCSESC4 @params
    $results += Get-ADSHCADCSESC5 @params
    $results += Get-ADSHCADCSESC6 @params
    $results += Get-ADSHCADCSESC7 @params
    $results += Get-ADSHCADCSESC8 @params
    $results += Get-ADSHCADCSNTAuthStore @params
    $results += Get-ADSHCADCSEnrollmentAgents @params

    return $results
}
