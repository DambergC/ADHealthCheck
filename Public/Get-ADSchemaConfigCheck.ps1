function Get-ADSchemaConfigCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $results = @()
    $results += Get-ADSHCSchemaInfo
    $results += Get-ADSHCDomainConfig
    $results += Get-ADSHCAdvancedConfig

    return $results
}