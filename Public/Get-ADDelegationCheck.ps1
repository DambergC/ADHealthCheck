function Get-ADDelegationCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $results = @()
    $results += Get-ADSHCDelegations
    $results += Get-ADSHCUnprotectedOUs

    return $results
}