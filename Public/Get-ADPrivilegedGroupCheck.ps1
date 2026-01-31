function Get-ADPrivilegedGroupCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $params = @{}
    if ($Domain) { $params['Server'] = $Domain }

    $results = @()
    $results += Get-ADSHCPrivilegedGroupMembership   @params
    $results += Get-ADSHCPrivilegedExternalMembers   @params
    $results += Get-ADSHCPrivilegedDisabledMembers   @params
    $results += Get-ADSHCPrivilegedInactiveMembers   @params
    $results += Get-ADSHCPrivilegedPasswordNeverExp  @params
    $results += Get-ADSHCPrivilegedCanBeDelegated    @params
    $results += Get-ADSHCPrivilegedSmartcardRequired @params
    $results += Get-ADSHCProtectedUsersIssues        @params
    $results += Get-ADSHCPrivilegedServiceAccounts   @params
    $results += Get-ADSHCAllPrivilegedMembers        @params

    return $results
}