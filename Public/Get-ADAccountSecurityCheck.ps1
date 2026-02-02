function Get-ADAccountSecurityCheck {
    [CmdletBinding()]
    param(
        [string] $Domain,
        [int]    $InactiveDays = 90
    )

    Test-ADModuleLoaded -Name 'ActiveDirectory'

    $params = @{}
    if ($Domain) { $params['Server'] = $Domain }

    $results = @()

    # User accounts
    $results += Get-ADSHCInactiveAccounts       @params -InactiveDays $InactiveDays
    $results += Get-ADSHCLockedAccounts         @params
    $results += Get-ADSHCPasswordNeverExpires   @params
    $results += Get-ADSHCPasswordNotRequired    @params
    $results += Get-ADSHCReversibleEncryption   @params
    $results += Get-ADSHCSIDHistory             @params
    $results += Get-ADSHCBadPrimaryGroup        @params
    $results += Get-ADSHCDESEnabled             @params
    $results += Get-ADSHCNotAESEnabled          @params
    $results += Get-ADSHCNoPreAuthRequired      @params
    $results += Get-ADSHCTrustedForDelegation   @params
    $results += Get-ADSHCDuplicateAccounts      @params
    $results += Get-ADSHCSmartcardRequired      @params
    $results += Get-ADSHCUnixPasswords          @params
    $results += Get-ADSHCServiceAccounts        @params

    # Computer accounts
    $results += Get-ADSHCComputerPasswordAge    @params
    $results += Get-ADSHCClusterPasswordAge     @params
    $results += Get-ADSHCLAPSCoverage           @params
    $results += Get-ADSHCStaleComputers          @params -InactiveDays $InactiveDays

    # Password distributions
    $results += Get-ADSHCPasswordAgeDistribution   @params
    $results += Get-ADSHCLAPSAgeDistribution       @params
    $results += Get-ADSHCPrivilegedLastLogonDist   @params
    $results += Get-ADSHCPrivilegedPwdLastSetDist  @params

    # Coverage / hygiene
    $results += Get-ADSHCSmartcardCoverage         @params

    return $results
}