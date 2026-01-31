function Get-ADSHCKrbtgtInfo {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $uParams = @{
        Identity   = 'krbtgt'
        Properties = @('PasswordLastSet','badPwdCount')
    }
    if ($Server) { $uParams['Server'] = $Server }

    $krbtgt = Get-ADUser @uParams

    $data = [PSCustomObject]@{
        Name            = $krbtgt.SamAccountName
        PasswordLastSet = $krbtgt.PasswordLastSet
        BadPwdCount     = $krbtgt.badPwdCount
    }

    New-ADSHCResult -Category 'Krbtgt/Admin' -Check 'Krbtgt last change' `
        -Severity 'Info' `
        -Message "Krbtgt password last set: $($krbtgt.PasswordLastSet)." `
        -Data $data
}

function Get-ADSHCAdminGuestInfo {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dParams = @{}
    if ($Server) { $dParams['Server'] = $Server }
    $domain  = Get-ADDomain @dParams

    $adminSid = "$($domain.DomainSID)-500"
    $guestSid = "$($domain.DomainSID)-501"

    $adminParams = @{
        Identity   = $adminSid
        Properties = @('LastLogonDate','SamAccountName')
    }
    if ($Server) { $adminParams['Server'] = $Server }

    $guestParams = @{
        Identity   = $guestSid
        Properties = @('Enabled','SamAccountName')
    }
    if ($Server) { $guestParams['Server'] = $Server }

    $admin = Get-ADUser @adminParams
    $guest = Get-ADUser @guestParams

    $data = [PSCustomObject]@{
        AdminAccountName = $admin.SamAccountName
        AdminLastLogon   = $admin.LastLogonDate
        GuestAccountName = $guest.SamAccountName
        GuestEnabled     = $guest.Enabled
    }

    New-ADSHCResult -Category 'Krbtgt/Admin' -Check 'Admin/Guest accounts' `
        -Severity $(
            if ($guest.Enabled) { 'Warning' } else { 'Info' }
        ) `
        -Message "Admin last logon: $($admin.LastLogonDate); Guest enabled: $($guest.Enabled)." `
        -Data $data
}