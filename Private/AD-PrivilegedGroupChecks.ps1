$script:PrivilegedGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators'
)

function Get-ADSHCPrivilegedGroupMembership {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $results = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams

        $results += [PSCustomObject]@{
            Group   = $groupName
            Members = $members
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Privileged group membership' `
        -Severity 'Info' `
        -Message "Collected membership for privileged groups." `
        -Data $results
}

function Get-ADSHCPrivilegedExternalMembers {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $external = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams
        foreach ($m in $members) {
            if ($m.ObjectClass -eq 'foreignSecurityPrincipal') {
                $external += [PSCustomObject]@{
                    Group  = $groupName
                    Member = $m
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'External members' `
        -Severity 'Warning' `
        -Message "Found $($external.Count) foreign security principals in privileged groups." `
        -Data $external
}

function Get-ADSHCPrivilegedDisabledMembers {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $disabled = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams | Where-Object { $_.objectClass -eq 'user' }

        foreach ($m in $members) {
            $uParams = @{ Identity = $m.DistinguishedName; Properties = 'Enabled' }
            if ($Server) { $uParams['Server'] = $Server }

            $u = Get-ADUser @uParams
            if (-not $u.Enabled) {
                $disabled += [PSCustomObject]@{
                    Group  = $groupName
                    User   = $u
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Disabled members' `
        -Severity 'Warning' `
        -Message "Found $($disabled.Count) disabled users in privileged groups." `
        -Data $disabled
}

function Get-ADSHCPrivilegedInactiveMembers {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $inactive  = @()
    $threshold = (Get-Date).AddDays(-90)

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams | Where-Object { $_.objectClass -eq 'user' }

        foreach ($m in $members) {
            $uParams = @{ Identity = $m.DistinguishedName; Properties = 'LastLogonDate' }
            if ($Server) { $uParams['Server'] = $Server }

            $u = Get-ADUser @uParams
            if (-not $u.LastLogonDate -or $u.LastLogonDate -lt $threshold) {
                $inactive += [PSCustomObject]@{
                    Group  = $groupName
                    User   = $u
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Inactive members' `
        -Severity 'Warning' `
        -Message "Found $($inactive.Count) inactive users in privileged groups (no logon in 90+ days)." `
        -Data $inactive
}

function Get-ADSHCPrivilegedPasswordNeverExp {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $neverExp = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams | Where-Object { $_.objectClass -eq 'user' }

        foreach ($m in $members) {
            $uParams = @{ Identity = $m.DistinguishedName; Properties = 'PasswordNeverExpires' }
            if ($Server) { $uParams['Server'] = $Server }

            $u = Get-ADUser @uParams
            if ($u.PasswordNeverExpires) {
                $neverExp += [PSCustomObject]@{
                    Group = $groupName
                    User  = $u
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Password never expires' `
        -Severity 'Critical' `
        -Message "Found $($neverExp.Count) privileged users with non-expiring passwords." `
        -Data $neverExp
}

function Get-ADSHCPrivilegedCanBeDelegated {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $deleg = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams | Where-Object { $_.objectClass -eq 'user' }

        foreach ($m in $members) {
            $uParams = @{ Identity = $m.DistinguishedName; Properties = 'userAccountControl' }
            if ($Server) { $uParams['Server'] = $Server }

            $u = Get-ADUser @uParams
            # NOT_DELEGATED bit: 0x100000
            if (-not ($u.userAccountControl -band 0x100000)) {
                $deleg += [PSCustomObject]@{
                    Group = $groupName
                    User  = $u
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Can be delegated' `
        -Severity 'Warning' `
        -Message "Found $($deleg.Count) privileged users that can be delegated." `
        -Data $deleg
}

function Get-ADSHCPrivilegedSmartcardRequired {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $smart = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams | Where-Object { $_.objectClass -eq 'user' }

        foreach ($m in $members) {
            $uParams = @{ Identity = $m.DistinguishedName; Properties = 'userAccountControl' }
            if ($Server) { $uParams['Server'] = $Server }

            $u = Get-ADUser @uParams
            # SMARTCARD_REQUIRED = 0x40000
            if (-not ($u.userAccountControl -band 0x40000)) {
                $smart += [PSCustomObject]@{
                    Group = $groupName
                    User  = $u
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Smart card required' `
        -Severity 'Warning' `
        -Message "Found $($smart.Count) privileged users without smartcard requirement." `
        -Data $smart
}

function Get-ADSHCProtectedUsersIssues {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $gParams = @{ Identity = 'Protected Users'; ErrorAction = 'SilentlyContinue' }
    if ($Server) { $gParams['Server'] = $Server }

    $group = Get-ADGroup @gParams
    if (-not $group) {
        return New-ADSHCResult -Category 'Privileged Groups' -Check 'Protected Users group' `
            -Severity 'Warning' `
            -Message "Protected Users group not found." `
            -Data $null
    }

    $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
    if ($Server) { $mParams['Server'] = $Server }

    $members = Get-ADGroupMember @mParams

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Protected Users group' `
        -Severity 'Info' `
        -Message "Protected Users group has $($members.Count) members." `
        -Data $members
}

function Get-ADSHCPrivilegedServiceAccounts {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $svc = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams | Where-Object { $_.objectClass -eq 'user' }

        foreach ($m in $members) {
            if ($m.Name -match 'svc|_svc|sa_') {
                $svc += [PSCustomObject]@{
                    Group = $groupName
                    User  = $m
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Service accounts' `
        -Severity 'Warning' `
        -Message "Found $($svc.Count) likely service accounts in privileged groups." `
        -Data $svc
}

function Get-ADSHCAllPrivilegedMembers {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $data = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams
        foreach ($m in $members) {
            $data += [PSCustomObject]@{
                Group              = $groupName
                MemberName         = $m.Name
                MemberClass        = $m.objectClass
                DistinguishedName  = $m.DistinguishedName
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'All privileged members' `
        -Severity 'Info' `
        -Message "Enumerated all members of privileged groups ($($data.Count) entries)." `
        -Data $data
}

function Get-ADSHCPrivilegedLockedMembers {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $locked = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams | Where-Object { $_.objectClass -eq 'user' }

        foreach ($m in $members) {
            $uParams = @{ Identity = $m.DistinguishedName; Properties = 'LockedOut' }
            if ($Server) { $uParams['Server'] = $Server }

            $u = Get-ADUser @uParams
            if ($u.LockedOut) {
                $locked += [PSCustomObject]@{
                    Group = $groupName
                    User  = $u
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Locked members' `
        -Severity 'Warning' `
        -Message "Found $($locked.Count) locked users in privileged groups." `
        -Data $locked
}

function Get-ADSHCPrivilegedSPNs {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $spnUsers = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        $gParams = @{ Identity = $groupName; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $group = Get-ADGroup @gParams
        if (-not $group) { continue }

        $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members = Get-ADGroupMember @mParams | Where-Object { $_.objectClass -eq 'user' }

        foreach ($m in $members) {
            $uParams = @{ Identity = $m.DistinguishedName; Properties = @('servicePrincipalName','Enabled') }
            if ($Server) { $uParams['Server'] = $Server }

            $u = Get-ADUser @uParams
            if ($u.Enabled -and $u.servicePrincipalName -and $u.servicePrincipalName.Count -gt 0) {
                $spnUsers += [PSCustomObject]@{
                    Group = $groupName
                    User  = $u
                    SPNs  = $u.servicePrincipalName
                }
            }
        }
    }

    New-ADSHCResult -Category 'Privileged Groups' -Check 'Privileged SPNs' `
        -Severity 'Warning' `
        -Message "Found $($spnUsers.Count) privileged users with SPNs (potential kerberoast exposure)." `
        -Data $spnUsers
}