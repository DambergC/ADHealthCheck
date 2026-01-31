function Get-ADSHCInactiveAccounts {
    [CmdletBinding()]
    param(
        [string] $Server,
        [int]    $InactiveDays = 90
    )

    $filter = "Enabled -eq 'True'"
    $props  = @('SamAccountName','LastLogonDate','Enabled')

    $adParams = @{
        Filter     = $filter
        Properties = $props
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams -ErrorAction Stop

    $threshold = (Get-Date).AddDays(-$InactiveDays)
    $inactive  = $users | Where-Object {
        -not $_.LastLogonDate -or $_.LastLogonDate -lt $threshold
    }

    New-ADSHCResult -Category 'Account Security' -Check 'Inactive accounts' `
        -Severity 'Warning' `
        -Message "Found $($inactive.Count) inactive accounts (>$InactiveDays days)." `
        -Data $inactive
}

function Get-ADSHCLockedAccounts {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        LockedOut = $true
        UsersOnly = $true
    }
    if ($Server) { $adParams['Server'] = $Server }

    $locked = Search-ADAccount @adParams -ErrorAction SilentlyContinue

    New-ADSHCResult -Category 'Account Security' -Check 'Locked accounts' `
        -Severity 'Info' `
        -Message "Found $($locked.Count) locked accounts." `
        -Data $locked
}

function Get-ADSHCPasswordNeverExpires {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "UserAccountControl -band 0x10000"
        Properties = 'PasswordNeverExpires'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams
    New-ADSHCResult -Category 'Account Security' -Check 'Password never expires' `
        -Severity 'Warning' `
        -Message "Found $($users.Count) accounts with non-expiring passwords." `
        -Data $users
}

function Get-ADSHCPasswordNotRequired {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "UserAccountControl -band 0x20"
        Properties = 'PasswordNotRequired'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams
    New-ADSHCResult -Category 'Account Security' -Check 'Password not required' `
        -Severity 'Critical' `
        -Message "Found $($users.Count) accounts that do not require a password." `
        -Data $users
}

function Get-ADSHCReversibleEncryption {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = 'userAccountControl'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams | Where-Object {
        $_.userAccountControl -band 0x80
    }

    New-ADSHCResult -Category 'Account Security' -Check 'Reversible encryption' `
        -Severity 'Critical' `
        -Message "Found $($users.Count) accounts with passwords stored using reversible encryption." `
        -Data $users
}

function Get-ADSHCSIDHistory {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "SIDHistory -like '*'"
        Properties = 'SIDHistory'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams
    New-ADSHCResult -Category 'Account Security' -Check 'SID History' `
        -Severity 'Warning' `
        -Message "Found $($users.Count) accounts with SIDHistory set." `
        -Data $users
}

function Get-ADSHCBadPrimaryGroup {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = @('PrimaryGroupID','Enabled')
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams
    $bad = $users | Where-Object { $_.PrimaryGroupID -ne 513 -and $_.Enabled -eq $true }

    New-ADSHCResult -Category 'Account Security' -Check 'Bad primary group' `
        -Severity 'Warning' `
        -Message "Found $($bad.Count) accounts with non-standard primary groups (<>513)." `
        -Data $bad
}

function Get-ADSHCDESEnabled {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = 'userAccountControl'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams | Where-Object {
        $_.userAccountControl -band 0x200000
    }

    New-ADSHCResult -Category 'Account Security' -Check 'DES enabled' `
        -Severity 'Warning' `
        -Message "Found $($users.Count) accounts with DES encryption enabled." `
        -Data $users
}

function Get-ADSHCNotAESEnabled {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = 'userAccountControl'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams | Where-Object {
        -not ($_.userAccountControl -band 0x80000 -or $_.userAccountControl -band 0x100000)
    }

    New-ADSHCResult -Category 'Account Security' -Check 'Not AES enabled' `
        -Severity 'Warning' `
        -Message "Found $($users.Count) accounts that do not have AES encryption enabled." `
        -Data $users
}

function Get-ADSHCNoPreAuthRequired {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = 'userAccountControl'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams | Where-Object {
        $_.userAccountControl -band 0x400000
    }

    New-ADSHCResult -Category 'Account Security' -Check 'No PreAuth required' `
        -Severity 'Critical' `
        -Message "Found $($users.Count) accounts with Kerberos pre-authentication disabled (AS-REP roastable)." `
        -Data $users
}

function Get-ADSHCTrustedForDelegation {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        LDAPFilter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        Properties = @('userAccountControl','SamAccountName')
    }
    if ($Server) { $adParams['Server'] = $Server }

    $objs = Get-ADObject @adParams

    New-ADSHCResult -Category 'Account Security' -Check 'Trusted for delegation' `
        -Severity 'Warning' `
        -Message "Found $($objs.Count) accounts trusted for unconstrained delegation." `
        -Data $objs
}

function Get-ADSHCDuplicateAccounts {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = @('DisplayName','SamAccountName','UserPrincipalName')
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams

    $dups = @()
    foreach ($prop in 'DisplayName','SamAccountName','UserPrincipalName') {
        $grouped = $users | Group-Object -Property $prop | Where-Object { $_.Count -gt 1 -and $_.Name }
        foreach ($g in $grouped) {
            $dups += [PSCustomObject]@{
                Property = $prop
                Value    = $g.Name
                Objects  = $g.Group
            }
        }
    }

    New-ADSHCResult -Category 'Account Security' -Check 'Duplicate accounts' `
        -Severity 'Info' `
        -Message "Found $($dups.Count) duplicate account groups across DisplayName/SamAccountName/UPN." `
        -Data $dups
}

function Get-ADSHCSmartcardRequired {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = 'userAccountControl'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams
    $scReq = $users | Where-Object { $_.userAccountControl -band 0x40000 }

    New-ADSHCResult -Category 'Account Security' -Check 'Smart card required' `
        -Severity 'Info' `
        -Message "Found $($scReq.Count) accounts requiring smartcards. Validate configuration separately." `
        -Data $scReq
}

function Get-ADSHCUnixPasswords {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    # Only request attributes that actually exist
    $props  = @('userPassword')
    $filter = "userPassword -like '*'"

    if (Test-ADAttributeExists -AttributeName 'msSFU30Password') {
        $props  += 'msSFU30Password'
        $filter = "msSFU30Password -like '*' -or userPassword -like '*'"
    }

    $adParams = @{
        Filter     = $filter
        Properties = $props
        ErrorAction = 'SilentlyContinue'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams

    New-ADSHCResult -Category 'Account Security' -Check 'Unix passwords' `
        -Severity 'Warning' `
        -Message "Found $($users.Count) accounts with Unix-style password attributes (where schema supports them)." `
        -Data $users
}

function Get-ADSHCServiceAccounts {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = @('servicePrincipalName','SamAccountName')
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams

    $svcName = $users | Where-Object {
        $_.SamAccountName -match 'svc|_svc|sa_'
    }
    $svcSpn  = $users | Where-Object {
        $_.servicePrincipalName -and $_.servicePrincipalName.Count -gt 0
    }

    $combined = ($svcName + $svcSpn) | Select-Object -Unique

    New-ADSHCResult -Category 'Account Security' -Check 'Service accounts' `
        -Severity 'Info' `
        -Message "Identified $($combined.Count) likely service accounts (heuristic based)." `
        -Data $combined
}

function Get-ADSHCComputerPasswordAge {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "*"
        Properties = @('PasswordLastSet','OperatingSystem')
    }
    if ($Server) { $adParams['Server'] = $Server }

    $computers = Get-ADComputer @adParams
    $staleThreshold = (Get-Date).AddDays(-90)

    $stale = $computers | Where-Object {
        $_.PasswordLastSet -and $_.PasswordLastSet -lt $staleThreshold
    }

    New-ADSHCResult -Category 'Computer Accounts' -Check 'Computer password not changed' `
        -Severity 'Warning' `
        -Message "Found $($stale.Count) computers with passwords older than 90 days." `
        -Data $stale
}

function Get-ADSHCClusterPasswordAge {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "servicePrincipalName -like '*MSClusterVirtualServer*'"
        Properties = 'PasswordLastSet'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $clusters = Get-ADComputer @adParams
    $staleThreshold = (Get-Date).AddDays(-180)
    $stale = $clusters | Where-Object { $_.PasswordLastSet -lt $staleThreshold }

    New-ADSHCResult -Category 'Computer Accounts' -Check 'Cluster password not changed' `
        -Severity 'Warning' `
        -Message "Found $($stale.Count) cluster accounts with passwords older than 180 days." `
        -Data $stale
}

function Get-ADSHCLAPSCoverage {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $props = @()
    $hasLegacy = Test-ADAttributeExists -AttributeName 'ms-Mcs-AdmPwdExpirationTime'
    $hasNew    = Test-ADAttributeExists -AttributeName 'msLAPS-PasswordExpirationTime'

    if ($hasLegacy) { $props += 'ms-Mcs-AdmPwdExpirationTime' }
    if ($hasNew)    { $props += 'msLAPS-PasswordExpirationTime' }

    if (-not $props) {
        return New-ADSHCResult -Category 'Computer Accounts' -Check 'LAPS coverage' `
            -Severity 'Info' `
            -Message "LAPS attributes not present in schema; skipping LAPS coverage check." `
            -Data $null
    }

    $adParams = @{
        Filter     = "*"
        Properties = $props
        ErrorAction = 'SilentlyContinue'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $computers = Get-ADComputer @adParams

    $legacy = if ($hasLegacy) { $computers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' } } else { @() }
    $new    = if ($hasNew)    { $computers | Where-Object { $_.'msLAPS-PasswordExpirationTime' } } else { @() }
    $both   = if ($hasLegacy -and $hasNew) {
        $computers | Where-Object {
            $_.'ms-Mcs-AdmPwdExpirationTime' -and $_.'msLAPS-PasswordExpirationTime'
        }
    } else { @() }

    $data = [PSCustomObject]@{
        Total       = $computers.Count
        LegacyLAPS  = $legacy.Count
        NewLAPS     = $new.Count
        Both        = $both.Count
    }

    New-ADSHCResult -Category 'Computer Accounts' -Check 'LAPS coverage' `
        -Severity 'Info' `
        -Message "LAPS coverage (where schema attributes exist): Legacy=$($legacy.Count), New=$($new.Count), Both=$($both.Count) of $($computers.Count) computers." `
        -Data $data
}

function Get-ADSHCPasswordAgeDistribution {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{
        Filter     = "Enabled -eq 'True'"
        Properties = 'PasswordLastSet'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $users = Get-ADUser @adParams
    $now = Get-Date
    $bins = @{
        '0-30'    = 0
        '31-60'   = 0
        '61-90'   = 0
        '91-180'  = 0
        '181-365' = 0
        '365+'    = 0
        'Unknown' = 0
    }

    foreach ($u in $users) {
        if (-not $u.PasswordLastSet) {
            $bins['Unknown']++
            continue
        }
        $age = ($now - $u.PasswordLastSet).Days
        switch ($age) {
            {$_ -le 30}  { $bins['0-30']++;    break }
            {$_ -le 60}  { $bins['31-60']++;   break }
            {$_ -le 90}  { $bins['61-90']++;   break }
            {$_ -le 180} { $bins['91-180']++;  break }
            {$_ -le 365} { $bins['181-365']++; break }
            default       { $bins['365+']++ }
        }
    }

    $data = $bins.GetEnumerator() | Sort-Object Name
    New-ADSHCResult -Category 'Password Analysis' -Check 'Password distribution' `
        -Severity 'Info' `
        -Message "Password age distribution calculated for $($users.Count) enabled accounts." `
        -Data $data
}

function Get-ADSHCLAPSAgeDistribution {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    if (-not (Test-ADAttributeExists -AttributeName 'ms-Mcs-AdmPwdExpirationTime')) {
        return New-ADSHCResult -Category 'Password Analysis' -Check 'LAPS distribution' `
            -Severity 'Info' `
            -Message "Legacy LAPS attribute ms-Mcs-AdmPwdExpirationTime not present in schema; skipping distribution check." `
            -Data $null
    }

    $adParams = @{
        Filter     = "*"
        Properties = 'ms-Mcs-AdmPwdExpirationTime'
        ErrorAction = 'SilentlyContinue'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $computers = Get-ADComputer @adParams
    $now = Get-Date
    $bins = @{
        '0-7'     = 0
        '8-14'    = 0
        '15-30'   = 0
        '31-60'   = 0
        '61+'     = 0
        'Unknown' = 0
    }

    foreach ($c in $computers) {
        if (-not $c.'ms-Mcs-AdmPwdExpirationTime') {
            $bins['Unknown']++; continue
        }
        $exp = [DateTime]::FromFileTimeUtc([int64]$c.'ms-Mcs-AdmPwdExpirationTime')
        $age = ($now - $exp).Days * -1
        switch ($age) {
            {$_ -le 7}   { $bins['0-7']++;   break }
            {$_ -le 14}  { $bins['8-14']++;  break }
            {$_ -le 30}  { $bins['15-30']++; break }
            {$_ -le 60}  { $bins['31-60']++; break }
            default       { $bins['61+']++ }
        }
    }

    $data = $bins.GetEnumerator() | Sort-Object Name
    New-ADSHCResult -Category 'Password Analysis' -Check 'LAPS distribution' `
        -Severity 'Info' `
        -Message "Legacy LAPS password age distribution calculated for $($computers.Count) computers (where attribute exists)." `
        -Data $data
}

function Get-ADSHCPrivilegedLastLogonDist {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $domain = Get-ADSHCDomainContext -Server $Server
    $privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')

    $members = @()
    foreach ($g in $privGroups) {
        $gParams = @{ Identity = $g; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }
        $group = Get-ADGroup @gParams
        if ($group) {
            $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
            if ($Server) { $mParams['Server'] = $Server }
            $members += Get-ADGroupMember @mParams
        }
    }

    $userDns = $members | Where-Object { $_.objectClass -eq 'user' } | Select-Object -ExpandProperty DistinguishedName -Unique

    $users = foreach ($dn in $userDns) {
        $uParams = @{ Identity = $dn; Properties = 'LastLogonDate' }
        if ($Server) { $uParams['Server'] = $Server }
        Get-ADUser @uParams
    }

    $now = Get-Date
    $bins = @{
        '0-30'    = 0
        '31-90'   = 0
        '91-180'  = 0
        '181-365' = 0
        '365+'    = 0
        'Never'   = 0
    }

    foreach ($u in $users) {
        if (-not $u.LastLogonDate) {
            $bins['Never']++; continue
        }
        $age = ($now - $u.LastLogonDate).Days
        switch ($age) {
            {$_ -le 30}  { $bins['0-30']++;    break }
            {$_ -le 90}  { $bins['31-90']++;   break }
            {$_ -le 180} { $bins['91-180']++;  break }
            {$_ -le 365} { $bins['181-365']++; break }
            default       { $bins['365+']++ }
        }
    }

    $data = $bins.GetEnumerator() | Sort-Object Name
    New-ADSHCResult -Category 'Password Analysis' -Check 'Privileged account last logon distribution' `
        -Severity 'Info' `
        -Message "Calculated last logon distribution for $($users.Count) privileged accounts." `
        -Data $data
}

function Get-ADSHCPrivilegedPwdLastSetDist {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $domain = Get-ADSHCDomainContext -Server $Server
    $privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')

    $members = @()
    foreach ($g in $privGroups) {
        $gParams = @{ Identity = $g; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }
        $group = Get-ADGroup @gParams
        if ($group) {
            $mParams = @{ Identity = $group; Recursive = $true; ErrorAction = 'SilentlyContinue' }
            if ($Server) { $mParams['Server'] = $Server }
            $members += Get-ADGroupMember @mParams
        }
    }

    $userDns = $members | Where-Object { $_.objectClass -eq 'user' } | Select-Object -ExpandProperty DistinguishedName -Unique

    $users = foreach ($dn in $userDns) {
        $uParams = @{ Identity = $dn; Properties = 'PasswordLastSet' }
        if ($Server) { $uParams['Server'] = $Server }
        Get-ADUser @uParams
    }

    $now = Get-Date
    $bins = @{
        '0-30'    = 0
        '31-90'   = 0
        '91-180'  = 0
        '181-365' = 0
        '365+'    = 0
        'Unknown' = 0
    }

    foreach ($u in $users) {
        if (-not $u.PasswordLastSet) {
            $bins['Unknown']++; continue
        }
        $age = ($now - $u.PasswordLastSet).Days
        switch ($age) {
            {$_ -le 30}  { $bins['0-30']++;    break }
            {$_ -le 90}  { $bins['31-90']++;   break }
            {$_ -le 180} { $bins['91-180']++;  break }
            {$_ -le 365} { $bins['181-365']++; break }
            default       { $bins['365+']++ }
        }
    }

    $data = $bins.GetEnumerator() | Sort-Object Name
    New-ADSHCResult -Category 'Password Analysis' -Check 'Privileged password last set distribution' `
        -Severity 'Info' `
        -Message "Calculated password last set distribution for $($users.Count) privileged accounts." `
        -Data $data
}