function Get-ADSHCDCInventory {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dcParams = @{ Filter = "*" }
    if ($Server) { $dcParams['Server'] = $Server }

    $dcs = Get-ADDomainController @dcParams

    New-ADSHCResult -Category 'Domain Controllers' -Check 'DC inventory' `
        -Severity 'Info' `
        -Message "Found $($dcs.Count) domain controllers." `
        -Data $dcs
}

function Get-ADSHCDCSecurity {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dcParams = @{ Filter = "*" }
    if ($Server) { $dcParams['Server'] = $Server }

    $dcs     = Get-ADDomainController @dcParams
    $results = @()

    foreach ($dc in $dcs) {
        $computer = $dc.HostName

        $session = New-CimSession -ComputerName $computer -ErrorAction SilentlyContinue
        if (-not $session) {
            $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'DC security' `
                -Severity 'Error' `
                -Message "Could not create CIM session to ${computer}" `
                -Data $dc
            continue
        }

        # SMB configuration
        $smb1 = Get-SmbServerConfiguration -CimSession $session -ErrorAction SilentlyContinue
        if ($smb1) {
            $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'SMB1 support' `
                -Severity $(
                    if ($smb1.EnableSMB1Protocol) { 'Warning' } else { 'Info' }
                ) `
                -Message "DC ${computer}: SMB1 enabled = $($smb1.EnableSMB1Protocol)" `
                -Data $smb1

            $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'SMB2/SMB3 support' `
                -Severity 'Info' `
                -Message "DC ${computer}: SMB2/3 enabled = $($smb1.EnableSMB2Protocol)" `
                -Data $smb1
        }

        # Spooler service
        $spooler = Get-Service -Name spooler -ComputerName $computer -ErrorAction SilentlyContinue
        if ($spooler) {
            $sev = if ($spooler.Status -eq 'Running') { 'Warning' } else { 'Info' }
            $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'Remote spooler' `
                -Severity $sev `
                -Message "DC ${computer}: Spooler service state = $($spooler.Status)" `
                -Data $spooler
        }

        # WebClient
        $webClient = Get-Service -Name WebClient -ComputerName $computer -ErrorAction SilentlyContinue
        if ($webClient) {
            $sev = if ($webClient.Status -eq 'Running') { 'Warning' } else { 'Info' }
            $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'WebClient enabled' `
                -Severity $sev `
                -Message "DC ${computer}: WebClient service state = $($webClient.Status)" `
                -Data $webClient
        }

        # LDAP signing / channel binding quick registry check
         # LDAP signing / channel binding quick registry check
        if ($computer -eq $env:COMPUTERNAME -or $computer -eq "$($env:COMPUTERNAME).$((Get-ADDomain).DNSRoot)") {
            try {
                $ldapKey = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
                if ($ldapKey) {
                    $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'LDAP signing disabled' `
                        -Severity 'Info' `
                        -Message "DC ${computer}: LDAP signing-related registry keys present: $($ldapKey.PSObject.Properties.Name -join ', ')" `
                        -Data $ldapKey
                }
            }
            catch {
                $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'LDAP signing disabled' `
                    -Severity 'Error' `
                    -Message "DC ${computer}: Failed to read LDAP signing registry keys locally: $($_.Exception.Message)" `
                    -Data $null
            }
        }
        else {
            $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'LDAP signing disabled' `
                -Severity 'Info' `
                -Message "DC ${computer}: Skipping LDAP signing registry check (not local host; remote registry access not implemented)." `
                -Data $null
        }

        # TODO: add:
        # - Null session support
        # - LDAPS certificate
        # - Channel binding exact status
        # - RPC exposure
    }

    return $results
}

function Get-ADSHCDCConfiguration {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dcParams = @{ Filter = "*" }
    if ($Server) { $dcParams['Server'] = $Server }

    $dcs     = Get-ADDomainController @dcParams
    $results = @()

    $domParams = @{}
    if ($Server) { $domParams['Server'] = $Server }
    $domain  = Get-ADDomain @domParams

    foreach ($dc in $dcs) {
    $compParams = @{
        Identity    = $dc.ComputerObjectDN
        Properties  = '*'
        ErrorAction = 'SilentlyContinue'
    }
    if ($Server) { $compParams['Server'] = $Server }

    $comp = Get-ADComputer @compParams

    $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'DC configuration' `
        -Severity 'Info' `
        -Message "DC $($dc.HostName) configuration collected." `
        -Data ([PSCustomObject]@{
            OwnerSid          = $comp.ObjectSID
            Name              = $dc.HostName
            OperatingSystem   = $comp.OperatingSystem
            OSVersion         = $comp.OperatingSystemVersion
            IPAddresses       = $dc.IPAddress
            IsGlobalCatalog   = $dc.IsGlobalCatalog
            IsReadOnly        = $dc.IsReadOnly
            PasswordLastSet   = $comp.PasswordLastSet
            CreationDate      = $comp.WhenCreated
            DistinguishedName = $comp.DistinguishedName
            DomainFQDN        = $domain.DNSRoot
            FSMORoles         = $domain.OperationsMasterRole
        })
}

    return $results
}

function Get-ADSHCSysvolDfsrHealth {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dcParams = @{ Filter = "*" }
    if ($Server) { $dcParams['Server'] = $Server }

    $dcs = Get-ADDomainController @dcParams
    $results = @()

    foreach ($dc in $dcs) {
        $computer = $dc.HostName

        $dfsr = Get-Service -Name DFSR -ComputerName $computer -ErrorAction SilentlyContinue
        $shares = Get-CimInstance -ClassName Win32_Share -ComputerName $computer -ErrorAction SilentlyContinue
        $sysvolShare = $shares | Where-Object { $_.Name -eq 'SYSVOL' }

        $sev = if (-not $dfsr -or $dfsr.Status -ne 'Running' -or -not $sysvolShare) { 'Warning' } else { 'Info' }
        $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'SYSVOL/DFSR health' `
            -Severity $sev `
            -Message "DC ${computer}: DFSR=$($dfsr.Status), SYSVOL share present=$($null -ne $sysvolShare)." `
            -Data ([PSCustomObject]@{ DFSR = $dfsr; SYSVOL = $sysvolShare })
    }

    return $results
}

function Get-ADSHCTimeSync {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dcParams = @{ Filter = "*" }
    if ($Server) { $dcParams['Server'] = $Server }

    $dcs = Get-ADDomainController @dcParams
    $results = @()

    foreach ($dc in $dcs) {
        $computer = $dc.HostName
        $svc = Get-Service -Name W32Time -ComputerName $computer -ErrorAction SilentlyContinue

        $sev = if (-not $svc -or $svc.Status -ne 'Running') { 'Warning' } else { 'Info' }
        $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'Time sync' `
            -Severity $sev `
            -Message "DC ${computer}: W32Time service state = $($svc.Status)." `
            -Data $svc
    }

    return $results
}

function Get-ADSHCSecureChannel {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dcParams = @{ Filter = "*" }
    if ($Server) { $dcParams['Server'] = $Server }

    $dcs = Get-ADDomainController @dcParams
    $results = @()

    foreach ($dc in $dcs) {
        $computer = $dc.HostName

        try {
            $ok = Invoke-Command -ComputerName $computer -ScriptBlock { Test-ComputerSecureChannel -Verbose:$false } -ErrorAction Stop
            $sev = if ($ok) { 'Info' } else { 'Warning' }
            $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'Secure channel' `
                -Severity $sev `
                -Message "DC ${computer}: secure channel test = $ok." `
                -Data $ok
        } catch {
            $results += New-ADSHCResult -Category 'Domain Controllers' -Check 'Secure channel' `
                -Severity 'Error' `
                -Message "DC ${computer}: secure channel test failed (PS remoting)." `
                -Data $_
        }
    }

    return $results
}

function Get-ADSHCUnsupportedDCOS {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dcParams = @{ Filter = "*" }
    if ($Server) { $dcParams['Server'] = $Server }

    $dcs = Get-ADDomainController @dcParams
    $unsupported = @()

    foreach ($dc in $dcs) {
        $compParams = @{ Identity = $dc.ComputerObjectDN; Properties = 'OperatingSystem' }
        if ($Server) { $compParams['Server'] = $Server }

        $comp = Get-ADComputer @compParams
        if ($comp.OperatingSystem -notmatch 'Windows Server 2016|Windows Server 2019|Windows Server 2022|Windows Server 2025') {
            $unsupported += [PSCustomObject]@{
                Name            = $dc.HostName
                OperatingSystem = $comp.OperatingSystem
            }
        }
    }

    New-ADSHCResult -Category 'Domain Controllers' -Check 'Unsupported OS' `
        -Severity $(if ($unsupported.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($unsupported.Count) domain controllers on unsupported or legacy OS versions." `
        -Data $unsupported
}