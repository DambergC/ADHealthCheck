function Get-ADSHCADCSTemplateObjects {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $rootDN      = (Get-ADRootDSE).configurationNamingContext
    $templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$rootDN"

    $adParams = @{
        SearchBase  = $templatesDn
        LDAPFilter  = '(objectClass=pKICertificateTemplate)'
        Properties  = @(
            'DisplayName','pKIExtendedKeyUsage','Flags','revision',
            'msPKI-RA-Signature','msPKI-Enrollment-Flag','msPKI-Certificate-Name-Flag',
            'msPKI-Private-Key-Flag','msPKI-RA-Application-Policies','msPKI-RA-Policies',
            'msPKI-Certificate-Application-Policy'
        )
        ErrorAction = 'SilentlyContinue'
    }
    if ($Server) { $adParams['Server'] = $Server }

    Get-ADObject @adParams
}

function Get-ADSHCADCSTemplates {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $rootDN      = (Get-ADRootDSE).configurationNamingContext
    $templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$rootDN"

    $adParams = @{
        SearchBase  = $templatesDn
        LDAPFilter  = '(objectClass=pKICertificateTemplate)'
        Properties  = '*'
        ErrorAction = 'SilentlyContinue'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $templates = Get-ADObject @adParams

    $data = foreach ($t in $templates) {
        [PSCustomObject]@{
            Name                = $t.Name
            DisplayName         = $t.DisplayName
            pKIExtendedKeyUsage = $t.pKIExtendedKeyUsage
            Flags               = $t.Flags

            # These AD attributes contain '-' in the name; must be accessed with quotes and ().
            RequiresManagerApproval  = $t.'msPKI-RA-Signature'
            EnrollmentAgentTemplate  = $t.'msPKI-Enrollment-Flag'
            AnyPurposeEKU            = $t.'msPKI-Certificate-Name-Flag'
            SchemaVersion            = $t.'revision'
        }
    }

    New-ADSHCResult -Category 'ADCS' -Check 'Certificate templates' `
        -Severity 'Info' `
        -Message "Collected $($templates.Count) certificate templates (risk analysis can be extended)." `
        -Data $data
}

function Get-ADSHCADCSCAs {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $rootDN = (Get-ADRootDSE).configurationNamingContext
    $caDn   = "CN=Certification Authorities,CN=Public Key Services,CN=Services,$rootDN"

    $adParams = @{
        SearchBase  = $caDn
        LDAPFilter  = '(objectClass=pKIEnrollmentService)'
        Properties  = '*'
        ErrorAction = 'SilentlyContinue'
    }
    if ($Server) { $adParams['Server'] = $Server }

    $cas = Get-ADObject @adParams

    $data = foreach ($ca in $cas) {
        [PSCustomObject]@{
            Name        = $ca.Name
            DnsHostName = $ca.dNSHostName
            CAType      = $ca.cAType
            WhenCreated = $ca.WhenCreated
        }
    }

    New-ADSHCResult -Category 'ADCS' -Check 'Certificate Authorities' `
        -Severity 'Info' `
        -Message "Collected $($cas.Count) enterprise CAs." `
        -Data $data
}

function Get-ADSHCADCSESC1 {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $templates = Get-ADSHCADCSTemplateObjects -Server $Server
    $esc1 = @()

    foreach ($t in $templates) {
        $enrolleeSupplies = ($t.'msPKI-Certificate-Name-Flag' -band 0x1)
        $requiresApproval = ($t.'msPKI-RA-Signature' -gt 0)
        $eku = @($t.pKIExtendedKeyUsage)
        $clientAuth = $eku -contains '1.3.6.1.5.5.7.3.2' -or $eku -contains '1.3.6.1.4.1.311.20.2.2'

        if ($enrolleeSupplies -and $clientAuth -and -not $requiresApproval) {
            $esc1 += $t
        }
    }

    New-ADSHCResult -Category 'ADCS' -Check 'ESC1 - Enrollee supplies subject' `
        -Severity $(if ($esc1.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($esc1.Count) templates matching ESC1 heuristic." `
        -Data $esc1
}

function Get-ADSHCADCSESC2 {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $templates = Get-ADSHCADCSTemplateObjects -Server $Server
    $esc2 = $templates | Where-Object {
        -not $_.pKIExtendedKeyUsage -or $_.pKIExtendedKeyUsage -contains '2.5.29.37.0'
    }

    New-ADSHCResult -Category 'ADCS' -Check 'ESC2 - Any Purpose EKU' `
        -Severity $(if ($esc2.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($esc2.Count) templates with Any Purpose EKU or no EKU restrictions." `
        -Data $esc2
}

function Get-ADSHCADCSESC3 {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $templates = Get-ADSHCADCSTemplateObjects -Server $Server
    $esc3 = $templates | Where-Object {
        $_.pKIExtendedKeyUsage -contains '1.3.6.1.4.1.311.20.2.1'
    }

    New-ADSHCResult -Category 'ADCS' -Check 'ESC3 - Enrollment agent templates' `
        -Severity $(if ($esc3.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($esc3.Count) enrollment agent templates." `
        -Data $esc3
}

function Get-ADSHCADCSESC4 {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $templates = Get-ADSHCADCSTemplateObjects -Server $Server
    $risky = @()

    foreach ($t in $templates) {
        try {
            $acl = Get-Acl -Path ("AD:\" + $t.DistinguishedName)
            $badAces = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference -match 'Authenticated Users|Domain Users|Everyone' -and
                ($_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty|ExtendedRight')
            }
            if ($badAces) {
                $risky += [PSCustomObject]@{
                    Template = $t.DisplayName
                    RiskyAces = $badAces
                }
            }
        } catch {
            continue
        }
    }

    New-ADSHCResult -Category 'ADCS' -Check 'ESC4 - Template ACLs' `
        -Severity $(if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($risky.Count) templates with risky ACLs (heuristic)." `
        -Data $risky
}

function Get-ADSHCADCSESC5 {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $rootDN = (Get-ADRootDSE).configurationNamingContext
    $caDn   = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$rootDN"

    $adParams = @{ SearchBase = $caDn; LDAPFilter = '(objectClass=pKIEnrollmentService)'; Properties = '*' }
    if ($Server) { $adParams['Server'] = $Server }

    $cas = Get-ADObject @adParams
    $risky = @()

    foreach ($ca in $cas) {
        try {
            $acl = Get-Acl -Path ("AD:\" + $ca.DistinguishedName)
            $badAces = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference -match 'Authenticated Users|Domain Users|Everyone' -and
                ($_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty|ExtendedRight')
            }
            if ($badAces) {
                $risky += [PSCustomObject]@{
                    CA = $ca.Name
                    RiskyAces = $badAces
                }
            }
        } catch {
            continue
        }
    }

    New-ADSHCResult -Category 'ADCS' -Check 'ESC5 - CA object ACLs' `
        -Severity $(if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($risky.Count) CAs with risky ACLs (heuristic)." `
        -Data $risky
}

function Get-ADSHCADCSESC6 {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $templates = Get-ADSHCADCSTemplateObjects -Server $Server
    $esc6 = $templates | Where-Object { $_.'msPKI-Certificate-Name-Flag' -band 0x1 }

    New-ADSHCResult -Category 'ADCS' -Check 'ESC6 - Subject/SAN supply' `
        -Severity $(if ($esc6.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($esc6.Count) templates that allow enrollee-supplied subject/SAN (heuristic)." `
        -Data $esc6
}

function Get-ADSHCADCSESC7 {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $rootDN = (Get-ADRootDSE).configurationNamingContext
    $caDn   = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$rootDN"

    $adParams = @{ SearchBase = $caDn; LDAPFilter = '(objectClass=pKIEnrollmentService)'; Properties = '*' }
    if ($Server) { $adParams['Server'] = $Server }

    $cas = Get-ADObject @adParams
    $risky = @()

    foreach ($ca in $cas) {
        try {
            $acl = Get-Acl -Path ("AD:\" + $ca.DistinguishedName)
            $badAces = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference -match 'Authenticated Users|Domain Users|Everyone' -and
                ($_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty')
            }
            if ($badAces) {
                $risky += [PSCustomObject]@{
                    CA = $ca.Name
                    RiskyAces = $badAces
                }
            }
        } catch {
            continue
        }
    }

    New-ADSHCResult -Category 'ADCS' -Check 'ESC7 - CA management rights' `
        -Severity $(if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($risky.Count) CAs with potentially risky management permissions (heuristic)." `
        -Data $risky
}

function Get-ADSHCADCSESC8 {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    New-ADSHCResult -Category 'ADCS' -Check 'ESC8 - Web enrollment/NTLM relay' `
        -Severity 'Info' `
        -Message "ESC8 requires CA web enrollment/HTTP configuration review; automated detection not available in AD attributes." `
        -Data $null
}

function Get-ADSHCADCSNTAuthStore {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $rootDN = (Get-ADRootDSE).configurationNamingContext
    $ntAuthDn = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$rootDN"

    $adParams = @{ Identity = $ntAuthDn; Properties = 'cACertificate' }
    if ($Server) { $adParams['Server'] = $Server }

    $ntAuth = Get-ADObject @adParams -ErrorAction SilentlyContinue
    $count = if ($ntAuth.'cACertificate') { $ntAuth.'cACertificate'.Count } else { 0 }

    New-ADSHCResult -Category 'ADCS' -Check 'NTAuth store' `
        -Severity $(if ($count -eq 0) { 'Warning' } else { 'Info' }) `
        -Message "NTAuth store contains $count certificate(s)." `
        -Data $ntAuth
}

function Get-ADSHCADCSEnrollmentAgents {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $templates = Get-ADSHCADCSTemplateObjects -Server $Server | Where-Object {
        $_.pKIExtendedKeyUsage -contains '1.3.6.1.4.1.311.20.2.1'
    }

    $groups = @('Enterprise Key Admins','Key Admins')
    $members = @()

    foreach ($g in $groups) {
        $gParams = @{ Identity = $g; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $gParams['Server'] = $Server }

        $grp = Get-ADGroup @gParams
        if (-not $grp) { continue }

        $mParams = @{ Identity = $grp; Recursive = $true; ErrorAction = 'SilentlyContinue' }
        if ($Server) { $mParams['Server'] = $Server }

        $members += Get-ADGroupMember @mParams
    }

    $data = [PSCustomObject]@{
        EnrollmentAgentTemplates = $templates
        KeyAdminMembers          = $members
    }

    New-ADSHCResult -Category 'ADCS' -Check 'Enrollment agent abuse' `
        -Severity 'Info' `
        -Message "Found $($templates.Count) enrollment agent templates and $($members.Count) key admin members." `
        -Data $data
}