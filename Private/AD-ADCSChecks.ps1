function Get-ADSHCADCSTemplates {
    [CmdletBinding()]
    param()

    $rootDN      = (Get-ADRootDSE).configurationNamingContext
    $templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$rootDN"

    $templates = Get-ADObject -SearchBase $templatesDn `
                              -LDAPFilter '(objectClass=pKICertificateTemplate)' `
                              -Properties * -ErrorAction SilentlyContinue

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
    param()

    $rootDN = (Get-ADRootDSE).configurationNamingContext
    $caDn   = "CN=Certification Authorities,CN=Public Key Services,CN=Services,$rootDN"

    $cas = Get-ADObject -SearchBase $caDn `
                         -LDAPFilter '(objectClass=pKIEnrollmentService)' `
                         -Properties * -ErrorAction SilentlyContinue

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