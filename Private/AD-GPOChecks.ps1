function Get-ADSHCSysvolPath {
    $domain = Get-ADDomain
    return "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)"
}

function Get-ADSHCGPPPasswords {
    [CmdletBinding()]
    param()

    $sysvol = Get-ADSHCSysvolPath
    $gppFiles = Get-ChildItem -Path $sysvol -Recurse -Include '*.xml' -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'Groups.xml|Scheduledtasks.xml|Services.xml|DataSources.xml|Printers.xml|Drives.xml'
    }

    $hits = @()
    foreach ($file in $gppFiles) {
        $xml = $null
        try {
            $xml = [xml](Get-Content -Path $file.FullName -ErrorAction Stop)
        } catch {
            continue
        }

        if ($xml.InnerXml -match 'cpassword=') {
            $hits += $file.FullName
        }
    }

    New-ADSHCResult -Category 'GPO - GPP' -Check 'GPP passwords' `
        -Severity $(
            if ($hits.Count -gt 0) { 'Critical' } else { 'Info' }
        ) `
        -Message "Found $($hits.Count) GPP XML file(s) containing cpassword attributes." `
        -Data $hits
}

function Get-ADSHCGPPFiles {
    [CmdletBinding()]
    param()

    $sysvol = Get-ADSHCSysvolPath
    $files = Get-ChildItem -Path $sysvol -Recurse -Include 'Files.xml' -ErrorAction SilentlyContinue

    New-ADSHCResult -Category 'GPO - GPP' -Check 'GPP file deployment' `
        -Severity 'Info' `
        -Message "Found $($files.Count) GPP Files.xml definitions." `
        -Data $files
}

function Get-ADSHCGPPFirewall {
    [CmdletBinding()]
    param()

    $sysvol = Get-ADSHCSysvolPath
    $files = Get-ChildItem -Path $sysvol -Recurse -Include 'FirewallPolicy*.xml','Firewall*.xml' -ErrorAction SilentlyContinue

    New-ADSHCResult -Category 'GPO - GPP' -Check 'GPP firewall rules' `
        -Severity 'Info' `
        -Message "Found $($files.Count) GPP firewall-related XML definitions." `
        -Data $files
}

function Get-ADSHCGPPTerminalServices {
    [CmdletBinding()]
    param()

    $sysvol = Get-ADSHCSysvolPath
    $files = Get-ChildItem -Path $sysvol -Recurse -Include 'TerminalServices.xml','TS*.xml' -ErrorAction SilentlyContinue

    New-ADSHCResult -Category 'GPO - GPP' -Check 'GPP terminal service configs' `
        -Severity 'Info' `
        -Message "Found $($files.Count) GPP Terminal Services configuration XML files." `
        -Data $files
}

function Get-ADSHCGPPFolderOptions {
    [CmdletBinding()]
    param()

    $sysvol = Get-ADSHCSysvolPath
    $files = Get-ChildItem -Path $sysvol -Recurse -Include 'Folders.xml','FolderOptions.xml' -ErrorAction SilentlyContinue

    New-ADSHCResult -Category 'GPO - GPP' -Check 'GPP folder options' `
        -Severity 'Info' `
        -Message "Found $($files.Count) GPP folder options XML files." `
        -Data $files
}

function Get-ADSHCGPPLoginScripts {
    [CmdletBinding()]
    param()

    $sysvol = Get-ADSHCSysvolPath
    $files = Get-ChildItem -Path $sysvol -Recurse -Include 'Scripts.xml' -ErrorAction SilentlyContinue

    New-ADSHCResult -Category 'GPO - GPP' -Check 'GPP login scripts' `
        -Severity 'Info' `
        -Message "Found $($files.Count) GPP login script XML files." `
        -Data $files
}

function Get-ADSHCGPOPasswordPolicies {
    [CmdletBinding()]
    param()

    # Domain password policy
    $domain = Get-ADDefaultDomainPasswordPolicy
    New-ADSHCResult -Category 'GPO - Security Settings' -Check 'Password policies' `
        -Severity 'Info' `
        -Message "Domain password policy collected." `
        -Data $domain
}

function Get-ADSHCGPOAuditPolicies {
    [CmdletBinding()]
    param()

    # Simple: from default domain controllers policy
    $gpo = Get-GPO -All | Where-Object { $_.DisplayName -like '*Domain Controllers*' } | Select-Object -First 1
    New-ADSHCResult -Category 'GPO - Security Settings' -Check 'Audit policies' `
        -Severity 'Info' `
        -Message "Audit policy GPO reference collected (further parsing can be added)." `
        -Data $gpo
}

function Get-ADSHCGPOUserRights {
    [CmdletBinding()]
    param()

    # Placeholder: requires parsing gpttmpl.inf or secedit export
    New-ADSHCResult -Category 'GPO - Security Settings' -Check 'Right assignments' `
        -Severity 'Info' `
        -Message "User rights assignments collection not fully implemented. Extend using secedit/gpttmpl.inf parsing." `
        -Data $null
}

function Get-ADSHCGPOWSUSConfig {
    [CmdletBinding()]
    param()

    # Basic: find GPO registry settings pointing to WSUS server
    $gpos = Get-GPO -All
    $wsusGpos = @()

    foreach ($g in $gpos) {
        $report = Get-GPOReport -Guid $g.Id -ReportType Xml
        $xml = [xml]$report
        if ($xml.InnerXml -match 'WUServer') {
            $wsusGpos += $g
        }
    }

    New-ADSHCResult -Category 'GPO - Security Settings' -Check 'WSUS configuration' `
        -Severity 'Info' `
        -Message "Found $($wsusGpos.Count) GPOs configuring WSUS. Detailed certificate/SSL checks can be extended." `
        -Data $wsusGpos
}

function Get-ADSHCGPODefenderASR {
    [CmdletBinding()]
    param()

    # Placeholder – real logic: parse Defender ASR policies from registry/ADMX-backed policies
    New-ADSHCResult -Category 'GPO - Security Settings' -Check 'Defender ASR rules' `
        -Severity 'Info' `
        -Message "Defender ASR parsing not fully implemented. Extend using GP reports or registry policy parsing." `
        -Data $null
}

function Get-ADSHCGPOEventForwarding {
    [CmdletBinding()]
    param()

    # Placeholder – event forwarding is often configured via subscription XML in GPO
New-ADSHCResult -Category 'GPO - GPP' -Check 'GPP passwords' `
    -Severity $(
        if ($hits.Count -gt 0) { 'Critical' } else { 'Info' }
    ) `
    -Message "Found $($hits.Count) GPP XML file(s) containing cpassword attributes." `
    -Data $hits
}

function Get-ADSHCGPODelegations {
    [CmdletBinding()]
    param()

    $gpos = Get-GPO -All
    $info = foreach ($g in $gpos) {
        $perm = Get-GPPermission -Guid $g.Id -All
        [PSCustomObject]@{
            GPOName  = $g.DisplayName
            Id       = $g.Id
            Delegations = $perm
        }
    }

    New-ADSHCResult -Category 'GPO - Management' -Check 'GPO delegations' `
        -Severity 'Info' `
        -Message "Collected delegation info for $($gpos.Count) GPOs." `
        -Data $info
}

function Get-ADSHCGPOInformation {
    [CmdletBinding()]
    param()

    $gpos = Get-GPO -All | Select-Object DisplayName,Id,GpoStatus,CreationTime,ModificationTime
    New-ADSHCResult -Category 'GPO - Management' -Check 'GPO information' `
        -Severity 'Info' `
        -Message "Collected information on $($gpos.Count) GPOs." `
        -Data $gpos
}