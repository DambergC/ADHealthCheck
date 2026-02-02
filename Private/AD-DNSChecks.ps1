function Get-ADSHCDNSZones {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dnsParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $dnsParams['ComputerName'] = $Server }

    try {
        $zones = Get-DnsServerZone @dnsParams
    } catch {
        return New-ADSHCResult -Category 'DNS' -Check 'DNS zones' `
            -Severity 'Error' `
            -Message "Failed to enumerate DNS zones from server '$Server'. Ensure it is a DNS server and RPC is reachable." `
            -Data $_
    }

    $data = foreach ($z in $zones) {
        [PSCustomObject]@{
            ZoneName       = $z.ZoneName
            ZoneType       = $z.ZoneType
            IsDsIntegrated = $z.IsDsIntegrated
            DynamicUpdate  = $z.DynamicUpdate
            AllowZoneTransfer = $z.AllowZoneTransfer
        }
    }

    New-ADSHCResult -Category 'DNS' -Check 'DNS zones' `
        -Severity 'Info' `
        -Message "Collected $($zones.Count) DNS zones." `
        -Data $data
}

function Get-ADSHCDNSZoneTransfers {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dnsParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $dnsParams['ComputerName'] = $Server }

    try {
        $zones = Get-DnsServerZone @dnsParams
    } catch {
        return New-ADSHCResult -Category 'DNS' -Check 'Zone transfer settings' `
            -Severity 'Error' `
            -Message "Failed to enumerate DNS zones from server '$Server'." `
            -Data $_
    }

    $risky = $zones | Where-Object { $_.AllowZoneTransfer -ne 'None' }

    $sev = if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }
    New-ADSHCResult -Category 'DNS' -Check 'Zone transfer settings' `
        -Severity $sev `
        -Message "Found $($risky.Count) zones allowing transfers (non-None)." `
        -Data $risky
}

function Get-ADSHCDNSAgingScavenging {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dnsParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $dnsParams['ComputerName'] = $Server }

    try {
        $zones = Get-DnsServerZone @dnsParams
    } catch {
        return New-ADSHCResult -Category 'DNS' -Check 'Aging/scavenging' `
            -Severity 'Error' `
            -Message "Failed to enumerate DNS zones from server '$Server'." `
            -Data $_
    }

    $noAging = $zones | Where-Object { -not $_.AgingEnabled }
    $sev = if ($noAging.Count -gt 0) { 'Warning' } else { 'Info' }

    New-ADSHCResult -Category 'DNS' -Check 'Aging/scavenging' `
        -Severity $sev `
        -Message "Found $($noAging.Count) zones without aging/scavenging enabled." `
        -Data $noAging
}

function Get-ADSHCDNSDynamicUpdates {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $dnsParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $dnsParams['ComputerName'] = $Server }

    try {
        $zones = Get-DnsServerZone @dnsParams
    } catch {
        return New-ADSHCResult -Category 'DNS' -Check 'Dynamic updates' `
            -Severity 'Error' `
            -Message "Failed to enumerate DNS zones from server '$Server'." `
            -Data $_
    }

    $insecure = $zones | Where-Object { $_.DynamicUpdate -eq 'NonsecureAndSecure' }
    $sev = if ($insecure.Count -gt 0) { 'Warning' } else { 'Info' }

    New-ADSHCResult -Category 'DNS' -Check 'Dynamic updates' `
        -Severity $sev `
        -Message "Found $($insecure.Count) zones allowing nonsecure dynamic updates." `
        -Data $insecure
}