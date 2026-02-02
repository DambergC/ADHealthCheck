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