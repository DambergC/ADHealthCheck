function Get-ADSHCDNSZones {
    [CmdletBinding()]
    param()

    $zones = Get-DnsServerZone -ErrorAction SilentlyContinue

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