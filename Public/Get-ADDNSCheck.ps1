function Get-ADDNSCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    # Requires DnsServer module on a DNS server or management host
    Test-ADModuleLoaded -Name 'DnsServer'

    $results = @()
    $results += Get-ADSHCDNSZones

    return $results
}