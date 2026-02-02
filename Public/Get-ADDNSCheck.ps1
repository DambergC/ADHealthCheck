function Get-ADDNSCheck {
    [CmdletBinding()]
    param(
        [string] $Domain,
        [string] $DnsServer
    )

    # Requires DnsServer module on a DNS server or management host
    Test-ADModuleLoaded -Name 'DnsServer'

    $params = @{}
    if ($DnsServer) {
        $params['Server'] = $DnsServer
    } elseif ($Domain) {
        try {
            $dnsDc = Get-ADDomainController -DomainName $Domain -Discover -Service "DNS" -ErrorAction Stop
            $params['Server'] = $dnsDc.HostName
        } catch {
            return New-ADSHCResult -Category 'DNS' -Check 'DNS zones' `
                -Severity 'Error' `
                -Message "Unable to locate a DNS server for domain '$Domain'. Run on a DNS server or specify -DnsServer." `
                -Data $_
        }
    }

    $results = @()
    $results += Get-ADSHCDNSZones           @params
    $results += Get-ADSHCDNSZoneTransfers   @params
    $results += Get-ADSHCDNSAgingScavenging @params
    $results += Get-ADSHCDNSDynamicUpdates  @params

    return $results
}