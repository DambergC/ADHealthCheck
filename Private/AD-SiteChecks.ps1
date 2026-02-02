function Get-ADSHCSites {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $adParams = @{ Filter = '*' }
    if ($Server) { $adParams['Server'] = $Server }

    $sites    = Get-ADReplicationSite @adParams
    $subnets  = Get-ADReplicationSubnet @adParams

    $data = [PSCustomObject]@{
        Sites   = $sites
        Subnets = $subnets
    }

    New-ADSHCResult -Category 'Sites' -Check 'Site configuration' `
        -Severity 'Info' `
        -Message "Collected $($sites.Count) sites and $($subnets.Count) subnets." `
        -Data $data
}