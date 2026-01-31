function Get-ADSHCSites {
    [CmdletBinding()]
    param()

    $sites    = Get-ADReplicationSite -Filter *
    $subnets  = Get-ADReplicationSubnet -Filter *

    $data = [PSCustomObject]@{
        Sites   = $sites
        Subnets = $subnets
    }

    New-ADSHCResult -Category 'Sites' -Check 'Site configuration' `
        -Severity 'Info' `
        -Message "Collected $($sites.Count) sites and $($subnets.Count) subnets." `
        -Data $data
}