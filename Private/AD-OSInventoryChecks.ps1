function Get-ADSHCOSInventory {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $computers = Get-ADComputer -Filter "*" -Server $Server -Properties OperatingSystem,OperatingSystemVersion
    $grouped = $computers | Group-Object -Property OperatingSystem,OperatingSystemVersion | ForEach-Object {
        [PSCustomObject]@{
            OperatingSystem        = $_.Group[0].OperatingSystem
            OperatingSystemVersion = $_.Group[0].OperatingSystemVersion
            Count                  = $_.Count
        }
    }

    New-ADSHCResult -Category 'OS Inventory' -Check 'Operating systems' `
        -Severity 'Info' `
        -Message "Calculated OS inventory for $($computers.Count) computers." `
        -Data $grouped
}