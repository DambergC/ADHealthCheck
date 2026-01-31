function Get-ADSHCLoginScripts {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $users = Get-ADUser -Filter "scriptPath -like '*'" -Server $Server -Properties scriptPath
    $grouped = $users | Group-Object -Property scriptPath | ForEach-Object {
        [PSCustomObject]@{
            ScriptPath = $_.Name
            Users      = $_.Group
            Count      = $_.Count
        }
    }

    New-ADSHCResult -Category 'Login Scripts' -Check 'Login scripts' `
        -Severity 'Info' `
        -Message "Found $($grouped.Count) distinct login scripts assigned." `
        -Data $grouped
}