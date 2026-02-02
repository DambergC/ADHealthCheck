function Get-ADSHCBackupInfo {
    [CmdletBinding()]
    param()

    # Placeholder: You can query event logs / backup software APIs here.
    New-ADSHCResult -Category 'Backup/Recovery' -Check 'Last AD backup' `
        -Severity 'Info' `
        -Message "Backup detection not implemented; integrate with your backup solution/event logs." `
        -Data $null
}

function Get-ADSHCSystemStateBackup {
    [CmdletBinding()]
    param(
        [string] $Server,
        [int]    $MaxAgeDays = 7
    )

    $logs = @('Microsoft-Windows-WindowsBackup/Operational','Microsoft-Windows-Backup')
    $events = @()

    foreach ($log in $logs) {
        try {
            $evParams = @{ LogName = $log; MaxEvents = 200 }
            if ($Server) { $evParams['ComputerName'] = $Server }
            $events += Get-WinEvent @evParams -ErrorAction SilentlyContinue
        } catch {
            continue
        }
    }

    $systemState = $events | Where-Object { $_.Message -match 'System State' } | Sort-Object TimeCreated -Descending
    $last = $systemState | Select-Object -First 1

    if (-not $last) {
        return New-ADSHCResult -Category 'Backup/Recovery' -Check 'System state backup age' `
            -Severity 'Warning' `
            -Message "No system state backup events found in the last 200 events." `
            -Data $null
    }

    $age = (New-TimeSpan -Start $last.TimeCreated -End (Get-Date)).Days
    $sev = if ($age -gt $MaxAgeDays) { 'Warning' } else { 'Info' }

    New-ADSHCResult -Category 'Backup/Recovery' -Check 'System state backup age' `
        -Severity $sev `
        -Message "Last system state backup was $age day(s) ago." `
        -Data $last
}