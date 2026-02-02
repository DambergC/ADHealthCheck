function Get-ADBackupRecoveryCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    $results = @()
    $results += Get-ADSHCBackupInfo
    $results += Get-ADSHCSystemStateBackup
    return $results
}