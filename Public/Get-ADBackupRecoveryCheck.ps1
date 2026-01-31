function Get-ADBackupRecoveryCheck {
    [CmdletBinding()]
    param(
        [string] $Domain
    )

    $results = @()
    $results += Get-ADSHCBackupInfo
    return $results
}