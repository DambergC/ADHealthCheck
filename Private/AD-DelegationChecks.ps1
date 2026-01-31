function Get-ADSHCDelegations {
    [CmdletBinding()]
    param()

    $domain = Get-ADDomain
    $ouObjects = Get-ADOrganizationalUnit -Filter * -SearchBase $domain.DistinguishedName

    $deleg = @()

    foreach ($ou in $ouObjects) {
        $acl = Get-Acl -Path ("AD:\" + $ou.DistinguishedName)
        foreach ($ace in $acl.Access) {
            if ($ace.IsInherited -eq $false -and $ace.IdentityReference -notlike "*$($domain.NetBIOSName)*") {
                $deleg += [PSCustomObject]@{
                    DistinguishedName = $ou.DistinguishedName
                    Account           = $ace.IdentityReference
                    Rights            = $ace.ActiveDirectoryRights
                    Inherited         = $ace.IsInherited
                }
            }
        }
    }

    New-ADSHCResult -Category 'Delegations' -Check 'Delegations' `
        -Severity 'Info' `
        -Message "Collected explicit delegation ACEs for OUs ($($deleg.Count) entries)." `
        -Data $deleg
}

function Get-ADSHCUnprotectedOUs {
    [CmdletBinding()]
    param()

    $domain = Get-ADDomain
    $ouObjects = Get-ADOrganizationalUnit -Filter * -SearchBase $domain.DistinguishedName -Properties ProtectedFromAccidentalDeletion

    $unprotected = $ouObjects | Where-Object { -not $_.ProtectedFromAccidentalDeletion }

    New-ADSHCResult -Category 'Delegations' -Check 'Unprotected OUs' `
        -Severity 'Warning' `
        -Message "Found $($unprotected.Count) OUs without protection from accidental deletion." `
        -Data $unprotected
}