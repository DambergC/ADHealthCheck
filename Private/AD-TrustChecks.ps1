function Get-ADSHCTrusts {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $tParams = @{
        Filter     = "*"
        Properties = '*'
    }
    if ($Server) { $tParams['Server'] = $Server }

    $trusts = Get-ADTrust @tParams

    $data = foreach ($t in $trusts) {
        [PSCustomObject]@{
            Name            = $t.Name
            Source          = $t.Source
            Target          = $t.Target
            Direction       = $t.Direction
            TrustType       = $t.TrustType
            TrustAttributes = $t.TrustAttributes
            Created         = $t.Created
            Modified        = $t.Modified
            SIDFiltering    = $t.SIDFilteringForestAware
        }
    }

    New-ADSHCResult -Category 'Trusts' -Check 'Trust relationships' `
        -Severity 'Info' `
        -Message "Collected $($trusts.Count) trusts." `
        -Data $data
}

function Get-ADSHCTrustSIDFiltering {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $tParams = @{
        Filter     = "*"
        Properties = '*'
    }
    if ($Server) { $tParams['Server'] = $Server }

    $trusts = Get-ADTrust @tParams
    $risky = $trusts | Where-Object {
        $_.TrustType -in 'External','Forest' -and (
            $_.SIDFilteringForestAware -eq $false -or $_.SIDFilteringQuarantined -eq $false
        )
    }

    New-ADSHCResult -Category 'Trusts' -Check 'SID filtering' `
        -Severity $(if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($risky.Count) trusts with SID filtering potentially disabled." `
        -Data $risky
}

function Get-ADSHCTrustSelectiveAuth {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $tParams = @{
        Filter     = "*"
        Properties = '*'
    }
    if ($Server) { $tParams['Server'] = $Server }

    $trusts = Get-ADTrust @tParams
    $risky = $trusts | Where-Object {
        $_.TrustType -in 'External','Forest' -and $_.SelectiveAuthentication -eq $false
    }

    New-ADSHCResult -Category 'Trusts' -Check 'Selective authentication' `
        -Severity $(if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($risky.Count) trusts without selective authentication." `
        -Data $risky
}

function Get-ADSHCTrustTransitivity {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    $tParams = @{
        Filter     = "*"
        Properties = '*'
    }
    if ($Server) { $tParams['Server'] = $Server }

    $trusts = Get-ADTrust @tParams
    $risky = $trusts | Where-Object {
        $_.TrustType -eq 'External' -and $_.ForestTransitive
    }

    New-ADSHCResult -Category 'Trusts' -Check 'Transitivity risks' `
        -Severity $(if ($risky.Count -gt 0) { 'Warning' } else { 'Info' }) `
        -Message "Found $($risky.Count) external trusts marked forest transitive." `
        -Data $risky
}