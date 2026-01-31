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