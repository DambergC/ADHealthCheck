function Get-ADSHCSchemaInfo {
    [CmdletBinding()]
    param()

    $root = Get-ADRootDSE
    $schemaDN = $root.schemaNamingContext
    $schema = Get-ADObject -Identity $schemaDN -Properties objectVersion,whenChanged

    $data = [PSCustomObject]@{
        SchemaVersion       = $schema.objectVersion
        SchemaLastChanged   = $schema.whenChanged
    }

    New-ADSHCResult -Category 'Schema/Config' -Check 'Schema information' `
        -Severity 'Info' `
        -Message "Schema version: $($schema.objectVersion), changed: $($schema.whenChanged)." `
        -Data $data
}

function Get-ADSHCDomainConfig {
    [CmdletBinding()]
    param()

    $dom    = Get-ADDomain
    $forest = Get-ADForest

    $data = [PSCustomObject]@{
        DomainFQDN          = $dom.DNSRoot
        NetBIOSName         = $dom.NetBIOSName
        DomainSID           = $dom.DomainSID
        ForestFQDN          = $forest.RootDomain
        DomainCreationDate  = $dom.WhenCreated
        DomainFunctionalLevel= $dom.DomainMode
        ForestFunctionalLevel= $forest.ForestMode
        RecycleBinEnabled   = $forest.RecycleBinEnabled
        NumberOfDCs         = $dom.DomainControllers.Count
        MachineAccountQuota = $dom.MachineAccountQuota
    }

    New-ADSHCResult -Category 'Schema/Config' -Check 'Domain configuration' `
        -Severity 'Info' `
        -Message "Domain and forest configuration collected." `
        -Data $data
}

function Get-ADSHCAdvancedConfig {
    [CmdletBinding()]
    param()

    $dom = Get-ADDomain
    $root = Get-ADRootDSE

    # DSHeuristics often on "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,..."
    $dsObj = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$($root.configurationNamingContext)" -Properties dSHeuristics -ErrorAction SilentlyContinue

    $data = [PSCustomObject]@{
        DSHeuristics  = $dsObj.dSHeuristics
        NTFRSForSYSVOL = (Get-ADObject -SearchBase $root.configurationNamingContext -LDAPFilter "(objectClass=nTFRSSettings)" -ErrorAction SilentlyContinue) -ne $null
    }

    New-ADSHCResult -Category 'Schema/Config' -Check 'Advanced configuration' `
        -Severity 'Info' `
        -Message "Advanced directory configuration partially collected (DSHeuristics, NTFRS presence)." `
        -Data $data
}