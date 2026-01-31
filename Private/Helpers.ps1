function New-ADSHCResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Category,

        [Parameter(Mandatory)]
        [string] $Check,

        [Parameter(Mandatory)]
        [ValidateSet('Info','Warning','Critical','Error')]
        [string] $Severity,

        [Parameter()]
        [string] $Message,

        [Parameter()]
        $Data
    )

    [PSCustomObject]@{
        Category = $Category
        Check    = $Check
        Severity = $Severity
        Message  = $Message
        Data     = $Data
    }
}

function Test-ADModuleLoaded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $Name
    )

    foreach ($m in $Name) {
        if (-not (Get-Module -Name $m -ListAvailable)) {
            throw "Required module '$m' is not available. Please install/import it."
        }
    }
}

function Get-ADSHCDomainContext {
    [CmdletBinding()]
    param(
        [string] $Server
    )

    if ($Server) {
        return Get-ADDomain -Server $Server
    } else {
        return Get-ADDomain
    }
}

function Test-ADAttributeExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $AttributeName
    )

    try {
        $schemaNC = (Get-ADRootDSE).schemaNamingContext
        $attr = Get-ADObject -SearchBase $schemaNC `
                             -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$AttributeName))" `
                             -ErrorAction Stop
        return $null -ne $attr
    }
    catch {
        return $false
    }
}