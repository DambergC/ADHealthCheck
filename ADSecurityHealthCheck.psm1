#Requires -Modules ActiveDirectory, GroupPolicy

$script:ModuleRoot = Split-Path -Parent $PSCommandPath

# Dot-source private functions
Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Filter '*.ps1' | ForEach-Object {
    . $_.FullName
}

# Dot-source public functions
Get-ChildItem -Path (Join-Path $ModuleRoot 'Public') -Filter '*.ps1' | ForEach-Object {
    . $_.FullName
}