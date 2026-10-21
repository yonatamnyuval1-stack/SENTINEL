$ErrorActionPreference = "Stop"
$honeyJson = Join-Path $PSScriptRoot "honey.json"
if (-not (Test-Path $honeyJson)) {
    throw "honey.json not found: $honeyJson"
}
$raw = Get-Content $honeyJson -Raw | ConvertFrom-Json
$root = $raw.decoy_root.Replace("{home}", $env:USERPROFILE)
if (-not (Test-Path $root)) {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
}
Write-Host "Decoy-root: $root"
auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
Write-Host "File System auditing enabled."
function Set-FileAudit {
    param([string]$Path)
    $acl = Get-Acl -Path $Path
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        "ReadData,WriteData,AppendData,Delete,DeleteSubdirectoriesAndFiles,ReadAttributes,WriteAttributes",
        "None",
        "None",
        "Success,Failure"
    )
    $acl.AddAuditRule($rule) | Out-Null
    Set-Acl -Path $Path -AclObject $acl
}
Set-FileAudit -Path $root
Get-ChildItem -Path $root -File | ForEach-Object {
    Set-FileAudit -Path $_.FullName
}
Write-Host "SACL applied."
Write-Host "Done. Run SENTINEL agent as Administrator to read Security events."