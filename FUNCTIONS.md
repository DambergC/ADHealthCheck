# ADSecurityHealthCheck – Functions (User‑Facing)

This is a short, practical reference to the public functions you run and what they check. All commands return structured objects with `Category`, `Check`, `Severity`, `Message`, `Data`.

## Prerequisites (quick)
- ActiveDirectory module
- GroupPolicy module
- DnsServer module (only for DNS checks)
- Read access to AD and SYSVOL; additional rights for DC remote checks

## Public Functions

### Get-ADSecurityHealthCheck
**Purpose:** Run the full suite (accounts, privileged groups, DCs, GPO/GPP, DNS, trusts, ADCS, schema/config, delegations, OS inventory, sites, backup, krbtgt/admin).  
**Example:**
```powershell
$results = Get-ADSecurityHealthCheck -Domain contoso.com
```

### Get-ADAccountSecurityCheck
**Purpose:** Account hygiene (inactive/locked users, weak password settings, delegation flags, Unix password attributes, service accounts), plus computer account hygiene and password distributions.  
**Example:**
```powershell
Get-ADAccountSecurityCheck -Domain contoso.com
```

### Get-ADPrivilegedGroupCheck
**Purpose:** Privileged group membership, disabled/locked/inactive members, delegation risks, smartcard requirement, service accounts, SPNs.  
**Example:**
```powershell
Get-ADPrivilegedGroupCheck -Domain contoso.com
```

### Get-ADDomainControllerCheck
**Purpose:** DC inventory/config, SMB1/2, spooler/WebClient, LDAP signing registry checks, SYSVOL/DFSR health, time service, secure channel, unsupported OS.  
**Example:**
```powershell
Get-ADDomainControllerCheck -Domain contoso.com
```

### Get-ADGPOCheck
**Purpose:** GPP passwords, GPP files/firewall/TS/folder options/scripts; password/audit/user rights/WSUS/ASR; delegations; empty/unlinked GPOs; WMI filter issues.  
**Example:**
```powershell
Get-ADGPOCheck -Domain contoso.com
```

### Get-ADDNSCheck
**Purpose:** DNS zones, zone transfer settings, aging/scavenging, dynamic updates.  
**Example:**
```powershell
Get-ADDNSCheck -Domain contoso.com
Get-ADDNSCheck -DnsServer dns01.contoso.com
```

### Get-ADTrustCheck
**Purpose:** Trust relationships, SID filtering, selective authentication, transitivity risks.  
**Example:**
```powershell
Get-ADTrustCheck -Domain contoso.com
```

### Get-ADADCSCheck
**Purpose:** AD CS templates and CAs, ESC1–ESC8 heuristics, NTAuth store, enrollment agent exposure.  
**Example:**
```powershell
Get-ADADCSCheck -Domain contoso.com
```

### Get-ADSchemaConfigCheck
**Purpose:** Schema info, domain/forest config, advanced configuration.  
**Example:**
```powershell
Get-ADSchemaConfigCheck -Domain contoso.com
```

### Get-ADDelegationCheck
**Purpose:** Delegation permissions and unprotected OUs.  
**Example:**
```powershell
Get-ADDelegationCheck -Domain contoso.com
```

### Get-ADOSInventoryCheck
**Purpose:** Operating system inventory for domain‑joined computers.  
**Example:**
```powershell
Get-ADOSInventoryCheck -Domain contoso.com
```

### Get-ADSiteCheck
**Purpose:** AD sites and subnets.  
**Example:**
```powershell
Get-ADSiteCheck -Domain contoso.com
```

### Get-ADLoginScriptCheck
**Purpose:** Logon script usage across users.  
**Example:**
```powershell
Get-ADLoginScriptCheck -Domain contoso.com
```

### Get-ADBackupRecoveryCheck
**Purpose:** Backup placeholder plus system state backup age from event logs.  
**Example:**
```powershell
Get-ADBackupRecoveryCheck -Domain contoso.com
```

### Get-ADKrbtgtAdminCheck
**Purpose:** Krbtgt and default admin/guest account status.  
**Example:**
```powershell
Get-ADKrbtgtAdminCheck -Domain contoso.com
```
