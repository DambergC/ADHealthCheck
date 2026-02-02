# ADSecurityHealthCheck

`ADSecurityHealthCheck` is a PowerShell module for running a broad set of security and configuration checks against an on‑premises Active Directory environment.  

It wraps many low‑level directory, GPO, DNS, AD CS, and configuration queries into higher‑level “check” functions that return structured objects you can analyze or export.

> **Note**  
> Function names and behavior are inferred from the current repository contents and may evolve.  
> This README focuses on *what functions exist* and *what they do*.

---

## Table of Contents

- [Overview](#overview)
- [Installation & Import](#installation--import)
- [Usage Basics](#usage-basics)
- [Public Functions](#public-functions)
  - [Get-ADSecurityHealthCheck](#get-adsecurityhealthcheck)
  - [Get-ADAccountSecurityCheck](#get-adaccountsecuritycheck)
  - [Get-ADPrivilegedGroupCheck](#get-adprivilegedgroupcheck)
  - [Get-ADDomainControllerCheck](#get-addomaincontrollercheck)
  - [Get-ADGPOCheck](#get-adgpocheck)
  - [Get-ADDNSCheck](#get-addnscheck)
  - [Get-ADTrustCheck](#get-adtrustcheck)
  - [Get-ADADCSCheck](#get-adadcscheck)
  - [Get-ADSchemaConfigCheck](#get-adschemaconfigcheck)
  - [Get-ADDelegationCheck](#get-addelegationcheck)
  - [Get-ADOSInventoryCheck](#get-adosinventorycheck)
  - [Get-ADSiteCheck](#get-adsitecheck)
  - [Get-ADLoginScriptCheck](#get-adloginscriptcheck)
  - [Get-ADBackupRecoveryCheck](#get-adbackuprecoverycheck)
  - [Get-ADKrbtgtAdminCheck](#get-adkrbtgtadmincheck)
- [Private / Internal Functions](#private--internal-functions)
  - [Result & Helper Utilities](#result--helper-utilities)
  - [Account Security Checks](#account-security-checks)
  - [Privileged Group & DC Checks](#privileged-group--dc-checks)
  - [GPO and GPP Checks](#gpo-and-gpp-checks)
  - [DNS Checks](#dns-checks)
  - [AD CS Checks](#ad-cs-checks)
  - [Schema & Configuration Checks](#schema--configuration-checks)
  - [Delegation Checks](#delegation-checks)
  - [OS Inventory Checks](#os-inventory-checks)
  - [Site & Login Script Checks](#site--login-script-checks)
  - [Backup & Recovery Checks](#backup--recovery-checks)
- [Output Format](#output-format)
- [Extending the Module](#extending-the-module)

---

## Overview

The module is structured as a standard PowerShell module:

- **Root module**: `ADSecurityHealthCheck.psm1`  
  Automatically dot‑sources all `Private\*.ps1` and `Public\*.ps1` function files.
- **Module manifest**: `ADSecurityHealthCheck.psd1`  
  Declares exported functions (public API) and dependencies:
  - `ActiveDirectory`
  - `GroupPolicy`
  - Some checks also require `DnsServer`.

Checks are implemented as **private functions** (prefixed `Get-ADSHC...`) that return standardized result objects, and **public wrapper functions** (prefixed `Get-AD...Check`) that orchestrate those internal checks for a specific area.

---

## Installation & Import

Clone or download the repository into one of your PowerShell module paths (e.g. `Documents\WindowsPowerShell\Modules\ADSecurityHealthCheck`), then:

```powershell
Import-Module ADSecurityHealthCheck
```

### Prerequisites

Required modules and features (install on the machine running the checks):

- **ActiveDirectory** (RSAT AD PowerShell)
- **GroupPolicy** (RSAT Group Policy Management)
- **DnsServer** (RSAT DNS Server tools) — required only for DNS checks

Recommended platform permissions:

- Read access to AD objects and SYSVOL.
- For **Domain Controller** checks: local admin or delegated rights to query services/CIM and remote registry on DCs.
- For **Secure channel** and service checks: PowerShell remoting (WinRM) enabled from the running host to DCs.

Example installs:

```powershell
# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GroupPolicy-Management, RSAT-DNS-Server

# Windows 10/11 (RSAT)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0

Import-Module ActiveDirectory
Import-Module GroupPolicy
Import-Module DnsServer
```

---

## Usage Basics

Most public functions follow this pattern:

```powershell
# Example: run all GPO-related checks
$results = Get-ADGPOCheck -Domain contoso.com

# Inspect all results
$results | Format-Table Category, Check, Severity, Message

# Drill into raw data for a specific check
$results |
  Where-Object { $_.Check -eq 'GPP passwords' } |
  Select-Object -ExpandProperty Data
```

Common parameters:

- `-Domain` — optional. If omitted, the current logon / default domain is used.  
  Where present, it is passed as `-Server` to low‑level AD cmdlets.

All checks return **objects**, not text. They share a common shape produced by `New-ADSHCResult`:

```powershell
[PSCustomObject]@{
    Category = '...'
    Check    = '...'
    Severity = 'Info' | 'Warning' | 'Critical' | 'Error'
    Message  = 'Human-readable summary'
    Data     = <raw data specific to the check>
}
```

---

## Public Functions

The following functions are **exported** by the module (listed in `FunctionsToExport` in `ADSecurityHealthCheck.psd1`):

### `Get-ADSecurityHealthCheck`

**Purpose:**  
Top‑level orchestrator (as indicated by the manifest). It is expected to:

- Run a broad set of sub‑checks: accounts, GPOs, DNS, trusts, AD CS, schema/config, delegations, OS inventory, sites, backup, krbtgt/admin, etc.
- Aggregate all `New-ADSHCResult` objects into a single collection.

**Typical usage:**

```powershell
# Run a full AD security health check
$results = Get-ADSecurityHealthCheck -Domain contoso.com
```

### `Get-ADAccountSecurityCheck`

**Purpose:**  
Runs checks related to account security posture, such as (from `Private/AD-AccountChecks.ps1`):

- Accounts with weak or insecure settings (password never expires, no pre‑auth, reversible encryption, DES, etc.).
- Unix‑style password attributes, if schema supports them (`msSFU30Password`, `userPassword`).
- Service accounts and accounts with SPNs.
- Computer account hygiene (stale computers, computer password age, cluster password age, LAPS coverage).
- Password age distributions and privileged account last logon/last set distributions.
- Smartcard coverage summary across enabled users.

**Example:**

```powershell
$results = Get-ADAccountSecurityCheck -Domain contoso.com
```

### `Get-ADPrivilegedGroupCheck`

**Purpose:**  
Audits privileged groups (e.g. Domain Admins, Enterprise Admins, etc.), checking:

- Membership (including nested/indirect membership).
- Potentially risky group assignments.
- Privileged accounts not in expected groups (implementation resides in `Private/AD-PrivilegedGroupChecks.ps1`).

**Example:**

```powershell
$results = Get-ADPrivilegedGroupCheck -Domain contoso.com
```

### `Get-ADDomainControllerCheck`

**Purpose:**  
Performs health and configuration checks for domain controllers, such as:

- DC inventory and configuration details (OS, roles, GC/RODC status).
- Insecure DC settings (SMBv1, spooler, WebClient, LDAP signing registry checks).
- SYSVOL/DFSR health and SYSVOL share presence.
- Time service status.
- Secure channel validation.
- Unsupported/legacy DC OS versions.

**Example:**

```powershell
$results = Get-ADDomainControllerCheck -Domain contoso.com
```

### `Get-ADGPOCheck`

**File:** `Public/Get-ADGPOCheck.ps1`  
**Key internal functions used:** from `Private/AD-GPOChecks.ps1` and related files.

**Purpose:**  
Runs a wide set of Group Policy Object (GPO) and Group Policy Preference (GPP) checks.

Internally, it calls functions such as:

- **GPP checks (Category: `GPO - GPP`):**
  - `Get-ADSHCGPPPasswords` — finds **GPP stored credentials/passwords** in SYSVOL.
  - `Get-ADSHCGPPFiles` — collect GPP *Files* configuration XML.
  - `Get-ADSHCGPPFirewall` — collect GPP firewall settings.
  - `Get-ADSHCGPPTerminalServices` — collect GPP Remote Desktop/Terminal Services configs.
  - `Get-ADSHCGPPFolderOptions` — detect Folder Options GPP settings.
  - `Get-ADSHCGPPLoginScripts` — detect GPP‑defined logon script XML (`Scripts.xml`).

- **GPO configuration checks:**
  - `Get-ADSHCGPOPasswordPolicies` — fine‑grained password policies & password settings.
  - `Get-ADSHCGPOAuditPolicies` — audit policy configuration.
  - `Get-ADSHCGPOUserRights` — user rights assignments.
  - `Get-ADSHCGPOWSUSConfig` — WSUS/client update policies.
  - `Get-ADSHCGPODefenderASR` — Microsoft Defender Attack Surface Reduction rules.
  - `Get-ADSHCGPOEventForwarding` — event forwarding configuration.
  - `Get-ADSHCGPODelegations` — GPO security filtering & delegation.
  - `Get-ADSHCGPOInformation` — basic inventory for all GPOs.
  - `Get-ADSHCGPOEmpty` — detects GPOs with no user/computer settings.
  - `Get-ADSHCGPOUnlinked` — detects GPOs with no links.
  - `Get-ADSHCGPOWmiFilterIssues` — WMI filter presence and query sanity checks (fallback to AD query if GroupPolicy cmdlets are missing).

**Example:**

```powershell
$results = Get-ADGPOCheck -Domain contoso.com
```

### `Get-ADDNSCheck`

**File:** `Public/Get-ADDNSCheck.ps1`  
**Requires:** `DnsServer` module (on a DNS server or a management host).

**Purpose:**  
Performs DNS‑related checks for the AD DNS infrastructure.

Internal function(s):

- `Get-ADSHCDNSZones` — collects DNS zones and configuration from AD‑integrated DNS.
- `Get-ADSHCDNSZoneTransfers` — flags zones allowing transfer.
- `Get-ADSHCDNSAgingScavenging` — flags zones without aging/scavenging.
- `Get-ADSHCDNSDynamicUpdates` — flags zones allowing nonsecure dynamic updates.

`Get-ADDNSCheck` also accepts `-DnsServer` to target a specific DNS server.

**Example:**

```powershell
$results = Get-ADDNSCheck -Domain contoso.com
```

### `Get-ADTrustCheck`

**Purpose:**  
Checks Active Directory trusts:

- Trust relationships to other forests/domains.
- Trust directions and security characteristics (e.g., selective authentication, transitivity).

Internal checks include:

- `Get-ADSHCTrustSIDFiltering` — flags trusts with SID filtering disabled.
- `Get-ADSHCTrustSelectiveAuth` — flags trusts without selective authentication.
- `Get-ADSHCTrustTransitivity` — flags risky transitivity settings.

Internal functions live in `Private/AD-TrustChecks.ps1` (not shown in snippet, but implied by naming).

**Example:**

```powershell
$results = Get-ADTrustCheck -Domain contoso.com
```

### `Get-ADADCSCheck`

**File:** `Private/AD-ADCSChecks.ps1` (private implementation)  

**Purpose:**  
Audits Active Directory Certificate Services (AD CS) configuration:

Internal functions include:

- `Get-ADSHCADCSTemplates`  
  - Enumerates certificate templates from `CN=Certificate Templates,...`.
  - Collects fields like:
    - `Name`, `DisplayName`
    - `pKIExtendedKeyUsage`
    - various flags (enrollment, issuance, security).
  - Returns aggregated data with category `ADCS`.

- `Get-ADSHCADCSCAs`  
  - Enumerates Certification Authorities from `CN=Certification Authorities,...`.
  - Collects CA metadata (name, configuration, URLs, etc.).

- **ESC heuristic checks** (based on template/CA ACLs and flags):
  - `Get-ADSHCADCSESC1` — enrollee supplies subject + client auth template.
  - `Get-ADSHCADCSESC2` — any‑purpose EKU or no EKU restrictions.
  - `Get-ADSHCADCSESC3` — enrollment agent templates.
  - `Get-ADSHCADCSESC4` — risky template ACLs.
  - `Get-ADSHCADCSESC5` — risky CA object ACLs.
  - `Get-ADSHCADCSESC6` — subject/SAN supply flags (heuristic).
  - `Get-ADSHCADCSESC7` — risky CA management permissions (heuristic).
  - `Get-ADSHCADCSESC8` — web enrollment/NTLM relay exposure (manual review note).

- Additional checks:
  - `Get-ADSHCADCSNTAuthStore` — NTAuth certificate store contents.
  - `Get-ADSHCADCSEnrollmentAgents` — enrollment agent templates and key admin members.

The public wrapper `Get-ADADCSCheck` aggregates these into health check results.

**Example:**

```powershell
$results = Get-ADADCSCheck -Domain contoso.com
```

### `Get-ADSchemaConfigCheck`

**File:** `Public/Get-ADSchemaConfigCheck.ps1`

**Purpose:**  
Runs schema and configuration partition checks, via:

- `Get-ADSHCSchemaInfo` — collects high‑level schema data (version, extensions, etc.).
- `Get-ADSHCDomainConfig` — domain‑level configuration (e.g. functional levels, critical settings).
- `Get-ADSHCAdvancedConfig` — advanced configuration flags and optional features.

**Example:**

```powershell
$results = Get-ADSchemaConfigCheck -Domain contoso.com
```

### `Get-ADDelegationCheck`

**File:** `Public/Get-ADDelegationCheck.ps1`  
**Internal functions:** `Private/AD-DelegationChecks.ps1`

**Purpose:**  
Audits delegation and OU protection:

- `Get-ADSHCDelegations`  
  - Gathers explicit delegated permissions on OUs and other key containers.
- `Get-ADSHCUnprotectedOUs`  
  - Uses `Get-ADOrganizationalUnit` to find OUs **without** `ProtectedFromAccidentalDeletion` set.
  - Emits a `Warning` severity result:

    ```powershell
    New-ADSHCResult -Category 'Delegations' -Check 'Unprotected OUs' `
        -Severity 'Warning' `
        -Message "Found <N> OUs without protection from accidental deletion." `
        -Data $unprotected
    ```

**Example:**

```powershell
$results = Get-ADDelegationCheck -Domain contoso.com
```

### `Get-ADOSInventoryCheck`

**Purpose:**  
Performs an operating system inventory across domain‑joined computers, collecting:

- OS versions and editions.
- Potentially support status or risk flags based on OS age.

Implemented in `Private/AD-OSInventoryChecks.ps1`.

**Example:**

```powershell
$results = Get-ADOSInventoryCheck -Domain contoso.com
```

### `Get-ADSiteCheck`

**File:** `Private/AD-SiteChecks.ps1` (internal)  

**Purpose:**  
Audits AD Sites and Services configuration.

Internal function:

- `Get-ADSHCSites`  
  - Uses `Get-ADReplicationSite` and `Get-ADReplicationSubnet`.
  - Packs them into a result:

    ```powershell
    New-ADSHCResult -Category 'Sites' -Check 'Site configuration' `
        -Severity 'Info' `
        -Message "Collected <sites> sites and <subnets> subnets." `
        -Data [PSCustomObject]@{ Sites = $sites; Subnets = $subnets }
    ```

The public wrapper `Get-ADSiteCheck` returns that result.

**Example:**

```powershell
$results = Get-ADSiteCheck -Domain contoso.com
```

### `Get-ADLoginScriptCheck`

**File:** `Public/Get-ADLoginScriptCheck.ps1`  
**Internal function:** `Private/AD-LoginScriptChecks.ps1`

**Purpose:**  
Identifies and summarizes user logon scripts referenced on user accounts.

Internal function `Get-ADSHCLoginScripts`:

- Queries users with a `scriptPath`:

  ```powershell
  $users = Get-ADUser -Filter "scriptPath -like '*'" -Server $Server -Properties scriptPath
  ```

- Groups them by `scriptPath` and emits:

  ```powershell
  New-ADSHCResult -Category 'Login Scripts' -Check 'Login scripts' `
      -Severity 'Info' `
      -Message "Found <N> distinct login scripts assigned." `
      -Data $grouped
  ```

Public wrapper `Get-ADLoginScriptCheck`:

- Optional parameter: `-Domain`
- Ensures `ActiveDirectory` module is loaded via `Test-ADModuleLoaded`.
- Passes `-Server` when `-Domain` is set.

**Example:**

```powershell
$results = Get-ADLoginScriptCheck -Domain contoso.com
```

### `Get-ADBackupRecoveryCheck`

**File:** `Public/Get-ADBackupRecoveryCheck.ps1`  
**Internal function:** `Private/AD-BackupRecoveryChecks.ps1`

**Purpose:**  
Placeholder for backup & recovery checks.

`Get-ADSHCBackupInfo` currently does:

```powershell
New-ADSHCResult -Category 'Backup/Recovery' -Check 'Last AD backup' `
    -Severity 'Info' `
    -Message "Backup detection not implemented; integrate with your backup solution/event logs." `
    -Data $null
```

Additional check implemented:

- `Get-ADSHCSystemStateBackup` — inspects Windows Backup event logs for recent system state backups and reports age.

Designed to be extended with:

- Queries against backup software / APIs.
- Event log analysis for system state/AD backups.

**Example:**

```powershell
$results = Get-ADBackupRecoveryCheck -Domain contoso.com
```

### `Get-ADKrbtgtAdminCheck`

**File:** `Public/Get-ADKrbtgtAdminCheck.ps1`  
**Internal functions:** in `Private/AD-AccountChecks.ps1`

**Purpose:**  
Focuses on krbtgt & administrator‑like accounts:

- `Get-ADSHCKrbtgtInfo`  
  - Inspects the `krbtgt` account (password last set, risk indicators).
- `Get-ADSHCAdminGuestInfo`  
  - Evaluates `Administrator` and `Guest` accounts, such as:
    - Enabled/disabled state.
    - Renamed default accounts.
    - Potential security risks.

Wrapper flow:

```powershell
Test-ADModuleLoaded -Name 'ActiveDirectory'
$params = @{}
if ($Domain) { $params['Server'] = $Domain }

$results = @()
$results += Get-ADSHCKrbtgtInfo @params
$results += Get-ADSHCAdminGuestInfo @params
```

**Example:**

```powershell
$results = Get-ADKrbtgtAdminCheck -Domain contoso.com
```

---

## Private / Internal Functions

Internal functions are under the `Private` folder and are dot‑sourced by `ADSecurityHealthCheck.psm1`.  
They are not exported directly but are essential building blocks.

### Result & Helper Utilities

**File:** `Private/Helpers.ps1`

- `New-ADSHCResult`  
  - Standardizes output of every check.
- `Test-ADModuleLoaded`  
  - Throws if required modules (e.g. `ActiveDirectory`, `GroupPolicy`, `DnsServer`) are not available.
- `Get-ADSHCDomainContext`  
  - Resolves domain / server context (used by many checks).
- Additional helper functions (not fully listed here) provide:
  - Attribute existence checks (`Test-ADAttributeExists`).
  - Common AD query patterns.
  - Conversions and risk evaluation helpers.

These helpers keep public functions thin and focused on orchestration.

### Account Security Checks

**File:** `Private/AD-AccountChecks.ps1`

All internal functions and purpose:

- `Get-ADSHCInactiveAccounts` — enabled users inactive for a threshold (default 90 days).
- `Get-ADSHCLockedAccounts` — locked out user accounts.
- `Get-ADSHCPasswordNeverExpires` — users with non‑expiring passwords.
- `Get-ADSHCPasswordNotRequired` — users not required to have a password.
- `Get-ADSHCReversibleEncryption` — users with reversible encryption enabled.
- `Get-ADSHCSIDHistory` — users with SIDHistory set.
- `Get-ADSHCBadPrimaryGroup` — users with non‑standard primary group.
- `Get-ADSHCDESEnabled` — users with DES enabled.
- `Get-ADSHCNotAESEnabled` — users without AES encryption enabled.
- `Get-ADSHCNoPreAuthRequired` — users without Kerberos pre‑auth.
- `Get-ADSHCTrustedForDelegation` — users/computers trusted for delegation.
- `Get-ADSHCDuplicateAccounts` — duplicate DisplayName/SamAccountName/UPN values.
- `Get-ADSHCSmartcardRequired` — accounts with smartcard requirement.
- `Get-ADSHCUnixPasswords` — Unix‑style password attributes (`msSFU30Password`, `userPassword`).
- `Get-ADSHCServiceAccounts` — heuristic service account identification.
- `Get-ADSHCComputerPasswordAge` — stale computer account password age (>90 days).
- `Get-ADSHCClusterPasswordAge` — cluster account password age (>180 days).
- `Get-ADSHCLAPSCoverage` — legacy/new LAPS attribute coverage.
- `Get-ADSHCPasswordAgeDistribution` — password age distribution for enabled users.
- `Get-ADSHCLAPSAgeDistribution` — LAPS password age distribution.
- `Get-ADSHCPrivilegedLastLogonDist` — privileged account last logon distribution.
- `Get-ADSHCPrivilegedPwdLastSetDist` — privileged password last set distribution.
- `Get-ADSHCStaleComputers` — stale computer accounts by last logon.
- `Get-ADSHCSmartcardCoverage` — smartcard requirement coverage summary.

### Privileged Group & DC Checks

**Files:**

- `Private/AD-PrivilegedGroupChecks.ps1`
- `Private/AD-DCChecks.ps1`

Privileged group functions:

- `Get-ADSHCPrivilegedGroupMembership` — enumerates members of privileged groups.
- `Get-ADSHCPrivilegedExternalMembers` — flags foreign security principals.
- `Get-ADSHCPrivilegedDisabledMembers` — disabled privileged users.
- `Get-ADSHCPrivilegedLockedMembers` — locked privileged users.
- `Get-ADSHCPrivilegedInactiveMembers` — inactive privileged users.
- `Get-ADSHCPrivilegedPasswordNeverExp` — non‑expiring privileged passwords.
- `Get-ADSHCPrivilegedCanBeDelegated` — privileged users allowed for delegation.
- `Get-ADSHCPrivilegedSmartcardRequired` — privileged users without smartcard requirement.
- `Get-ADSHCProtectedUsersIssues` — Protected Users group membership summary.
- `Get-ADSHCPrivilegedServiceAccounts` — heuristic service accounts in privileged groups.
- `Get-ADSHCPrivilegedSPNs` — privileged users with SPNs.
- `Get-ADSHCAllPrivilegedMembers` — flattened list of all privileged members.

Domain controller functions:

- `Get-ADSHCDCInventory` — DC inventory.
- `Get-ADSHCDCSecurity` — SMB1/2, spooler, WebClient, LDAP signing checks.
- `Get-ADSHCDCConfiguration` — DC configuration details (OS, roles, creation, etc.).
- `Get-ADSHCSysvolDfsrHealth` — SYSVOL/DFSR and SYSVOL share status.
- `Get-ADSHCTimeSync` — W32Time service state.
- `Get-ADSHCSecureChannel` — secure channel test (PS remoting required).
- `Get-ADSHCUnsupportedDCOS` — unsupported/legacy DC OS versions.

### GPO and GPP Checks

**File:** `Private/AD-GPOChecks.ps1`

Key functions (as described above):

- `Get-ADSHCGPPPasswords`
- `Get-ADSHCGPPFiles`
- `Get-ADSHCGPPFirewall`
- `Get-ADSHCGPPTerminalServices`
- `Get-ADSHCGPPFolderOptions`
- `Get-ADSHCGPPLoginScripts`
- `Get-ADSHCGPOPasswordPolicies`
- `Get-ADSHCGPOAuditPolicies`
- `Get-ADSHCGPOUserRights`
- `Get-ADSHCGPOWSUSConfig`
- `Get-ADSHCGPODefenderASR`
- `Get-ADSHCGPOEventForwarding`
- `Get-ADSHCGPODelegations`
- `Get-ADSHCGPOInformation`
- `Get-ADSHCGPOEmpty`
- `Get-ADSHCGPOUnlinked`
- `Get-ADSHCGPOWmiFilterIssues`

Each returns a `New-ADSHCResult` object with:

- `Category` like `GPO - GPP`, `GPO - Security`, etc.
- `Check` describing the specific area (e.g. `GPP passwords`).
- Severity based on risk.

### DNS Checks

**File:** `Private/AD-DNSChecks.ps1`

- `Get-ADSHCDNSZones`  
  - Uses `Get-DnsServerZone` and related DNS cmdlets to collect zone names, replication scope, and other properties.
- `Get-ADSHCDNSZoneTransfers` — flags zones allowing zone transfer.
- `Get-ADSHCDNSAgingScavenging` — flags zones without aging/scavenging.
- `Get-ADSHCDNSDynamicUpdates` — flags zones allowing nonsecure dynamic updates.

### AD CS Checks

**File:** `Private/AD-ADCSChecks.ps1`

Already covered above; key functions include:

- `Get-ADSHCADCSTemplates`
- `Get-ADSHCADCSCAs`
- `Get-ADSHCADCSESC1`
- `Get-ADSHCADCSESC2`
- `Get-ADSHCADCSESC3`
- `Get-ADSHCADCSESC4`
- `Get-ADSHCADCSESC5`
- `Get-ADSHCADCSESC6`
- `Get-ADSHCADCSESC7`
- `Get-ADSHCADCSESC8`
- `Get-ADSHCADCSNTAuthStore`
- `Get-ADSHCADCSEnrollmentAgents`

These output `Category = 'ADCS'` results with rich data about templates and CAs.

### Schema & Configuration Checks

**File:** `Private/AD-SchemaConfigChecks.ps1`

Typical functions:

- `Get-ADSHCSchemaInfo`
- `Get-ADSHCDomainConfig`
- `Get-ADSHCAdvancedConfig`

These focus on:

- Schema version and extensions.
- Domain and forest functional level.
- Enabled features and advanced security options.

### Delegation Checks

**File:** `Private/AD-DelegationChecks.ps1`

Known functions:

- `Get-ADSHCDelegations`  
  - Collects ACEs for delegated permissions (e.g. write rights on OUs).
- `Get-ADSHCUnprotectedOUs`  
  - Identifies OUs without accidental deletion protection (see snippet above).

### OS Inventory Checks

**File:** `Private/AD-OSInventoryChecks.ps1`

Functions here:

- Enumerate computer objects and gather OS data:
  - OS name/version.
  - Potential support status.
- Return results categorized as `OS Inventory` or similar.

### Site & Login Script Checks

**Files:**

- `Private/AD-SiteChecks.ps1` — `Get-ADSHCSites`
- `Private/AD-LoginScriptChecks.ps1` — `Get-ADSHCLoginScripts`

Responsibilities:

- Site topology and subnet coverage.
- Distribution of user logon scripts.

### Backup & Recovery Checks

**File:** `Private/AD-BackupRecoveryChecks.ps1`

- `Get-ADSHCBackupInfo`  
  - Currently a placeholder that informs the user that backup detection is not implemented and should be integrated with your backup solution / event logs.
- `Get-ADSHCSystemStateBackup`
  - Reads Windows Backup event logs to estimate last system state backup age.

---

## Output Format

Every check result is a `PSCustomObject` with:

- `Category` — broad area of the check (e.g. `Account Security`, `GPO - GPP`, `ADCS`, `Backup/Recovery`).
- `Check` — a short, unique check name.
- `Severity` — one of:
  - `Info`
  - `Warning`
  - `Critical`
  - `Error`
- `Message` — a human‑readable summary string.
- `Data` — raw or semi‑structured objects (e.g. AD objects, collections, or custom objects).

This design makes it straightforward to:

- Export to CSV/JSON.
- Feed into dashboards or reporting tools.
- Filter and sort by severity, category, or check name.

Example:

```powershell
$results |
  Where-Object Severity -in 'Critical','Warning' |
  Sort-Object Category, Check |
  Format-Table Category, Check, Severity, Message
```

---

## Extending the Module

To add a new check:

1. **Create a private function** under `Private\` (e.g. `Private\AD-NewCheckArea.ps1`) that:
   - Performs the necessary queries.
   - Returns a `New-ADSHCResult` object.

2. **Wire it into a public check**:
   - Either:
     - Call it from an existing public wrapper (e.g. `Get-ADSecurityHealthCheck` or `Get-ADAccountSecurityCheck`), or
     - Add a new public wrapper under `Public\` and export it in `ADSecurityHealthCheck.psd1`.

3. **Keep output consistent**:
   - Always use `New-ADSHCResult` so downstream consumers can handle results uniformly.

4. **Add documentation**:
   - Update this README (or additional docs) with:
     - The function name.
     - Description of what it checks.
     - Any dependencies (modules, permissions).

---

