<#PSScriptInfo

.VERSION 1.0.0

.GUID 7c1f3a52-8e4b-4d6a-9b0e-2f5d81c4a9e7

.AUTHOR TESC Scientific Computing

.COMPANYNAME The Evergreen State College - Scientific Computing

.COPYRIGHT (c) CC-BY 4.0

.TAGS Intune Entra EntraID MicrosoftGraph RBAC Audit AccessReview Endpoint

.LICENSEURI https://github.com/TESC-Scientific-Computing/endpoint-management/blob/main/LICENSE

.PROJECTURI https://github.com/TESC-Scientific-Computing/endpoint-management

.ICONURI

.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
1.0.0 Initial release: membership, Entra directory roles, Intune RBAC assignments,
      readable devices, optional PIM-eligible roles and Intune audit events, JSON/CSV export.

.PRIVATEDATA

#>

#Requires -Version 5.1

<#
.SYNOPSIS
  Reports what Intune access a user has: group membership, role assignments and the devices they can read.

.DESCRIPTION
  Queries Microsoft Graph (read-only) for the signed-in user, or for the user(s) given in
  -UserPrincipalName, and reports:

  1. Account details  - status, type, on-prem sync, department, optionally last sign-in.
  2. Membership       - every group the user belongs to, flagged Direct or Nested, with group type,
                        dynamic-membership rule and whether the group is role-assignable.
  3. Entra roles      - active directory roles (and, with -IncludeEligibleRoles, PIM-eligible roles).
                        Roles that implicitly grant Intune access (Global Administrator, Intune
                        Administrator, Global Reader) are flagged.
  4. Intune RBAC      - Intune role assignments that apply to the user through any of their groups,
                        with role, scope type, scope groups and whether the role grants device read.
  5. Devices          - managed devices the user can read, and how access is obtained
                        (all devices, or membership of an assignment scope group). Also lists the
                        devices where the user is the primary user.
  6. Audit (optional) - recent Intune audit events performed by the user (-IncludeAuditEvents).

  The script is standalone. It trusts and registers PSGallery if needed, installs the NuGet provider
  and the required module(s) for the current user, imports them, then connects with read-only
  Graph scopes. No tenant objects are created or modified.

  Sign-in (-AuthMode): single sign-on via WAM using the Windows/Edge work account, then device code
  (URL and code in the console, Edge opened) as a fallback. Browser cookies/tokens cannot be read directly.

  Limitation: device scope is derived from the assignment scope type and scope groups. Intune scope
  tags are not evaluated per device, so results may over-report devices for roles limited by tags.

.PARAMETER UserPrincipalName
  One or more UPNs (or object IDs) to query. When omitted, the account that signs in to Graph is used.
  Accepts pipeline input.

.PARAMETER TenantId
  Tenant ID or domain to sign in to. Defaults to the Evergreen tenant.

.PARAMETER ClientId
  Application (client) ID of a dedicated Entra app registration to sign in with. Defaults to the
  Microsoft Graph Command Line Tools app. See NOTES for the registration requirements.

.PARAMETER SkipDevices
  Skip the managed-device lookup (faster in large tenants).

.PARAMETER IncludeEligibleRoles
  Also report PIM-eligible Entra roles. Requests RoleEligibilitySchedule.Read.Directory.

.PARAMETER IncludeAuditEvents
  Also report the user's recent Intune audit events and last sign-in time.
  Requests DeviceManagementApps.Read.All and AuditLog.Read.All.

.PARAMETER AuditDays
  Look-back window in days for -IncludeAuditEvents. Default 30, range 1-90.

.PARAMETER OutputPath
  Folder to write a JSON report and CSV files per user. Created if missing.

.PARAMETER AuthMode
  How to sign in. Auto (default) tries single sign-on first and falls back to device code.
  SSO uses Web Account Manager (WAM) to reuse the work account already signed in to Windows/Edge.
  DeviceCode prints a code in the console and opens Microsoft Edge to the device login page.

.PARAMETER PassThru
  Return the result object(s) to the pipeline instead of only printing the summary.

.EXAMPLE
  .\Intune-Access-Query.ps1

  Reports access for the user running the script.

.EXAMPLE
  .\Intune-Access-Query.ps1 -UserPrincipalName jdoe@evergreen.edu -IncludeEligibleRoles -IncludeAuditEvents

  Reports access for another user, including PIM-eligible roles and recent audit activity.

.EXAMPLE
  'a@evergreen.edu','b@evergreen.edu' | .\Intune-Access-Query.ps1 -OutputPath C:\Temp\access -PassThru

  Audits several users and exports JSON and CSV files.

.INPUTS
  System.String. User principal names may be piped in.

.OUTPUTS
  None by default. With -PassThru, one PSCustomObject per user with the properties
  User, Groups, DirectoryRoles, EligibleRoles, IntuneRoleAssignments, Access, Devices,
  PrimaryUserDevices, AuditEvents and Warnings.

.NOTES
  Required Graph delegated permissions (read-only; admin consent is required in this tenant):
    User.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory,
    DeviceManagementRBAC.Read.All, DeviceManagementManagedDevices.Read.All, Device.Read.All
  Optional: RoleEligibilitySchedule.Read.Directory (-IncludeEligibleRoles),
    DeviceManagementApps.Read.All and AuditLog.Read.All (-IncludeAuditEvents).
  -SkipDevices drops the two device scopes.

  Dedicated app registration (-ClientId): register a single-tenant app, add the delegated Microsoft Graph
  permissions above, have an Entra admin grant consent, enable "Allow public client flows" (device code),
  and add the Mobile and desktop redirect URIs https://login.microsoftonline.com/common/oauth2/nativeclient
  and ms-appx-web://microsoft.aad.brokerplugin/<client id> (WAM single sign-on).
  Without -ClientId the shared Microsoft Graph Command Line Tools app
  (14d82eec-204b-4c2b-b7e8-296a70dab67e) is used, which also needs admin consent.

  Querying another user needs a role that can read those objects (for example Global Reader
  or Intune Administrator). A standard user can usually only query themselves.

.LINK
  https://github.com/TESC-Scientific-Computing/endpoint-management

.COMPONENT
  Microsoft Graph, Microsoft Intune RBAC, Microsoft Entra ID

.ROLE
  Access auditing / access review

.FUNCTIONALITY
  Read-only query of effective Intune access for a user.
#>

[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('User', 'UPN')]
    [string[]]$UserPrincipalName,

    [string]$TenantId = '22adcff7-c06f-49a6-8f20-50711c40ddaa',

    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [switch]$SkipDevices,
    [switch]$IncludeEligibleRoles,
    [switch]$IncludeAuditEvents,

    [ValidateRange(1, 90)]
    [int]$AuditDays = 30,

    [string]$OutputPath,
    [ValidateSet('Auto', 'SSO', 'DeviceCode')]
    [string]$AuthMode = 'Auto',

    [switch]$PassThru
)

begin {
    $ErrorActionPreference = 'Stop'
    $RequiredModules = @('Microsoft.Graph.Authentication')

    # ---------------------------------------------------------------------
    # Dependencies: PSGallery, NuGet provider, modules (CurrentUser scope)
    # ---------------------------------------------------------------------
    function Initialize-Dependency {
        param([string[]]$Module)

        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        $missing = @($Module | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
        if ($missing.Count -gt 0) {
            if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
                      Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
                Write-Host 'Installing NuGet package provider...' -ForegroundColor Cyan
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
            }

            $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if (-not $repo) {
                Register-PSRepository -Default
                $repo = Get-PSRepository -Name PSGallery
            }

            # Trust PSGallery only while installing, then restore the original policy
            $originalPolicy = $repo.InstallationPolicy
            try {
                if ($originalPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                }
                foreach ($m in $missing) {
                    Write-Host "Installing module $m from PSGallery..." -ForegroundColor Cyan
                    Install-Module -Name $m -Repository PSGallery -Scope CurrentUser -Force -AllowClobber
                }
            }
            finally {
                if ($originalPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy $originalPolicy
                }
            }
        }

        # Windows PowerShell cannot load two versions of an assembly; Graph fails with a TypeLoadException
        # when another module already loaded its own MSAL/Azure.Core build.
        if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
            $conflicts = [AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object { $_.GetName().Name -in 'Microsoft.Identity.Client', 'Azure.Core' -and
                               $_.Location -notmatch 'Microsoft\.Graph' } |
                ForEach-Object { "$($_.GetName().Name) $($_.GetName().Version)" }
            if ($conflicts) {
                Write-Warning "Conflicting assemblies already loaded in this session ($($conflicts -join '; '))."
                $script:Relaunch = $true
                return
            }
        }

        foreach ($m in $Module) { Import-Module -Name $m -ErrorAction Stop }
    }

    # ---------------------------------------------------------------------
    # Graph helpers
    # ---------------------------------------------------------------------
    function Invoke-GraphPaged {
        param([Parameter(Mandatory)][string]$Uri, [int]$Max = 0)
        $results = New-Object System.Collections.Generic.List[object]
        $next = $Uri
        while ($next) {
            $r = Invoke-MgGraphRequest -Method GET -Uri $next -Headers @{ ConsistencyLevel = 'eventual' }
            if ($r.ContainsKey('value')) { foreach ($i in $r.value) { $results.Add($i) } } else { $results.Add($r) }
            if ($Max -gt 0 -and $results.Count -ge $Max) { break }
            $next = $r['@odata.nextLink']
        }
        , $results.ToArray()
    }

    $script:GroupNameCache = @{}
    function Get-GroupName {
        param([string]$Id)
        if (-not $script:GroupNameCache.ContainsKey($Id)) {
            try {
                $g = Invoke-MgGraphRequest -Method GET -Uri "v1.0/groups/$Id`?`$select=displayName"
                $script:GroupNameCache[$Id] = $g.displayName
            }
            catch { $script:GroupNameCache[$Id] = "(unresolved: $Id)" }
        }
        $script:GroupNameCache[$Id]
    }

    # Entra roles that implicitly grant Intune access (template IDs)
    $ImplicitIntuneRoles = @{
        '62e90394-69f5-4237-9190-012177145e10' = 'Full'   # Global Administrator
        '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Full'   # Intune Administrator
        'f2ef992c-3afb-46b9-b7cf-a126ee74c451' = 'Read'   # Global Reader
    }
    $ReadActionPattern = 'ManagedDevices[_/]Read'
    $script:ManagedDevices = $null
    $script:Connected = $false

    Initialize-Dependency -Module $RequiredModules

    $script:Relaunch = $false
    $script:Targets = New-Object System.Collections.Generic.List[string]
    Initialize-Dependency -Module $RequiredModules
    if ($script:Relaunch -and $env:IAQ_CHILD) { throw 'Assembly conflict persists in a clean process; reinstall Microsoft.Graph.Authentication.' }
    if ($script:Relaunch) { return }

    # Minimum read-only set; Directory.Read.All is deliberately not requested
    $scopes = @(
        'User.Read.All', 'GroupMember.Read.All',
        'RoleManagement.Read.Directory', 'DeviceManagementRBAC.Read.All'
    )
    if (-not $SkipDevices)       { $scopes += 'DeviceManagementManagedDevices.Read.All', 'Device.Read.All' }
    if ($IncludeEligibleRoles)   { $scopes += 'RoleEligibilitySchedule.Read.Directory' }
    if ($IncludeAuditEvents)     { $scopes += 'DeviceManagementApps.Read.All', 'AuditLog.Read.All' }

    Write-Host 'Connecting to Microsoft Graph (read-only scopes)...' -ForegroundColor Cyan
    $connectParams = @{ Scopes = $scopes; TenantId = $TenantId; NoWelcome = $true }
    if ($ClientId) {
        $connectParams.ClientId = $ClientId
        Write-Host "Using app registration $ClientId" -ForegroundColor Cyan
    }
    $consentUrl = "https://login.microsoftonline.com/$TenantId/adminconsent?client_id=" +
                  $(if ($ClientId) { $ClientId } else { '14d82eec-204b-4c2b-b7e8-296a70dab67e' })

    $connectSso = {
        # WAM reuses the work account already signed in to Windows/Edge, so no prompt is normally shown
        Set-MgGraphOption -DisableLoginByWAM $false -ErrorAction SilentlyContinue
        Write-Host 'Trying single sign-on with the Windows/Edge work account...' -ForegroundColor Yellow
        Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
    }
    $connectDeviceCode = {
        Set-MgGraphOption -DisableLoginByWAM $true -ErrorAction SilentlyContinue
        Write-Host 'Device code sign-in: Edge will open; enter the code shown below.' -ForegroundColor Yellow
        $edgePath = (Get-Command msedge.exe -ErrorAction SilentlyContinue).Source
        if (-not $edgePath) {
            foreach ($d in @("${env:ProgramFiles(x86)}", $env:ProgramFiles)) {
                $cand = Join-Path $d 'Microsoft\Edge\Application\msedge.exe'
                if (Test-Path -LiteralPath $cand) { $edgePath = $cand; break }
            }
        }
        if ($edgePath) { Start-Process -FilePath $edgePath -ArgumentList 'https://microsoft.com/devicelogin' }
        # The code is emitted on the output stream, so it must not be piped to Out-Null
        Connect-MgGraph @connectParams -UseDeviceAuthentication -ErrorAction Stop
    }

    try {
        switch ($AuthMode) {
            'SSO'        { & $connectSso }
            'DeviceCode' { & $connectDeviceCode }
            default {
                try { & $connectSso }
                catch [System.TypeLoadException] { throw }
                catch {
                    Write-Warning "Single sign-on failed ($($_.Exception.Message)); falling back to device code."
                    & $connectDeviceCode
                }
            }
        }
    }
    catch [System.TypeLoadException] {
        if ($env:IAQ_CHILD) { throw }
        Write-Warning "Graph assembly conflict in this session: $($_.Exception.Message)"
        $script:Relaunch = $true
        return
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'AADSTS(65001|90094|90008|900941)|consent|admin') {
            Write-Warning ("Admin consent is required for the requested read-only scopes: $($scopes -join ', '). " +
                           "An Entra admin (Cloud Application Administrator or higher) can grant it at: $consentUrl")
        }
        throw "Sign-in failed or timed out: $msg Re-run the script; with device code, enter the code within a few minutes."
    }
    $ctx = Get-MgContext
    Write-Host "Connected as $($ctx.Account) (tenant $($ctx.TenantId))" -ForegroundColor Green

    if ($OutputPath -and -not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
}

process {
    if ($UserPrincipalName) { foreach ($u in $UserPrincipalName) { foreach ($x in ($u -split ',')) { if ($x.Trim()) { $script:Targets.Add($x.Trim()) } } } }
}

end {
    if ($script:Relaunch) {
        # Re-run in a clean powershell.exe so no stale or conflicting assemblies are loaded
        Write-Host 'Relaunching in a clean PowerShell process...' -ForegroundColor Yellow
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        foreach ($k in $PSBoundParameters.Keys) {
            if ($k -in 'UserPrincipalName', 'PassThru') { continue }
            $v = $PSBoundParameters[$k]
            if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v) { $argList += "-$k" } }
            else { $argList += "-$k"; $argList += [string]$v }
        }
        if ($script:Targets.Count -gt 0) { $argList += '-UserPrincipalName'; $argList += ($script:Targets -join ',') }
        if ($PassThru) { Write-Warning '-PassThru is not supported when relaunching; use -OutputPath for the results.' }
        $env:IAQ_CHILD = '1'
        try { & (Join-Path $PSHOME 'powershell.exe') @argList }
        finally { Remove-Item Env:\IAQ_CHILD -ErrorAction SilentlyContinue }
        return
    }

    if ($script:Targets.Count -eq 0) { $script:Targets.Add('me') }

    foreach ($target in $script:Targets) {
        $warnings = New-Object System.Collections.Generic.List[string]
        $userRef = if ($target -eq 'me') { 'me' } else { "users/$([uri]::EscapeDataString($target))" }

        # -----------------------------------------------------------------
        # 1. Account
        # -----------------------------------------------------------------
        $props = 'id,displayName,userPrincipalName,mail,accountEnabled,userType,jobTitle,department,onPremisesSyncEnabled,createdDateTime'
        if ($IncludeAuditEvents) { $props += ',signInActivity' }
        try {
            $u = Invoke-MgGraphRequest -Method GET -Uri "v1.0/$userRef`?`$select=$props"
        }
        catch {
            if ($IncludeAuditEvents) {
                $warnings.Add("signInActivity unavailable: $($_.Exception.Message)")
                $props = $props -replace ',signInActivity', ''
                $u = Invoke-MgGraphRequest -Method GET -Uri "v1.0/$userRef`?`$select=$props"
            }
            else { throw }
        }
        $upn = $u.userPrincipalName
        Write-Host "`n=== Intune access report: $($u.displayName) <$upn> ===" -ForegroundColor Cyan

        $account = [pscustomobject]@{
            DisplayName    = $u.displayName
            UserPrincipal  = $upn
            ObjectId       = $u.id
            Enabled        = $u.accountEnabled
            UserType       = $u.userType
            Department     = $u.department
            JobTitle       = $u.jobTitle
            OnPremSynced   = [bool]$u.onPremisesSyncEnabled
            Created        = $u.createdDateTime
            LastSignIn     = $u.signInActivity.lastSignInDateTime
            LastNonInteractiveSignIn = $u.signInActivity.lastNonInteractiveSignInDateTime
        }
        $account | Format-List

        # -----------------------------------------------------------------
        # 2. Membership (groups) and active Entra roles
        # -----------------------------------------------------------------
        $groups = @(); $dirRoles = @(); $groupIds = @{}
        try {
            $direct = @{}
            foreach ($d in (Invoke-GraphPaged "v1.0/users/$($u.id)/memberOf")) { $direct[$d.id] = $true }
            $transitive = Invoke-GraphPaged "v1.0/users/$($u.id)/transitiveMemberOf"

            foreach ($m in $transitive) {
                $type = $m['@odata.type'] -replace '#microsoft.graph.', ''
                if ($type -eq 'group') {
                    $groupIds[$m.id] = $m.displayName
                    $script:GroupNameCache[$m.id] = $m.displayName
                    $kind = if ($m.groupTypes -contains 'Unified') { 'Microsoft 365' }
                            elseif ($m.securityEnabled) { 'Security' } else { 'Other' }
                    $groups += [pscustomobject]@{
                        Name           = $m.displayName
                        Id             = $m.id
                        Type           = $kind
                        Membership     = if ($direct.ContainsKey($m.id)) { 'Direct' } else { 'Nested' }
                        Dynamic        = ($m.groupTypes -contains 'DynamicMembership')
                        MembershipRule = $m.membershipRule
                        RoleAssignable = [bool]$m.isAssignableToRole
                        OnPremSynced   = [bool]$m.onPremisesSyncEnabled
                    }
                }
                elseif ($type -eq 'directoryRole') {
                    $dirRoles += [pscustomobject]@{
                        Role             = $m.displayName
                        RoleTemplateId   = $m.roleTemplateId
                        Assignment       = if ($direct.ContainsKey($m.id)) { 'Direct' } else { 'Via group' }
                        ImplicitIntune   = $ImplicitIntuneRoles[$m.roleTemplateId]
                    }
                }
            }
        }
        catch { $warnings.Add("Membership lookup failed: $($_.Exception.Message)") }

        Write-Host "`n--- Group membership ($($groups.Count)) ---" -ForegroundColor Cyan
        $groups | Sort-Object Membership, Name | Format-Table Name, Type, Membership, Dynamic, RoleAssignable, OnPremSynced -AutoSize
        Write-Host "--- Active Entra directory roles ($($dirRoles.Count)) ---" -ForegroundColor Cyan
        $dirRoles | Format-Table Role, Assignment, ImplicitIntune -AutoSize

        $eligible = @()
        if ($IncludeEligibleRoles) {
            try {
                $uri = "v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($u.id)'&`$expand=roleDefinition"
                foreach ($e in (Invoke-GraphPaged $uri)) {
                    $eligible += [pscustomobject]@{
                        Role           = $e.roleDefinition.displayName
                        RoleTemplateId = $e.roleDefinition.templateId
                        DirectoryScope = $e.directoryScopeId
                        Status         = $e.status
                        Start          = $e.scheduleInfo.startDateTime
                        Expires        = $e.scheduleInfo.expiration.endDateTime
                        ImplicitIntune = $ImplicitIntuneRoles[$e.roleDefinition.templateId]
                    }
                }
                Write-Host "--- PIM-eligible Entra roles ($($eligible.Count)) ---" -ForegroundColor Cyan
                $eligible | Format-Table Role, DirectoryScope, Expires, ImplicitIntune -AutoSize
            }
            catch { $warnings.Add("Eligible role lookup failed: $($_.Exception.Message)") }
        }

        # -----------------------------------------------------------------
        # 3. Intune RBAC role assignments that apply to the user
        # -----------------------------------------------------------------
        $assignments = @()
        try {
            foreach ($stub in (Invoke-GraphPaged 'v1.0/deviceManagement/roleAssignments')) {
                $a = Invoke-MgGraphRequest -Method GET -Uri "v1.0/deviceManagement/roleAssignments/$($stub.id)?`$expand=roleDefinition"
                $viaIds = @($a.members | Where-Object { $groupIds.ContainsKey($_) })
                if ($viaIds.Count -eq 0) { continue }

                $perms = @($a.roleDefinition.rolePermissions |
                    ForEach-Object { $_.resourceActions } |
                    ForEach-Object { $_.allowedResourceActions }) | Where-Object { $_ }
                $scopeType = if ($a.scopeType) { $a.scopeType } else { 'resourceScope' }
                $assignments += [pscustomobject]@{
                    Assignment       = $a.displayName
                    AssignmentId     = $a.id
                    Role             = $a.roleDefinition.displayName
                    RoleId           = $a.roleDefinition.id
                    BuiltInRole      = [bool]$a.roleDefinition.isBuiltIn
                    ViaGroups        = ($viaIds | ForEach-Object { Get-GroupName $_ }) -join '; '
                    ScopeType        = $scopeType
                    ScopeGroupIds    = @($a.resourceScopes | Where-Object { $_ -and $_ -ne '/' })
                    ScopeGroups      = (@($a.resourceScopes | Where-Object { $_ -and $_ -ne '/' }) | ForEach-Object { Get-GroupName $_ }) -join '; '
                    GrantsDeviceRead = [bool]($perms | Where-Object { $_ -match $ReadActionPattern })
                    PermissionCount  = @($perms).Count
                }
            }
        }
        catch { $warnings.Add("Intune role assignment lookup failed: $($_.Exception.Message)") }

        Write-Host "--- Intune RBAC role assignments ($($assignments.Count)) ---" -ForegroundColor Cyan
        $assignments | Format-Table Assignment, Role, ViaGroups, ScopeType, ScopeGroups, GrantsDeviceRead -AutoSize

        # -----------------------------------------------------------------
        # 4. Effective access summary
        # -----------------------------------------------------------------
        $implicitFull = @($dirRoles | Where-Object ImplicitIntune -eq 'Full')
        $implicitRead = @($dirRoles | Where-Object ImplicitIntune -eq 'Read')
        $readAssignments = @($assignments | Where-Object GrantsDeviceRead)
        $allDevices = ($implicitFull.Count + $implicitRead.Count) -gt 0 -or
                      [bool]($readAssignments | Where-Object { $_.ScopeType -match 'allDevices' })
        $access = [pscustomobject]@{
            HasIntuneAccess        = ($assignments.Count + $implicitFull.Count + $implicitRead.Count) -gt 0
            ImplicitEntraRoles     = (($implicitFull + $implicitRead).Role) -join '; '
            CanReadDevices         = ($readAssignments.Count + $implicitFull.Count + $implicitRead.Count) -gt 0
            ReadsAllDevices        = $allDevices
            IntuneRoleCount        = $assignments.Count
            AssignmentsWithoutRead = @($assignments | Where-Object { -not $_.GrantsDeviceRead }).Count
        }
        Write-Host '--- Effective access ---' -ForegroundColor Cyan
        $access | Format-List

        # -----------------------------------------------------------------
        # 5. Devices the user can read
        # -----------------------------------------------------------------
        $devices = @(); $primaryDevices = @()
        if (-not $SkipDevices) {
            try {
                if ($null -eq $script:ManagedDevices) {
                    Write-Host 'Loading managed devices...' -ForegroundColor Cyan
                    $sel = 'id,deviceName,operatingSystem,osVersion,userId,userPrincipalName,azureADDeviceId,complianceState,lastSyncDateTime,managedDeviceOwnerType,model,serialNumber'
                    $script:ManagedDevices = Invoke-GraphPaged "v1.0/deviceManagement/managedDevices?`$select=$sel&`$top=999"
                }

                $access_via = @{}
                if ($allDevices) {
                    $viaText = if ($implicitFull.Count + $implicitRead.Count -gt 0) { 'Entra role: ' + $access.ImplicitEntraRoles } else { 'Intune role: All devices' }
                    foreach ($d in $script:ManagedDevices) { $access_via[$d.id] = $viaText }
                }
                else {
                    foreach ($ra in ($readAssignments | Where-Object { $_.ScopeGroupIds.Count -gt 0 })) {
                        foreach ($gid in $ra.ScopeGroupIds) {
                            $devIds = @{}; $userIds = @{}
                            foreach ($m in (Invoke-GraphPaged "v1.0/groups/$gid/transitiveMembers?`$select=id,deviceId")) {
                                $t = $m['@odata.type'] -replace '#microsoft.graph.', ''
                                if ($t -eq 'device' -and $m.deviceId) { $devIds[$m.deviceId] = $true }
                                elseif ($t -eq 'user') { $userIds[$m.id] = $true }
                            }
                            foreach ($d in $script:ManagedDevices) {
                                if (($d.azureADDeviceId -and $devIds.ContainsKey($d.azureADDeviceId)) -or
                                    ($d.userId -and $userIds.ContainsKey($d.userId))) {
                                    $label = "$($ra.Role) via scope group $(Get-GroupName $gid)"
                                    if ($access_via.ContainsKey($d.id)) { $access_via[$d.id] += "; $label" } else { $access_via[$d.id] = $label }
                                }
                            }
                        }
                    }
                }

                $devices = @($script:ManagedDevices | Where-Object { $access_via.ContainsKey($_.id) } | ForEach-Object {
                    [pscustomobject]@{
                        DeviceName  = $_.deviceName
                        OS          = $_.operatingSystem
                        OSVersion   = $_.osVersion
                        PrimaryUser = $_.userPrincipalName
                        Compliance  = $_.complianceState
                        LastSync    = $_.lastSyncDateTime
                        Serial      = $_.serialNumber
                        IntuneId    = $_.id
                        AccessVia   = $access_via[$_.id]
                    }
                } | Sort-Object DeviceName)

                $primaryDevices = @($script:ManagedDevices | Where-Object { $_.userId -eq $u.id } | ForEach-Object {
                    [pscustomobject]@{
                        DeviceName = $_.deviceName; OS = $_.operatingSystem
                        Compliance = $_.complianceState; LastSync = $_.lastSyncDateTime; IntuneId = $_.id
                    }
                })

                Write-Host "--- Devices readable by user ($($devices.Count) of $($script:ManagedDevices.Count) managed) ---" -ForegroundColor Cyan
                $devices | Format-Table DeviceName, OS, PrimaryUser, Compliance, LastSync, AccessVia -AutoSize
                Write-Host "--- Devices where user is primary user ($($primaryDevices.Count)) ---" -ForegroundColor Cyan
                $primaryDevices | Format-Table DeviceName, OS, Compliance, LastSync -AutoSize
            }
            catch { $warnings.Add("Device lookup failed: $($_.Exception.Message)") }
        }

        # -----------------------------------------------------------------
        # 6. Recent Intune audit events performed by the user
        # -----------------------------------------------------------------
        $audit = @()
        if ($IncludeAuditEvents) {
            try {
                $since = (Get-Date).ToUniversalTime().AddDays(-$AuditDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
                $events = Invoke-GraphPaged "v1.0/deviceManagement/auditEvents?`$filter=activityDateTime ge $since&`$top=500" -Max 5000
                $audit = @($events | Where-Object { $_.actor.userPrincipalName -eq $upn } | ForEach-Object {
                    [pscustomobject]@{
                        Time      = $_.activityDateTime
                        Activity  = $_.activity
                        Operation = $_.activityOperationType
                        Type      = $_.activityType
                        Result    = $_.activityResult
                        Category  = $_.category
                        Targets   = (@($_.resources | ForEach-Object { $_.displayName }) | Where-Object { $_ }) -join '; '
                    }
                } | Sort-Object Time -Descending)
                Write-Host "--- Intune audit events by user, last $AuditDays days ($($audit.Count)) ---" -ForegroundColor Cyan
                $audit | Select-Object -First 25 | Format-Table Time, Operation, Activity, Result, Targets -AutoSize
            }
            catch { $warnings.Add("Audit event lookup failed: $($_.Exception.Message)") }
        }

        foreach ($w in $warnings) { Write-Warning $w }

        $result = [pscustomobject]@{
            User                 = $account
            Groups               = $groups
            DirectoryRoles       = $dirRoles
            EligibleRoles        = $eligible
            IntuneRoleAssignments = $assignments
            Access               = $access
            Devices              = $devices
            PrimaryUserDevices   = $primaryDevices
            AuditEvents          = $audit
            Warnings             = @($warnings)
            QueriedBy            = $ctx.Account
            QueriedAt            = (Get-Date).ToString('o')
        }

        if ($OutputPath) {
            $base = Join-Path $OutputPath (($upn -replace '[^\w@.\-]', '_') + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$base.json" -Encoding UTF8
            $groups   | Export-Csv -LiteralPath "$base-groups.csv"      -NoTypeInformation -Encoding UTF8
            $dirRoles | Export-Csv -LiteralPath "$base-entra-roles.csv" -NoTypeInformation -Encoding UTF8
            $assignments | Select-Object * -ExcludeProperty ScopeGroupIds |
                Export-Csv -LiteralPath "$base-intune-roles.csv" -NoTypeInformation -Encoding UTF8
            if ($devices.Count -gt 0) { $devices | Export-Csv -LiteralPath "$base-devices.csv" -NoTypeInformation -Encoding UTF8 }
            Write-Host "Report written to $base*" -ForegroundColor Green
        }

        if ($PassThru) { $result }
    }

    Disconnect-MgGraph | Out-Null
}
