<#
.SYNOPSIS
  Sets up complete RBAC for Scientific Computing self-management under the Evergreen (22adcff7-c06f-49a6-8f20-50711c40ddaa) tenant.
  Aligns with Memorandum-SO-OIT-Intune (Science Operations → OIT, April 17 2026) and
  https://github.com/TESC-Scientific-Computing/endpoint-management

.DESCRIPTION
  Creates:
  - Entra ID security group "SG-Scientific-Computing-Admins"
  - Custom Intune RBAC role "Scientific-Computing-Administrator"
  - Scope Tag "Scientific-Computing"
  - Role assignment of the custom role to the admin group, scoped to the Scope Tag

  On-prem Active Directory OU delegation (OU=ScientificComputing,OU=Workstations,DC=evergreen,DC=edu)

.NOTES
  Requires:
  - Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.DeviceManagement,
    Microsoft.Graph.DeviceManagement.Administration modules; any that are missing are installed
    from PSGallery for the current user (PSGallery is set to Trusted) at the start of the script
  - Global Administrator or Privileged Role Administrator + Intune Administrator rights to run once
  - Tenant: 22adcff7-c06f-49a6-8f20-50711c40ddaa
#>

[CmdletBinding()]
param(
    [string]$AdminGroupName        = "SG-Scientific-Computing-Admins",
    [string]$CustomRoleName        = "Scientific-Computing-Administrator",
    [string]$ScopeTagName          = "Scientific-Computing",
    [string]$ScopeTagDescription   = "Scope tag for Scientific Computing devices and objects - enables delegated self-management",
    [string]$TenantId              = "22adcff7-c06f-49a6-8f20-50711c40ddaa"
)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $color = switch ($Level) { 'START' { 'Cyan' } 'DONE' { 'Green' } 'SKIP' { 'Yellow' } 'WARN' { 'DarkYellow' } 'ERROR' { 'Red' } default { 'Gray' } }
    Write-Host ("[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message) -ForegroundColor $color
}

$ScriptTimer = [System.Diagnostics.Stopwatch]::StartNew()
$StepTimer   = [System.Diagnostics.Stopwatch]::StartNew()
$StepTotal   = 8
$StepNumber  = 0
function Start-Step {
    param([string]$Name)
    $script:StepNumber++
    $script:StepTimer.Restart()
    Write-Host ""
    Write-Log "Step $script:StepNumber/${script:StepTotal}: $Name - starting" 'START'
}
function Complete-Step {
    param([string]$Detail)
    $elapsed = [math]::Round($script:StepTimer.Elapsed.TotalSeconds, 1)
    Write-Log "Step $script:StepNumber/${script:StepTotal} finished in ${elapsed}s$(if ($Detail) { ' - ' + $Detail })" 'DONE'
}

Write-Log "Intune RBAC setup for Scientific Computing started (tenant $TenantId)" 'START'
Write-Log "Planned: group '$AdminGroupName', scope tag '$ScopeTagName', role '$CustomRoleName', role assignment" 'INFO'

Write-Log "Checking PSGallery repository trust..." 'INFO'
if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
    Write-Log "PSGallery is not trusted; setting InstallationPolicy to Trusted" 'WARN'
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    Write-Log "PSGallery is now trusted" 'DONE'
} else {
    Write-Log "PSGallery is already trusted" 'SKIP'
}

# Modules are installed here rather than with #Requires, which would stop the script before it could install them
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.DeviceManagement.Administration'
)
Write-Log "Checking required modules: $($RequiredModules -join ', ')" 'INFO'
$MissingModules = @($RequiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
if ($MissingModules.Count -gt 0) {
    Write-Log "$($MissingModules.Count) module(s) missing: $($MissingModules -join ', ')" 'WARN'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
              Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
        Write-Log "Installing NuGet package provider..." 'INFO'
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
        Write-Log "NuGet package provider installed" 'DONE'
    }
    foreach ($Module in $MissingModules) {
        Write-Log "Installing module $Module from PSGallery (CurrentUser)..." 'INFO'
        Install-Module -Name $Module -Repository PSGallery -Scope CurrentUser -Force -AllowClobber
        Write-Log "Installed module $Module" 'DONE'
    }
} else {
    Write-Log "All required modules are already installed" 'SKIP'
}
foreach ($Module in $RequiredModules) {
    Write-Log "Importing module $Module..." 'INFO'
    Import-Module -Name $Module -ErrorAction Stop
}
Write-Log "Modules ready" 'DONE'

# --------------------------------------------------------------------------
# 1. Connect to Microsoft Graph with the required permissions
# --------------------------------------------------------------------------
$RequiredScopes = @(
    "RoleManagement.ReadWrite.Directory",
    "Group.ReadWrite.All",
    "DeviceManagementRBAC.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "Directory.ReadWrite.All"
)

Start-Step "Connect to Microsoft Graph"
Write-Log "Requesting scopes: $($RequiredScopes -join ', ')" 'INFO'
Write-Log "Signing in to tenant $TenantId (a sign-in prompt may appear)..." 'INFO'
Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId -NoWelcome
$GraphContext = Get-MgContext
Write-Log "Connected as $($GraphContext.Account) to tenant $($GraphContext.TenantId)" 'DONE'
Complete-Step
# Optionally: Select-MgProfile -Name "beta" if you need beta endpoints

# --------------------------------------------------------------------------
# 1a. Pre-flight check – current user's directory roles & groups
# --------------------------------------------------------------------------
Start-Step "Pre-flight: current user's directory roles and groups"
Write-Log "Reading memberships for $($GraphContext.Account)..." 'INFO'
try {
    $Memberships = @(Get-MgUserMemberOf -UserId (Get-MgContext).Account -All |
        ForEach-Object {
            [pscustomobject]@{
                Type = $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
                Name = $_.AdditionalProperties.displayName
            }
        } |
        Sort-Object Type, Name)
    $Memberships | Format-Table -AutoSize
    Complete-Step "$($Memberships.Count) memberships found"
}
catch {
    Write-Log "Could not retrieve membership information: $($_.Exception.Message)" 'WARN'
}

# --------------------------------------------------------------------------
# 1b. Pre-flight check – existing Intune role assignments
# --------------------------------------------------------------------------
Start-Step "Pre-flight: existing Intune RBAC role assignments"
try {
    Write-Log "Ensuring read scope DeviceManagementRBAC.Read.All..." 'INFO'
    # Ensure we have the read scope (already included above, but re-connect is harmless)
    Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All" -TenantId $TenantId -NoWelcome | Out-Null
    Write-Log "Listing existing role assignments..." 'INFO'
    $PreAssignments = @(Get-MgDeviceManagementRoleAssignment -All)
    $PreAssignments |
        Select-Object DisplayName, Id |
        Format-Table -AutoSize
    Complete-Step "$($PreAssignments.Count) role assignments found"
}
catch {
    Write-Log "Could not list existing role assignments: $($_.Exception.Message)" 'WARN'
}

Write-Log "Pre-flight checks complete; proceeding with setup (changes will be made from here)" 'DONE'

# --------------------------------------------------------------------------
# 2. Create (or retrieve) the Entra ID security group for SciComp admins
# --------------------------------------------------------------------------
Start-Step "Ensure Entra ID group '$AdminGroupName'"
Write-Log "Looking up group '$AdminGroupName'..." 'INFO'

$ExistingGroup = Get-MgGroup -Filter "displayName eq '$AdminGroupName'" -ErrorAction SilentlyContinue
if ($ExistingGroup) {
    $AdminGroup = $ExistingGroup
    Write-Log "Group already exists, skipping creation: $($AdminGroup.Id)" 'SKIP'
} else {
    Write-Log "Group not found; creating security group '$AdminGroupName'..." 'INFO'
    $AdminGroup = New-MgGroup -DisplayName $AdminGroupName `
                              -MailEnabled:$false `
                              -MailNickname ($AdminGroupName -replace '[^a-zA-Z0-9]','') `
                              -SecurityEnabled `
                              -Description "Security group for Scientific Computing administrators. Members receive the custom Intune RBAC role scoped to Scientific-Computing."
    Write-Log "Created group: $($AdminGroup.Id)" 'DONE'
}
Complete-Step

# --------------------------------------------------------------------------
# 3. Create the Scope Tag "Scientific-Computing"
# --------------------------------------------------------------------------
Start-Step "Ensure Scope Tag '$ScopeTagName'"
Write-Log "Listing existing scope tags..." 'INFO'

$ExistingTags = Get-MgDeviceManagementRoleScopeTag -All
$ScopeTag = $ExistingTags | Where-Object { $_.DisplayName -eq $ScopeTagName }

if ($ScopeTag) {
    Write-Log "Scope Tag already exists, skipping creation: $($ScopeTag.Id)" 'SKIP'
} else {
    Write-Log "Scope Tag not found; creating '$ScopeTagName'..." 'INFO'
    $ScopeTag = New-MgDeviceManagementRoleScopeTag -DisplayName $ScopeTagName `
                                                   -Description $ScopeTagDescription
    Write-Log "Created Scope Tag: $($ScopeTag.Id)" 'DONE'
}
Complete-Step

# --------------------------------------------------------------------------
# 4. Define & create the custom Intune RBAC role
#    Permissions map to the requirements in the Memorandum:
#    - manage Devices
#    - Device Group Management (dynamic / static)
#    - manage Groups
#    - manage MDM Configuration Profiles
#    - manage Endpoint Security
#    - manage Mobile Apps
#    - (WCD / provisioning packages are covered by device configuration + enrollment rights)
# --------------------------------------------------------------------------
Start-Step "Ensure custom Intune RBAC role '$CustomRoleName'"
Write-Log "Preparing role definition with permission list..." 'INFO'

# Resource actions that give SciComp the self-management surface they need
$ResourceActions = @(
    # Devices
    "Microsoft.Intune_ManagedDevices_Read",
    "Microsoft.Intune_ManagedDevices_Update",
    "Microsoft.Intune_ManagedDevices_Delete",
    "Microsoft.Intune_ManagedDevices_SetPrimaryUser",
    "Microsoft.Intune_RemoteTasks_Retire",
    "Microsoft.Intune_RemoteTasks_Wipe",
    "Microsoft.Intune_RemoteTasks_Sync",
    "Microsoft.Intune_RemoteTasks_Restart",
    "Microsoft.Intune_RemoteTasks_LocateDevice",
    "Microsoft.Intune_RemoteTasks_RemoteLock",
    "Microsoft.Intune_RemoteTasks_EnableLostMode",
    "Microsoft.Intune_RemoteTasks_DisableLostMode",
    "Microsoft.Intune_RemoteTasks_RequestRemoteAssistance",

    # Device configuration / MDM profiles
    "Microsoft.Intune_DeviceConfigurations_Read",
    "Microsoft.Intune_DeviceConfigurations_Create",
    "Microsoft.Intune_DeviceConfigurations_Update",
    "Microsoft.Intune_DeviceConfigurations_Delete",
    "Microsoft.Intune_DeviceConfigurations_Assign",

    # Endpoint security
    "Microsoft.Intune_SecurityBaselines_Read",
    "Microsoft.Intune_SecurityBaselines_Create",
    "Microsoft.Intune_SecurityBaselines_Update",
    "Microsoft.Intune_SecurityBaselines_Delete",
    "Microsoft.Intune_SecurityBaselines_Assign",
    "Microsoft.Intune_EndpointSecurity_Read",
    "Microsoft.Intune_EndpointSecurity_Create",
    "Microsoft.Intune_EndpointSecurity_Update",
    "Microsoft.Intune_EndpointSecurity_Delete",
    "Microsoft.Intune_EndpointSecurity_Assign",

    # Apps
    "Microsoft.Intune_MobileApps_Read",
    "Microsoft.Intune_MobileApps_Create",
    "Microsoft.Intune_MobileApps_Update",
    "Microsoft.Intune_MobileApps_Delete",
    "Microsoft.Intune_MobileApps_Assign",
    "Microsoft.Intune_MobileApps_Relate",

    # Groups (device & user groups that SciComp owns)
    "Microsoft.Intune_Organization_Read",
    "Microsoft.DirectoryServices_Groups_Read",
    "Microsoft.DirectoryServices_Groups_Create",
    "Microsoft.DirectoryServices_Groups_Update",
    "Microsoft.DirectoryServices_Groups_Delete",
    "Microsoft.DirectoryServices_Groups_AssignMembership",

    # Scope tags (read + assign their own)
    "Microsoft.Intune_RoleScopeTags_Read",
    "Microsoft.Intune_RoleScopeTags_Assign",

    # Enrollment / Autopilot / provisioning (helps with WCD packages)
    "Microsoft.Intune_EnrollmentPrograms_Read",
    "Microsoft.Intune_EnrollmentPrograms_Create",
    "Microsoft.Intune_EnrollmentPrograms_Update",
    "Microsoft.Intune_EnrollmentPrograms_Delete",
    "Microsoft.Intune_EnrollmentPrograms_Assign",
    "Microsoft.Intune_DeviceEnrollmentManagers_Read",
    "Microsoft.Intune_DeviceEnrollmentManagers_Create",
    "Microsoft.Intune_DeviceEnrollmentManagers_Update",
    "Microsoft.Intune_DeviceEnrollmentManagers_Delete"
)

Write-Log "Role defines $($ResourceActions.Count) allowed resource actions" 'INFO'
Write-Log "Listing existing role definitions..." 'INFO'
$ExistingRoles = Get-MgDeviceManagementRoleDefinition -All
$CustomRole = $ExistingRoles | Where-Object { $_.DisplayName -eq $CustomRoleName }

if ($CustomRole) {
    Write-Log "Custom role already exists, skipping creation: $($CustomRole.Id)" 'SKIP'
} else {
    Write-Log "Custom role not found; creating '$CustomRoleName'..." 'INFO'
    $RoleParams = @{
        DisplayName     = $CustomRoleName
        Description     = "Custom Intune RBAC role for Scientific Computing self-management. Scoped via Scope Tag 'Scientific-Computing'."
        RolePermissions = @(
            @{
                ResourceActions = @{
                    AllowedResourceActions = $ResourceActions
                }
            }
        )
        IsBuiltIn       = $false
    }
    $CustomRole = New-MgDeviceManagementRoleDefinition -BodyParameter $RoleParams
    Write-Log "Created custom role: $($CustomRole.Id)" 'DONE'
}
Complete-Step

# --------------------------------------------------------------------------
# 5. Assign the custom role to the admin group, scoped to the Scope Tag
# --------------------------------------------------------------------------
Start-Step "Create / verify role assignment"
Write-Log "Checking for an existing assignment of '$CustomRoleName' to '$AdminGroupName'..." 'INFO'

$ExistingAssignments = Get-MgDeviceManagementRoleAssignment -All
$ExistingAssignment = $ExistingAssignments | Where-Object {
    $_.DisplayName -eq "$CustomRoleName - $AdminGroupName" -or
    ($_.RoleDefinitionId -eq $CustomRole.Id -and $_.Members -contains $AdminGroup.Id)
}

if ($ExistingAssignment) {
    Write-Log "Role assignment already exists, skipping creation: $($ExistingAssignment.Id)" 'SKIP'
} else {
    Write-Log "Assignment not found; creating '$CustomRoleName - $AdminGroupName'..." 'INFO'
    $AssignmentParams = @{
        DisplayName       = "$CustomRoleName - $AdminGroupName"
        Description       = "Grants Scientific Computing admins the custom RBAC role, limited to objects tagged with Scope Tag 'Scientific-Computing'."
        RoleDefinitionId  = $CustomRole.Id
        Members           = @($AdminGroup.Id)
        ScopeTags         = @($ScopeTag.Id)          # scopes the assignment itself
        ScopeMembers      = @()                      # empty = all devices that carry the tag (or add specific group IDs)
    }
    $Assignment = New-MgDeviceManagementRoleAssignment -BodyParameter $AssignmentParams
    Write-Log "Created role assignment: $($Assignment.Id)" 'DONE'
}
Complete-Step


# --------------------------------------------------------------------------
# 6. Post-setup verification – list all Intune role assignments again
# --------------------------------------------------------------------------
Start-Step "Post-setup verification and summary"
Write-Log "Listing current Intune RBAC role assignments..." 'INFO'
$PostAssignments = @(Get-MgDeviceManagementRoleAssignment -All)
$PostAssignments |
    Select-Object DisplayName, Id |
    Format-Table -AutoSize
Write-Log "$($PostAssignments.Count) role assignments present" 'INFO'
Complete-Step


# --------------------------------------------------------------------------
# 7. Summary & next steps
# --------------------------------------------------------------------------
Write-Log "Setup complete in $([math]::Round($ScriptTimer.Elapsed.TotalSeconds, 1))s" 'DONE'
Write-Host "Admin Group ID     : $($AdminGroup.Id)"
Write-Host "Scope Tag ID       : $($ScopeTag.Id)"
Write-Host "Custom Role ID     : $($CustomRole.Id)"
Write-Host ""
Write-Host "Next actions to perform:" -ForegroundColor Yellow
Write-Host "1. Add the actual Scientific Computing staff to the group '$AdminGroupName'."
Write-Host "2. Tag every Scientific Computing device / profile / app / policy with the Scope Tag '$ScopeTagName'."
Write-Host "3. (Optional but recommended) Create dynamic Entra device groups filtered by the Scope Tag or by a device extension attribute."
Write-Host "4. Verify ControlPolicyConflict/MDMWinsOverGP CSP and that no 'All Devices' baselines conflict with SciComp."
Write-Host "5. Grant the same group read-only access to any tenant-wide profiles that affect SciComp devices (via additional scope-tag assignments if needed)."

Write-Log "Disconnecting from Microsoft Graph..." 'INFO'
Disconnect-MgGraph | Out-Null
Write-Log "Disconnected from Graph. Script finished." 'DONE'