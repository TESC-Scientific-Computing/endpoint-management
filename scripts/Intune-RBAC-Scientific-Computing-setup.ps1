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
    Microsoft.Graph.DeviceManagement.Administration modules (or Microsoft.Graph meta-module)
  - Global Administrator or Privileged Role Administrator + Intune Administrator rights to run once
  - Tenant: 22adcff7-c06f-49a6-8f20-50711c40ddaa
#>



if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
}

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.DeviceManagement, Microsoft.Graph.DeviceManagement.Administration

[CmdletBinding()]
param(
    [string]$AdminGroupName        = "SG-Scientific-Computing-Admins",
    [string]$CustomRoleName        = "Scientific-Computing-Administrator",
    [string]$ScopeTagName          = "Scientific-Computing",
    [string]$ScopeTagDescription   = "Scope tag for Scientific Computing devices and objects - enables delegated self-management",
    [string]$TenantId              = "22adcff7-c06f-49a6-8f20-50711c40ddaa"
)

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

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId -NoWelcome
# Optionally: Select-MgProfile -Name "beta" if you need beta endpoints

# --------------------------------------------------------------------------
# 1a. Pre-flight check – current user's directory roles & groups
# --------------------------------------------------------------------------
Write-Host "`n=== Pre-flight: Your current directory roles and groups ===" -ForegroundColor Cyan
try {
    Get-MgUserMemberOf -UserId (Get-MgContext).Account -All |
        ForEach-Object {
            [pscustomobject]@{
                Type = $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
                Name = $_.AdditionalProperties.displayName
            }
        } |
        Sort-Object Type, Name |
        Format-Table -AutoSize
}
catch {
    Write-Warning "Could not retrieve membership information: $($_.Exception.Message)"
}

# --------------------------------------------------------------------------
# 1b. Pre-flight check – existing Intune role assignments
# --------------------------------------------------------------------------
Write-Host "`n=== Pre-flight: Existing Intune RBAC role assignments ===" -ForegroundColor Cyan
try {
    # Ensure we have the read scope (already included above, but re-connect is harmless)
    Connect-MgGraph -Scopes "DeviceManagementRBAC.Read.All" -TenantId $TenantId -NoWelcome | Out-Null
    Get-MgDeviceManagementRoleAssignment -All |
        Select-Object DisplayName, Id |
        Format-Table -AutoSize
}
catch {
    Write-Warning "Could not list existing role assignments: $($_.Exception.Message)"
}

Write-Host "`nProceeding with setup...`n" -ForegroundColor Green

# --------------------------------------------------------------------------
# 2. Create (or retrieve) the Entra ID security group for SciComp admins
# --------------------------------------------------------------------------
Write-Host "Ensuring Entra ID group '$AdminGroupName' exists..." -ForegroundColor Cyan

$ExistingGroup = Get-MgGroup -Filter "displayName eq '$AdminGroupName'" -ErrorAction SilentlyContinue
if ($ExistingGroup) {
    $AdminGroup = $ExistingGroup
    Write-Host "  Group already exists: $($AdminGroup.Id)" -ForegroundColor Yellow
} else {
    $AdminGroup = New-MgGroup -DisplayName $AdminGroupName `
                              -MailEnabled:$false `
                              -MailNickname ($AdminGroupName -replace '[^a-zA-Z0-9]','') `
                              -SecurityEnabled `
                              -Description "Security group for Scientific Computing administrators. Members receive the custom Intune RBAC role scoped to Scientific-Computing."
    Write-Host "  Created group: $($AdminGroup.Id)" -ForegroundColor Green
}

# --------------------------------------------------------------------------
# 3. Create the Scope Tag "Scientific-Computing"
# --------------------------------------------------------------------------
Write-Host "Ensuring Scope Tag '$ScopeTagName' exists..." -ForegroundColor Cyan

$ExistingTags = Get-MgDeviceManagementRoleScopeTag -All
$ScopeTag = $ExistingTags | Where-Object { $_.DisplayName -eq $ScopeTagName }

if ($ScopeTag) {
    Write-Host "  Scope Tag already exists: $($ScopeTag.Id)" -ForegroundColor Yellow
} else {
    $ScopeTag = New-MgDeviceManagementRoleScopeTag -DisplayName $ScopeTagName `
                                                   -Description $ScopeTagDescription
    Write-Host "  Created Scope Tag: $($ScopeTag.Id)" -ForegroundColor Green
}

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
Write-Host "Ensuring custom Intune RBAC role '$CustomRoleName' exists..." -ForegroundColor Cyan

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

$ExistingRoles = Get-MgDeviceManagementRoleDefinition -All
$CustomRole = $ExistingRoles | Where-Object { $_.DisplayName -eq $CustomRoleName }

if ($CustomRole) {
    Write-Host "  Custom role already exists: $($CustomRole.Id)" -ForegroundColor Yellow
} else {
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
    Write-Host "  Created custom role: $($CustomRole.Id)" -ForegroundColor Green
}

# --------------------------------------------------------------------------
# 5. Assign the custom role to the admin group, scoped to the Scope Tag
# --------------------------------------------------------------------------
Write-Host "Creating / verifying role assignment..." -ForegroundColor Cyan

$ExistingAssignments = Get-MgDeviceManagementRoleAssignment -All
$ExistingAssignment = $ExistingAssignments | Where-Object {
    $_.DisplayName -eq "$CustomRoleName - $AdminGroupName" -or
    ($_.RoleDefinitionId -eq $CustomRole.Id -and $_.Members -contains $AdminGroup.Id)
}

if ($ExistingAssignment) {
    Write-Host "  Role assignment already exists: $($ExistingAssignment.Id)" -ForegroundColor Yellow
} else {
    $AssignmentParams = @{
        DisplayName       = "$CustomRoleName - $AdminGroupName"
        Description       = "Grants Scientific Computing admins the custom RBAC role, limited to objects tagged with Scope Tag 'Scientific-Computing'."
        RoleDefinitionId  = $CustomRole.Id
        Members           = @($AdminGroup.Id)
        ScopeTags         = @($ScopeTag.Id)          # scopes the assignment itself
        ScopeMembers      = @()                      # empty = all devices that carry the tag (or add specific group IDs)
    }
    $Assignment = New-MgDeviceManagementRoleAssignment -BodyParameter $AssignmentParams
    Write-Host "  Created role assignment: $($Assignment.Id)" -ForegroundColor Green
}


# --------------------------------------------------------------------------
# 6. Post-setup verification – list all Intune role assignments again
# --------------------------------------------------------------------------
Write-Host "`n=== Post-setup: Current Intune RBAC role assignments ===" -ForegroundColor Cyan
Get-MgDeviceManagementRoleAssignment -All |
    Select-Object DisplayName, Id |
    Format-Table -AutoSize


# --------------------------------------------------------------------------
# 7. Summary & next steps
# --------------------------------------------------------------------------
Write-Host "`n=== Setup complete ===" -ForegroundColor Green
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

Disconnect-MgGraph | Out-Null
Write-Host "`nDisconnected from Graph." -ForegroundColor Cyan