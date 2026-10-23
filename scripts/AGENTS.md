# scripts

## Purpose

PowerShell automation for Intune and Entra ID endpoint management.

## Ownership

- `Intune-RBAC-Scientific-Computing-setup.ps1`: creates the admin group, scope tag, custom Intune role and assignment (write access)
- `Intune-Access-Query.ps1`: read-only report of a user's group membership, Entra/Intune roles and readable devices

## Local Contracts

- Tenant ID default: `22adcff7-c06f-49a6-8f20-50711c40ddaa`
- `Intune-Access-Query.ps1` stays read-only (Graph `*.Read.*` scopes only), standalone (installs PSGallery modules itself, so it does not use `#Requires -Modules`), and carries full PSScriptInfo plus comment-based help
- `Intune-Access-Query.ps1` requests the minimum read-only Graph scopes (no `Directory.Read.All`), accepts `-ClientId` for a dedicated app registration, and prints an admin-consent URL when sign-in is blocked on consent; app registration requirements live in the script `.NOTES`
- Device scope in the query script is derived from assignment scope groups; scope tags are not evaluated
- `Intune-RBAC-Scientific-Computing-setup.ps1` logs every action through `Write-Log` / `Start-Step` / `Complete-Step` (timestamp, level START/INFO/SKIP/DONE/WARN, step N/total, duration); keep `$StepTotal` equal to the number of `Start-Step` calls, keep `param()` above all other code and do not use `#Requires -Modules` (modules are installed by the script)
- `Intune-Access-Query.ps1` signs in with `-AuthMode Auto` (WAM single sign-on, then terminal device code with Edge as the browser); on a Graph assembly conflict it relaunches itself once in a clean `powershell.exe -NoProfile` (`-PassThru` is not supported in that case)

## Work Guidance

- Keep script help, `.NOTES` permissions and parameters in sync with behavior

## Verification

- Parse check: `[System.Management.Automation.Language.Parser]::ParseFile(...)` with zero errors
- `Test-ScriptFileInfo` on scripts that carry PSScriptInfo

## Child DOX Index

None.
