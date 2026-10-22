# Endpoint Management
_(thinking out loud project)_

## Start here
For full context, read: [Memorandum-SO-OIT-Intune](https://github.com/TESC-Scientific-Computing/memorandums/blob/main/Memorandum-SO-OIT-Intune.md) (Science Operations to OIT, April 17, 2026)

### [Github issues used for Project tracking](https://github.com/TESC-Scientific-Computing/endpoint-management/issues?q=is%3Aissue)

#### Next steps
- [ ] [Access to Intune Admin Center](https://github.com/TESC-Scientific-Computing/endpoint-management/issues/3)
- [ ] [Access to Microsoft Defender for Endpoint portal](https://github.com/TESC-Scientific-Computing/endpoint-management/issues/4)


## Installing the Microsoft Graph PowerShell SDK
Requires PSGallery to be trusted, and the Microsoft.Graph module to be installed for the current user.
```powershell
if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
}
```

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```


## Device State Registration (Hybrid Entra join)

### [dsregcmd (Device State Registration Command)](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd)
Microsoft Entra ID device registration (Entra joined, Hybrid Entra joined, or Entra registered / Workplace Join

`dsregcmd /status /debug` get status

`dsregcmd /join /debug` force join



#### Starting join scheduled process
`Start-ScheduledTask -TaskPath "\Microsoft\Windows\Workplace Join\" -TaskName "Automatic-Device-Join"`

##### Reading the scheduled task messages
`Get-WinEvent -LogName "Microsoft-Windows-User Device Registration/Admin" -MaxEvents 30 | Format-List TimeCreated, Id, Message`


## [MMA on Windows devices for Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/update-agent-mma-windows)

query agent `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" | Select-Object Version`



### Specific labels used in this repo
- **AD**  _Active Directory_
- **GP**  _Group Policy_
- **Intune**  _Microsoft Intune_
- **MDE**  _Microsoft Defender for Endpoint_



## Issues
- [Active Directory Group Policy Structure](/Issues/Issue-1-GP-AD.md)



## Notes
- Tenant ID is public metadata
  - [Get-Tenant-ID](https://login.microsoftonline.com/evergreen.edu/.well-known/openid-configuration)
