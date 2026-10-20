# Endpoint Management

## dsregcmd (Device State Registration Command)
Microsoft Entra ID device registration (Entra joined, Hybrid Entra joined, or Entra registered / Workplace Join

`dsregcmd /status /debug` get status
`dsregcmd /join /debug` force join


## MMA [MMA on Windows devices for Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/update-agent-mma-windows)

query agent `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup" | Select-Object Version`



## Issues
### [Active Directory Group Policy Structure](/Issues/Issue-1-GP-AD.md)




## Notes
- Tenant ID is public metadata
  - [Get-Tenant-ID](https://login.microsoftonline.com/evergreen.edu/.well-known/openid-configuration)
