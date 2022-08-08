# Domain Enumuration
> Enumurate Object in the domain
## Table of Content
1. [Tools](#Tools)
2. [User enumuration](#User)
## Tools
1. [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
2. [ActiveDirectory Module]()
## Current Domain
Get current  domain using .NET class
```.NET
$ADClass =[System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```
Get current  domain using powershell
```powershell
Get-NetDomain #PowerView
Get-ADDomain #ActiveDirectory Module
```
