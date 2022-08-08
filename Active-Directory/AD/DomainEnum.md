# Domain Enumuration
> Enumurate Object in the domain

## Table of Content
1. [Tools](#Tools)
2. [Domain](#Domain)
3. [User](#User)

## Tools
1. [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
2. [ActiveDirectory Module]()

## Domain
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
Get object of another domain
```powershell
Get-NetDomain -Domain moneycorp.local #PowerView
Get-ADDomain -Identity moneycorp.local #ActiveDirectory Module
```
Get domain SID
```powershell
Get-DomainSID(Get-ADDomain).DomainSID #ActiveDirectory Module
```