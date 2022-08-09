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

## User

 list of users in the current domain
```powershell
# PowerView
Get-NetUser
Get-NetUser –Username student1

# ActiveDirectory Module
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
```
list of all properties for users in the current domain
```powershell
# PowerView
Get-UserProperty
Get-UserProperty –Properties pwdlastset

# ActiveDirectory Module
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name

Get-ADUser -Filter * -Properties * | selectname,@{expression ={[datetime]::fromFileTime($_.pwdlastset)}}
```

Search for a particular string in a user's attributes
```powershell
# PowerView
Find-UserField -SearchField Description -SearchTerm "built"

# ActiveDirectory Module
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```