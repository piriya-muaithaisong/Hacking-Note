# Domain Enumuration
> Enumurate Object in the domain

## Table of Content
1. [Tools](#Tools)
2. [Domain](#Domain)
3. [User](#User)
4. [Computer](#Computer)
5. [Group](#Group)

## Tools
1. [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
2. [ActiveDirectory Module]()

## My user join domain?
```powershell
(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

$env:USERDNSDomain
```


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
Get-DomainSID #PowerView
(Get-ADDomain).DomainSID #ActiveDirectory Module
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

## Computer

Get a list of computers in the current domain
```powershell
# PowerView
Get-NetComputer
Get-NetComputer –OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData

# ActiveDirectory Module
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{TestConnection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *

```
I dont remember this thing
```powershell
Get-NetOU | %{Get-NetComputer -ADSPath $_}
```

## Group

Get all the groups in the current domain
```powershell
# PowerView
Get-NetGroup
Get-NetGroup -Domain <target domain>
Get-NetGroup -FullData

# ActiveDirectory Module
Get-ADGroup -Filter * | select Name 
Get-ADGroup -Filter * -Properties *

```

Get all groups containing the word "admin" in group name
```powershell
# PowerView
Get-NetGroup *admin*
Get-NetGroup -GroupName *admin* -Domain moneycorp.local

# ActiveDirectory Module
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

Get all the members of the Domain Admins group
```powershell
# PowerView
Get-NetGroupMember -GroupName "Domain Admins" -Recurse

# ActiveDirectory Module
Get-ADGroupMember -Identity "Domain Admins" -Recursive 
```

Get the group membership for a user
```powershell
# PowerView
Get-NetGroup –UserName "student1"

# ActiveDirectory Module
Get-ADPrincipalGroupMembership -Identity student1
```