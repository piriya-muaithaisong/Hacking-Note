# Domain Enumuration
> Enumurate Object in the domain

## Table of Content
1. [Tools](#Tools)
2. [Domain](#Domain)
3. [User](#User)
4. [Computer](#Computer)
5. [Group](#Group)
6. [Actively Logged User](#Actively Logged User)
7. [share](#share)
8. [Domain Policy](#Domain Policy)
9. [Domain Controllers](#Domain Controllers)
10. [GPO](#GPO)
11. [OU](#OU)
12. [ACL/ACE](#ACL/ACE)
13. [Trust](#Trust)
14. [Forest](#Forest)
15. [User Hunting](#User Hunting)

## Tools
1. [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
2. [ActiveDirectory Module]()

## My user join domain?
check domain
```powershell
(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

$env:USERDNSDomain
```
check hostname
```powershell
 hostname
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
## Local Group
List all the local groups on a machine (needs administrator privs on nondc machines) -Powerview:
```powershell
Get-NetLocalGroup -ComputerName dcorpdc.dollarcorp.moneycorp.local -ListGroups
```

Get members of all the local groups on a machine (needs administrator privs on non-dc machines) -Powerview 
```powershell
Get-NetLocalGroup -ComputerName dcorpdc.dollarcorp.moneycorp.local -Recurse
```

## Actively Logged User
Get actively logged users on a computer (needs local admin rights on the target)
```powershell
Get-NetLoggedon -ComputerName dcorp-std134.dollarcorp.moneycorp.local
```

Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
```powershell
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

Get the last logged user on a computer (needs administrative rights and remote registry on the target)
```powershell
Get-LastLoggedOn –ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

## Share
Find shares on hosts in current domain.
```powershell
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -Verbose -ExcludeStandard -ExcludePrint -ExcludeIPC
```

Find sensitive files on computers in the domain
```powershell
Invoke-FileFinder –Verbose
```

Get all file servers of the domain
```powershell
Get-NetFileServer
```

## Domain Policy
Get domain policy for the current domain
```powershell
Get-DomainPolicy
(Get-DomainPolicy)."system access"
Get-DomainPolicy
(Get-DomainPolicy)."Kerberos Policy"
```

Get domain policy for another domain
```powershell
(Get-DomainPolicy -domain moneycorp.local)."system access"
```

## Domain Controllers

Get domain controllers for the current domain
```powershell
Get-NetDomainController
Get-ADDomainController # ActiveDirectory Module
```

Get domain controllers for another domain
```powershell
Get-NetDomainController -Domain moneycorp.local
Get-ADDomainController -DomainName moneycorp.local -Discover # ActiveDirectory Module
```

## GPO
check GPO on current machine
```powershell
gpresult /R /V 
```

Get list of GPO in current domain.
```powershell
Get-NetGPO
Get-NetGPO -ComputerName dcorpstudent1.dollarcorp.moneycorp.local 
Get-NetGPO -ADSpath 'LDAP://cn={3E04167E-C2B6-4A9A-8FB7-C811158DC97C},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local'

Get-GPO -All (#GroupPolicy module)
Get-GPResultantSetOfPolicy -ReportType Html -PathC:\Users\Administrator\report.html #(Provides RSoP)
```
Get GPO(s) which use Restricted Groups or groups.xml for interesting users
```powershell
Get-NetGPOGroup
```
Get users which are in a local group of a machine using GPO
```powershell
Find-GPOComputerAdmin –Computername dcorpstudent1.dollarcorp.moneycorp.local
```
Get machines where the given user is member of a specific group
```powershell
Find-GPOLocation -UserName student1 -Verbose 
```

## OU
Get OUs in a domain
```powershell
Get-NetOU -FullData
Get-ADOrganizationalUnit -Filter * -Properties * 
```

Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU
```powershell
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B83E8F4EF8081}"
Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081 (GroupPolicy module)
```
Get the computer's name that in the OU
```powershell
Get-NetOU StudentMachines| %{Get-NetComputer -ADSPath $_}
```

## ACL/ACE
How to Read the out put
```
"IdentityReference" 

has

"ActiveDirectoryRights"

to

"ObjectDN"
```
tips for ACL enumuration
> Query ACL in both user and group

Get the ACLs associated with the specified object
```powershell
Get-ObjectAcl -SamAccountName student1 -ResolveGUIDs
Get-ObjectAcl -ResolveGUIDs | ?{$_.IdentityReference -match 'dcorp\\RDPusers'}
Get-ObjectAcl -ResolveGUIDs | ?{$_.IdentityReference -match 'dcorp\\RDPusers' -AND $_.ObjectDN -match 'contro'}
```
Get the ACLs associated with the specified prefix to be used for search
```powershell
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```
Enumerate ACLs using ActiveDirectory module but without resolving GUIDs
```powershell
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
```
Get the ACLs associated with the specified LDAP path to be used for search
```powershell
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

Search for interesting ACEs
```powershell
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "student"}
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RDPUsers"}
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RDPUsers" -and $_.ObjectDN -match "134"}
```

Get the ACLs associated with the specified path
```powershell
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```


## Trust
Get a list of all domain trusts for the current domain
```powershell
Get-NetDomainTrust
Get-NetDomainTrust –Domain us.dollarcorp.moneycorp.local

Get-ADTrust
Get-ADTrust –Identity us.dollarcorp.moneycorp.local
```

# Forest
Get details about the current forest
```powershell
Get-NetForest
Get-NetForest -Forest eurocorp.local

Get-ADForest
Get-ADForest -Identity eurocorp.local
```
Get all domains in the current forest
```powershell
Get-NetForestDomain
Get-NetForestDomain -Forest eurocorp.local

(Get-ADForest).Domains
```

Get all global catalogs for the current forest
```powershell
Get-NetForestCatalog
Get-NetForestCatalog -Forest eurocorp.local

Get-ADForest | select -ExpandProperty GlobalCatalogs
```
Map trusts of a forest
```powershell
Get-NetForestTrust
Get-NetForestTrust -Forest eurocorp.local

Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

## User Hunting
Find all machines on the current domain where the current user has local admin access
>this command use **Get-NetComputer** then **CheckLocalAdminAccess** on each machine
```powershell
Find-LocalAdminAccess -Verbose
```
Find local admins on all machines of the domain (needs administrator privs on non-dc machines).
>this command use **Get-NetComputer** then **GetNetLocalGroup** on each machine
```powershell
Invoke-EnumerateLocalAdmin –Verbose
```
Find computers where a domain admin (or specified user/group) has sessions:
>this command use **Get-NetComputer** then **GetNetSession/Get-NetLoggedon** on each machine
```powershell
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -Stealth
```
To confirm admin access
```powershell
Invoke-UserHunter -CheckAccess
```
