# Tools
> tools 
## table of content
1. test

## Powershell

Copy ITEM
```powershell
Copy-Item .\MimikatzEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'

 Copy-Item -ToSession $appsrv1 -Path C:\AD\Tools\Rubeus.exe -Destination C:\Users\appadmin\Downloads
```

format table
```powershell
Get-NetUser| Format-Table
```

Select specipic data 
```powershell
Get-NetUser| select name
```

## PowerView.ps1
import
```powershell
. .\PowerView.ps1
```


## AD Module
import
```powershell
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

##  klist
list key
```powershell
 klist
```
destroy key
```powershell
 klist purge
```