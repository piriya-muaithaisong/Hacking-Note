# Azure Active Directory Recon
> TO DO
## Table of content

## Tools

ADDinternal
```powershell
Import-Module
C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose
```

## Azure Tenant

manaul
```
Get if Azure tenant is in use, tenant name and Federation

https://login.microsoftonline.com/getuserrealm.srf?login=[USERNAME@DOMAIN]&xml=1

Get the Tenant ID

https://login.microsoftonline.com/[DOMAIN]/.well-known/openid-configuration

Validate Email ID by sending requests to
https://login.microsoftonline.com/common/GetCredentialType
```

using ADDinternal
```powershell
#Get tenant name, authentication, brand name (usually same as directory name) and domain name
Get-AADIntLoginInformation -UserName root@defcorphq.onmicrosoft.com

#Get tenant ID
Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com 

#Get tenant domains
Get-AADIntTenantDomains -Domain defcorphq.onmicrosoft.com 
Get-AADIntTenantDomains -Domain deffin.onmicrosoft.com

#Get all the information
Invoke-AADIntReconAsOutsider -DomainName defcorphq.onmicrosoft.com
```

## Method
1. list all resource
2. list role assignment
3. Get permission to the resource -- can be done with API
4. list VM
5. list Webapp
6. list Function app
7. list Stroage account
8. list keyvault
9. list all enterprise application/service principal - using API or Az powershell
10. list the account that log on in server - use 
   1) az ad signed-in-user list-owned-objects
   2) az ad signed-in-user show
11. get role on socpe 
   1) Get-AzRoleAssignment -Scope /subscriptions/b413826f-108d4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Automation/automationAccounts/HybridAutomation
12. get administrative unit - using AzureAD module (see objective 16)
