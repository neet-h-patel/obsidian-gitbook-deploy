# ***nmap***
```shell
sudo nmap -v -Pn -n -sCV -p21 --script " ftp-* and not brute" `tip` -oN nmap_ftp_MACHINE
```
# ***Anonymous Login***
***anonymous:password (and no password)***
```shell
ftp `tip` -A
```
# ***Credentialed***
```shell
ftp user@`tip` -A
```
# ***interact***
```shell
help
ls
cd
```

```shell
# modes
binary
ascii
```

```shell
# files
put FILE
get FILE
mget # get all files
```

```shell
# exit
bye
close
```
# ***Download all files***
```shell
wget -m ftp://USER:PASS@`tip`
```
# ***Bruteforce***
```shell
# Quick User/Pass Brute
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/rockyou-40.txt ftp://`tip`

# Check sheet for other
```
# ***NXC***
```shell
nxc ftp `tip` -u 'user' -p 'pass' --ls [DIRECTORY]
nxc ftp `tip` -u 'user' -p 'pass' --get file.txt
nxc ftp `tip` -u 'user' -p 'pass' --put local.txt remote.txt
```
