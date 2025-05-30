# *wordlists*
```
password wordlists
---------
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/rockyou-40.txt

rules wordlists
---------
/usr/share/john/rules/best64.rule
/usr/share/hashcat/rules/rockyou-30000.rule
```
# *hashcat mode*
```shell
hashcat -h | grep -i <to_crack>
```
# *convert2john*
```shell
# Convert the hash to john format
locate *2john

<to_crack>2john > to_crack.hash
```
# *id_rsa*
```shell
# 1 Create "ssh.rule" file if needed. An example
# cap first letter, end with numbers 1 3 7, followed by special char ! @ or #
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#


# 2 Convert to correct format
ssh2john id_rsa > ssh.hash


# 3 Crack
# hashcat
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force

# john
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

# *NTLM*
```shell
# hashcat
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force


# john
john hashes.txt --format=nt --wordlist=/usr/share/wordlists/rockyou.txt --rules /usr/share/john/rules/best64.rule


#  https://medium.com/secstudent/using-john-the-ripper-with-lm-hashes-f757bd4fb094
```
# *NTLMv2*
```shell
# hashcat
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force


# john
john paul.hash --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt --rules /usr/share/john/rules/best64.rule


# https://exploit-notes.hdks.org/exploit/cryptography/algorithm/ntlm-ntlmv2/
```
# *Asreproast Hash*
```shell
# hashcat
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force


# john
john hashes.asreproast --wordlist=/usr/share/wordlists/rockyou.txt --rules /usr/share/john/rules/best64.rule
```
# *Kerberoast Hash*
```shell
# hashcat 
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force


# john
john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt --rules /usr/share/john/rules/best64.rule
```
# *GPP-stored*
```shell
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```
# *Keepass*
```shell
# 1. Convert database to hash and remove "Database" string:
keepass2john Database.kdbx > keepass.hash
sed -i 's/Database\://' keepass.hash


#
# CRACK
# hashcat
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

# john
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt --rules=/usr/share/john/rules/best64.rule
```